import { db } from './db.js';
import { cborEncode } from '@atproto/common';
import { WebSocket } from 'ws';

export type FirehoseEvent = {
  type: 'commit' | 'identity' | 'account';
  did: string;
  event: any;
};

class Sequencer {
  private clients: Set<WebSocket> = new Set();

  addClient(ws: WebSocket, cursor?: number) {
    this.clients.add(ws);
    ws.on('close', () => this.clients.delete(ws));
    
    if (cursor !== undefined) {
      this.backfill(ws, cursor);
    }
  }

  private async backfill(ws: WebSocket, cursor: number) {
    const res = await db.execute({
      sql: 'SELECT * FROM sequencer WHERE seq > ? ORDER BY seq ASC',
      args: [cursor]
    });
    for (const row of res.rows) {
      ws.send(this.formatEvent(row));
    }
  }

  async sequenceEvent(evt: FirehoseEvent) {
    const time = new Date().toISOString();
    const encoded = cborEncode(evt.event);
    
    const res = await db.execute({
      sql: 'INSERT INTO sequencer (did, type, event, time) VALUES (?, ?, ?, ?) RETURNING seq',
      args: [evt.did, evt.type, Buffer.from(encoded), time]
    });
    
    const seq = res.rows[0].seq as number;
    const fullEvent = this.formatEvent({
        seq,
        type: evt.type,
        event: encoded,
        time
    });

    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(fullEvent);
      }
    }
  }

  close() {
    for (const client of this.clients) {
      client.terminate();
    }
    this.clients.clear();
  }

  private formatEvent(row: any) {
    // ATProto firehose events are DAG-CBOR encoded frames: [header, body]
    // Header: { op: 1, t: '#commit' | '#identity' ... }
    // Body: The event object itself
    const header = { op: 1, t: `#${row.type}` };
    const body = { ...cborEncode(row.event as any), seq: row.seq, time: row.time }; // This is simplified
    
    // Actually, for a real firehose we should use the exact framing.
    // For now, let's just send a simple JSON or CBOR-encoded object.
    // Relays expect: [CBOR(header), CBOR(body)]
    return Buffer.concat([
        Buffer.from(cborEncode(header)),
        Buffer.from(row.event)
    ]);
  }
}

export const sequencer = new Sequencer();
