import { db } from './db.js';
import { cborEncode } from '@atproto/common';
import { WebSocket } from 'ws';

class Sequencer {
  clients = new Set();

  addClient(ws, cursor) {
    this.clients.add(ws);
    ws.on('close', () => this.clients.delete(ws));
    
    if (cursor !== undefined) {
      this.backfill(ws, cursor);
    }
  }

  async backfill(ws, cursor) {
    const res = await db.execute({
      sql: 'SELECT * FROM sequencer WHERE seq > ? ORDER BY seq ASC',
      args: [cursor]
    });
    for (const row of res.rows) {
      ws.send(this.formatEvent(row));
    }
  }

  async sequenceEvent(evt) {
    const time = new Date().toISOString();
    
    const res = await db.execute({
      sql: 'INSERT INTO sequencer (did, type, event, time) VALUES (?, ?, ?, ?) RETURNING seq',
      args: [evt.did, evt.type, Buffer.from(cborEncode(evt.event)), time]
    });
    
    const seq = res.rows[0].seq;
    
    // Add seq to the event body for the firehose broadcast
    const eventWithSeq = { ...evt.event, seq };
    const encodedWithSeq = cborEncode(eventWithSeq);

    const fullEvent = this.formatEvent({
        seq,
        type: evt.type,
        event: encodedWithSeq,
        time
    });

    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(fullEvent);
      }
    }
    return seq;
  }

  close() {
    for (const client of this.clients) {
      client.terminate();
    }
    this.clients.clear();
  }

  formatEvent(row) {
    const header = { op: 1, t: `#${row.type}` };
    return Buffer.concat([
        Buffer.from(cborEncode(header)),
        Buffer.from(row.event)
    ]);
  }
}

export const sequencer = new Sequencer();
