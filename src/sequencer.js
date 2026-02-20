import { db } from './db.js';
import { cborEncode, cborDecode } from '@atproto/common';
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
    console.log(`[SEQUENCER] Backfilling from cursor: ${cursor}`);
    try {
        const res = await db.execute({
          sql: 'SELECT * FROM sequencer WHERE seq > ? ORDER BY seq ASC LIMIT 100',
          args: [cursor]
        });
        for (const row of res.rows) {
          ws.send(this.formatEvent(row));
        }
    } catch (err) {
        console.error('[SEQUENCER] Backfill failed:', err);
    }
  }

  async sequenceEvent(evt) {
    const time = new Date().toISOString();
    
    // 1. Insert placeholder to get the next sequence number
    const res = await db.execute({
      sql: 'INSERT INTO sequencer (did, type, event, time) VALUES (?, ?, ?, ?) RETURNING seq',
      args: [evt.did, evt.type, Buffer.from([0]), time] // Placeholder
    });
    
    const seq = res.rows[0].seq;
    
    // 2. Encode the FULL event including the seq
    const eventWithSeq = { ...evt.event, seq };
    const encoded = Buffer.from(cborEncode(eventWithSeq));

    // 3. Update the database with the real encoded event
    await db.execute({
        sql: 'UPDATE sequencer SET event = ? WHERE seq = ?',
        args: [encoded, seq]
    });

    const fullEvent = this.formatEvent({
        type: evt.type,
        event: encoded
    });

    console.log(`[SEQUENCER] Broadcasting seq ${seq} to ${this.clients.size} clients`);
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
    const encodedHeader = cborEncode(header);
    console.log(`[SEQUENCER] Formatting event: type=${row.type}, header_len=${encodedHeader.length}, body_len=${row.event.length}`);
    return Buffer.concat([
        Buffer.from(encodedHeader),
        Buffer.from(row.event)
    ]);
  }
}

export const sequencer = new Sequencer();
