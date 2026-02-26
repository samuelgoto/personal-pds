import { db } from './db.js';
import { WebSocket } from 'ws';
import * as cbor from '@ipld/dag-cbor';

class Sequencer {
  clients = new Set();

  getSubscriberCount() {
    return this.clients.size;
  }

  async addClient(ws, cursor) {
    this.clients.add(ws);
    ws.on('close', () => this.clients.delete(ws));
    
    if (cursor !== undefined) {
      await this.backfill(ws, cursor);
    } else {
      // If no cursor, send the latest event so they have a starting point
      try {
        const res = await db.execute({
          sql: 'SELECT * FROM sequencer ORDER BY seq DESC LIMIT 1'
        });
        if (res.rows.length > 0) {
          ws.send(this.formatEvent(res.rows[0]));
        }
      } catch (err) {
        console.error('[SEQUENCER] Failed to send latest event to new client:', err);
      }
    }
  }

  async backfill(ws, cursor) {
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
    
    // 2. Encode the FULL event including the seq and type using DAG-CBOR (canonical)
    const eventWithSeq = { ...evt.event, seq, type: evt.type };
    
    // Debug: ensure CIDs are objects
    if (eventWithSeq.commit && typeof eventWithSeq.commit === 'string') {
        console.error(`[SEQUENCER] WARNING: commit is a string, not CID object! ${eventWithSeq.commit}`);
    }

    const encoded = Buffer.from(cbor.encode(eventWithSeq));

    // 3. Update the database with the real encoded event
    await db.execute({
        sql: 'UPDATE sequencer SET event = ? WHERE seq = ?',
        args: [encoded, seq]
    });

    const fullEvent = this.formatEvent({
        type: evt.type,
        event: encoded
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
    const encodedHeader = cbor.encode(header);
    return Buffer.concat([
        Buffer.from(encodedHeader),
        Buffer.from(row.event)
    ]);
  }
}

export const sequencer = new Sequencer();
