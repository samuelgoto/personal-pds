import 'dotenv/config';
import { db } from '../src/db.js';
import * as cborg from 'cborg';

async function check() {
  try {
    const res = await db.execute({
      sql: "SELECT * FROM sequencer WHERE type = 'commit' ORDER BY seq DESC LIMIT 5"
    });
    
    console.log(`Checking last 5 commits...`);
    for (const row of res.rows) {
      const event = cborg.decode(new Uint8Array(row.event));
      console.log(`
Seq: ${row.seq} | Time: ${row.time}`);
      console.log(`Commit: ${event.commit}`);
      console.log(`Ops:`, JSON.stringify(event.ops, null, 2));
    }
    process.exit(0);
  } catch (err) {
    console.error('Check failed:', err);
    process.exit(1);
  }
}

check();
