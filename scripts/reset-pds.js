import 'dotenv/config';
import { db } from '../src/db.js';

async function reset() {
  console.log('Wiping ALL PDS data for a fresh start...');
  
  try {
    await db.execute('DELETE FROM repo_blocks');
    await db.execute('DELETE FROM sequencer');
    await db.execute('DELETE FROM blobs');
    await db.execute('DELETE FROM sessions');
    await db.execute("DELETE FROM system_state WHERE key = 'repo_created_at'");
    console.log('✅ All tables wiped successfully.');
    process.exit(0);
  } catch (err) {
    console.error('❌ Failed to wipe tables:', err);
    process.exit(1);
  }
}

reset();
