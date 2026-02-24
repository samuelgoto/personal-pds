import 'dotenv/config';
import { db } from '../src/db.js';

async function inspect() {
  try {
    const res = await db.execute('PRAGMA table_info(blobs)');
    console.log('Columns in blobs table:');
    console.table(res.rows);
    process.exit(0);
  } catch (err) {
    console.error('Inspection failed:', err);
    process.exit(1);
  }
}

inspect();
