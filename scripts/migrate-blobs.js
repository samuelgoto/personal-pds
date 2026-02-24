import 'dotenv/config';
import { db } from '../src/db.js';

async function migrate() {
  console.log('Migrating blobs table columns...');
  try {
    const res = await db.execute('PRAGMA table_info(blobs)');
    const columns = res.rows.map(r => r.name);
    
    if (columns.includes('data') && !columns.includes('content')) {
        console.log('Renaming data column to content...');
        // SQLite (Turso) supports renaming columns
        await db.execute('ALTER TABLE blobs RENAME COLUMN data TO content');
        console.log('✅ data renamed to content.');
    } else if (!columns.includes('content')) {
        console.log('Adding content column...');
        await db.execute('ALTER TABLE blobs ADD COLUMN content BLOB NOT NULL DEFAULT ""');
        console.log('✅ content column added.');
    } else {
        console.log('✅ content column already exists.');
    }

    process.exit(0);
  } catch (err) {
    console.error('❌ Migration failed:', err);
    process.exit(1);
  }
}

migrate();
