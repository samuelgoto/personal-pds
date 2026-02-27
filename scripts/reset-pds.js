import 'dotenv/config';
import { db, destroy } from '../src/db.js';

async function main() {
  console.log('⚠️ Wiping PDS state (database only)...');
  try {
    await destroy();
    console.log('✅ All tables cleared.');
    process.exit(0);
  } catch (err) {
    console.error('❌ Wipe failed:', err.message);
    process.exit(1);
  }
}

main();
