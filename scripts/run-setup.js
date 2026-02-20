import 'dotenv/config';
import { runFullSetup } from '../src/setup.js';

console.log('🚀 Starting PDS Setup locally...');
console.log(`Authoritative Domain: ${process.env.DOMAIN}`);
console.log(`PDS DID: ${process.env.PDS_DID}`);

async function main() {
  try {
    await runFullSetup({
      interactive: false,
      skipPlc: true // We assume PLC is already handled manually
    });
    console.log('
✅ Setup process completed.');
    process.exit(0);
  } catch (err) {
    console.error('
❌ Setup failed:', err);
    process.exit(1);
  }
}

main();
