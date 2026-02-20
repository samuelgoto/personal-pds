import 'dotenv/config';
import readline from 'readline';
import { runFullSetup } from './src/setup.js';

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    const results = await runFullSetup({
      interactive: true,
      skipPlc: process.argv.includes('--skip-plc'),
      rl
    });

    console.log(`\nSetup complete!`);
    console.log(`DID: ${results.did}`);
    console.log(`Root CID: ${results.rootCid}`);
    
    if (results.updatedEnv) {
      console.log('Updated .env file with new configuration.');
    }
  } catch (err) {
    console.error('\nSetup failed:');
    console.error(err);
    process.exit(1);
  } finally {
    rl.close();
  }
}

main();
