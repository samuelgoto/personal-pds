import * as crypto from '@atproto/crypto';

async function main() {
  const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
  const privKeyHex = Buffer.from(await keypair.export()).toString('hex');
  const did = keypair.did();

  console.log('--- New PDS Configuration ---');
  console.log(`PRIVATE_KEY=${privKeyHex}`);
  console.log(`PDS_DID=${did} (Placeholder, you might want a did:plc instead)`);
  console.log('------------------------------');
}

main();
