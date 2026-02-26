import * as crypto from '@atproto/crypto';
import * as cbor from '@ipld/dag-cbor';
import axios from 'axios';
import { createHash } from 'crypto';
import { base32 } from 'multiformats/bases/base32';

async function main() {
  const handle = process.argv[2];
  if (!handle) {
    console.error('❌ Error: Please provide your PDS handle (domain) as an argument.');
    console.log('Usage: npm run gen-key pds.your-domain.com');
    process.exit(1);
  }

  console.log(`🚀 Generating did:plc for ${handle}...`);

  // 1. Generate Signing Key (PRIVATE_KEY)
  const signingKeypair = await crypto.Secp256k1Keypair.create({ exportable: true });
  const privKeyHex = Buffer.from(await signingKeypair.export()).toString('hex');

  // 2. Generate Rotation Key
  const rotationKeypair = await crypto.Secp256k1Keypair.create({ exportable: true });
  const rotationKeyHex = Buffer.from(await rotationKeypair.export()).toString('hex');

  // 3. Construct PLC Operation
  const op = {
    type: 'plc_operation',
    rotationKeys: [rotationKeypair.did()],
    verificationMethods: {
      atproto: signingKeypair.did(),
    },
    alsoKnownAs: [`at://${handle}`],
    services: {
      atproto_pds: {
        type: 'AtprotoPersonalDataServer',
        endpoint: `https://${handle}`,
      },
    },
    prev: null,
  };

  // 4. Sign Operation
  const signature = await rotationKeypair.sign(cbor.encode(op));
  const signedOp = {
    ...op,
    sig: Buffer.from(signature).toString('base64url'),
  };

  // 5. Derive DID
  const encoded = cbor.encode(signedOp);
  const hash = createHash('sha256').update(encoded).digest();
  const plcDid = `did:plc:${base32.encode(hash).slice(1, 25)}`; // base32.encode returns string starting with 'b' multibase prefix

  console.log('\n--- New PDS Configuration ---');
  console.log(`HANDLE=${handle}`);
  console.log(`PDS_DID=${plcDid}`);
  console.log(`PRIVATE_KEY=${privKeyHex}`);
  console.log(`PLC_ROTATION_KEY=${rotationKeyHex} (Save this somewhere safe!)`);
  console.log('------------------------------\n');

  console.log(`🌐 Registering ${plcDid} on https://plc.directory...`);
  try {
    await axios.post(`https://plc.directory/${plcDid}`, signedOp);
    console.log('✅ DID registered successfully.');
  } catch (err) {
    console.error('❌ PLC Registration failed:', err.response?.data || err.message);
    console.log('\nYou can try registering manually later using the signed operation above.');
  }
}

main();
