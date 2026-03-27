import * as crypto from '@atproto/crypto';
import { generateKeyPairSync } from 'crypto';

async function main() {
  const es256kKeypair = await crypto.Secp256k1Keypair.create({ exportable: true });
  const es256kPrivateKeyHex = Buffer.from(await es256kKeypair.export()).toString('hex');

  const { privateKey: rs256PrivateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const rs256PrivateKeyPem = rs256PrivateKey
    .export({ format: 'pem', type: 'pkcs8' })
    .toString()
    .replace(/\n/g, '\\n');

  console.log('--- OAuth Signing Keys ---');
  console.log(`OAUTH_ES256K_PRIVATE_KEY=${es256kPrivateKeyHex}`);
  console.log(`OAUTH_RS256_PRIVATE_KEY=${rs256PrivateKeyPem}`);
  console.log('--------------------------');
}

main();
