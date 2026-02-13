import 'dotenv/config';
import { db, initDb } from './src/db';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from './src/repo';

async function setup() {
  await initDb();
  
  const handle = process.env.HANDLE || 'user.test';
  const password = process.env.PASSWORD || 'password';
  const domain = process.env.DOMAIN || 'localhost:3000';
  const did = `did:web:${domain}`;
  
  const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
  const signingKey = keypair.did().split(':').pop()!; // Simplified key storage
  
  // Actually we need the private key to sign future commits
  const privKey = keypair.export();
  
  console.log(`Setting up PDS for ${handle} (${did})`);
  
  const storage = new TursoStorage();
  const repo = await loadRepo(storage, did, keypair, null);
  const rootCid = repo.cid.toString();
  
  await db.execute({
    sql: 'INSERT OR REPLACE INTO account (handle, password, did, signing_key, root_cid) VALUES (?, ?, ?, ?, ?)',
    args: [handle, password, did, privKey, rootCid]
  });
  
  console.log('Setup complete!');
  console.log(`DID: ${did}`);
  console.log(`Handle: ${handle}`);
  console.log(`Password: ${password}`);
}

setup().catch(console.error);
