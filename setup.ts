import 'dotenv/config';
import { db, initDb } from './src/db';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from './src/repo';
import { sequencer } from './src/sequencer';
import { blocksToCarFile } from '@atproto/repo';
import { formatDid } from './src/util';

async function setup() {
  await initDb(db);
  
  const domain = process.env.DOMAIN || 'localhost:3000';
  const did = formatDid(domain);
  
  const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
  const privKey = await keypair.export();
  const privKeyHex = Buffer.from(privKey).toString('hex');
  
  console.log(`\n--- PDS INITIALIZATION ---\n`);
  console.log(`DID: ${did}`);
  console.log(`PRIVATE_KEY=${privKeyHex}`);
  console.log(`\nAdd the PRIVATE_KEY to your .env or Vercel environment variables.\n`);

  console.log(`Initializing repository...`);
  const storage = new TursoStorage();
  const repo = await loadRepo(storage, did, keypair, null);
  
  const carBlocks = await storage.getRepoBlocks();
  const blocks = await blocksToCarFile(repo.cid, carBlocks);

  await sequencer.sequenceEvent({
    type: 'commit',
    did: did,
    event: {
      repo: did,
      commit: repo.cid,
      blocks: blocks,
      rev: repo.commit.rev,
      since: null,
      ops: [],
      time: new Date().toISOString(),
    }
  });
  
  console.log('Setup complete! Repository root:', repo.cid.toString());
}

setup().catch(console.error);
