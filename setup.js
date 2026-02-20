import 'dotenv/config';
import { db, initDb } from './src/db.js';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from './src/repo.js';
import { sequencer } from './src/sequencer.js';
import { blocksToCarFile, WriteOpAction } from '@atproto/repo';
import { formatDid } from './src/util.js';

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
  
  // Initial empty repo
  let repo = await loadRepo(storage, did, keypair, null);
  
  // Create default profile
  console.log(`Creating default profile...`);
  repo = await repo.applyWrites([
    {
      action: WriteOpAction.Create,
      collection: 'app.bsky.actor.profile',
      rkey: 'self',
      record: {
        $type: 'app.bsky.actor.profile',
        displayName: domain,
        description: 'Personal PDS',
        createdAt: new Date().toISOString(),
      },
    }
  ], keypair);
  
  const recordCid = await repo.data.get('app.bsky.actor.profile/self');
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
      ops: [{ action: 'create', path: 'app.bsky.actor.profile/self', cid: recordCid || repo.cid }],
      time: new Date().toISOString(),
    }
  });
  
  console.log('Setup complete! Repository root:', repo.cid.toString());
}

setup().catch(console.error);
