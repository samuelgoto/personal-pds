import 'dotenv/config';
import { db, create } from '../src/db.js';
import { TursoStorage, getRootCid, setUpRepo } from '../src/repo.js';
import { Repo, WriteOpAction, blocksToCarFile } from '@atproto/repo';
import * as crypto from '@atproto/crypto';
import { CID } from 'multiformats';
import { sequencer } from '../src/sequencer.js';
import { fixCids } from '../src/util.js';
import axios from 'axios';

const RELAY_URL = process.env.RELAY_URL || 'https://bsky.network';

async function pingRelay(hostname) {
  try {
    console.log(`Pinging relay ${RELAY_URL} to crawl ${hostname}...`);
    await axios.post(`${RELAY_URL}/xrpc/com.atproto.sync.requestCrawl`, { hostname });
    console.log('Relay notified successfully.');
  } catch (err) {
    console.warn(`⚠️ Relay notification failed: ${err.response?.data?.message || err.message}`);
    console.warn('This is expected if your domain is not public (e.g., .test or localhost)');
  }
}

async function main() {
  const displayName = process.argv[2] || 'User';
  const description = process.argv[3] || 'My Personal PDS';
  const birthDate = process.argv[4] || '1990-01-01';

  const did = process.env.PDS_DID;
  const privKeyHex = process.env.PRIVATE_KEY;

  if (!did || !privKeyHex) {
    console.error('❌ Error: PDS_DID or PRIVATE_KEY not found in .env');
    process.exit(1);
  }

  try {
    console.log(`🚀 Setting up profile for ${did}...`);
    
    // 1. Ensure DB and Repo are initialized
    await create();
    await setUpRepo();

    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
    const storage = new TursoStorage();
    const rootCid = await getRootCid();
    
    if (!rootCid) throw new Error('Failed to find repository root');
    
    const repoObj = await Repo.load(storage, CID.parse(rootCid));

    // 2. Decide between Create and Update
    const existing = await repoObj.data.get('app.bsky.actor.profile/self');
    const action = existing ? WriteOpAction.Update : WriteOpAction.Create;

    console.log(`${existing ? 'Updating' : 'Creating'} profile record...`);
    const updatedRepo = await repoObj.applyWrites([
      {
        action,
        collection: 'app.bsky.actor.profile',
        rkey: 'self',
        record: fixCids({
          $type: 'app.bsky.actor.profile',
          displayName,
          description,
          createdAt: existing ? undefined : new Date().toISOString(), // Keep original createdAt if updating
        }),
      }
    ], keypair);

    // 3. Set the birthday preference
    console.log(`Setting birthday to ${birthDate}...`);
    await db.execute({
      sql: "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)",
      args: [`birthDate:${did}`, birthDate]
    });

    // 4. Sequence the event
    const recordCid = await updatedRepo.data.get('app.bsky.actor.profile/self');
    const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: did,
      event: {
        repo: did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: action.toLowerCase(), path: 'app.bsky.actor.profile/self', cid: recordCid }],
        blobs: [],
        time: new Date().toISOString(),
        rebase: false,
        tooBig: false,
      }
    });

    console.log('✅ Profile and birthdate setup complete.');
    console.log(`Root CID: ${updatedRepo.cid.toString()}`);

    // Notify relay
    const relayHost = process.argv[5] || process.env.HANDLE;
    await pingRelay(relayHost);

    process.exit(0);
  } catch (err) {
    console.error('❌ Setup failed:', err.stack || err.message);
    process.exit(1);
  }
}

main();
