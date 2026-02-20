import fs from 'fs';
import { createHash } from 'crypto';
import * as crypto from '@atproto/crypto';
import { cborEncode } from '@atproto/common';
import axios from 'axios';
import { db as defaultDb, initDb } from './db.js';
import { TursoStorage, loadRepo, getRootCid } from './repo.js';
import { sequencer } from './sequencer.js';
import { blocksToCarFile, WriteOpAction } from '@atproto/repo';
import { formatDid } from './util.js';

export async function runFullSetup(options = {}) {
  const {
    db = defaultDb,
    interactive = false,
    skipPlc = true,
    domain: providedDomain,
    rl = null // readline interface
  } = options;

  const results = {
    updatedEnv: false,
    did: null,
    rootCid: null,
  };

  // 1. Ensure .env exists (only if not in a test environment)
  if (!(process.env.NODE_ENV === 'test') && !fs.existsSync('.env')) {
    if (fs.existsSync('.env.example')) {
      fs.copyFileSync('.env.example', '.env');
    } else {
      fs.writeFileSync('.env', `PORT=3000\nDATABASE_URL=file:local.db\n`);
    }
  }

  // 2. Initialize Database
  await initDb(db);

  // 3. Handle Private Key
  let privKeyHex = process.env.PRIVATE_KEY;
  if (!privKeyHex) {
    const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    privKeyHex = Buffer.from(await keypair.export()).toString('hex');
    process.env.PRIVATE_KEY = privKeyHex;
    updateEnvFile('PRIVATE_KEY', privKeyHex);
    results.updatedEnv = true;
  }

  // 4. Identity Setup (did:plc)
  let domain = providedDomain || (process.env.DOMAIN || 'localhost:3000').split(':')[0];
  let pdsDid = process.env.PDS_DID;

  if (!pdsDid) {
    if (skipPlc) {
        // In tests or when skipped, we use a deterministic but unique placeholder for did:plc
        const hash = createHash('sha256').update(domain).digest('hex').slice(0, 24);
        pdsDid = `did:plc:${hash}`;
        console.log(`Using placeholder identity: ${pdsDid}`);
    } else if (interactive && rl) {
        console.log(`No PDS_DID found. Starting did:plc registration for ${domain}...`);
        pdsDid = await registerPlc(domain, privKeyHex, rl);
        if (!pdsDid) {
            console.log('Registration failed, using deterministic fallback for PDS_DID.');
            const hash = createHash('sha256').update(domain + privKeyHex).digest('hex').slice(0, 24);
            pdsDid = `did:plc:${hash}`;
        }
    }

    if (pdsDid) {
        process.env.PDS_DID = pdsDid;
        updateEnvFile('PDS_DID', pdsDid);
        results.updatedEnv = true;
    } else {
        throw new Error('Identity setup failed. PDS_DID is required.');
    }
  }

  const did = pdsDid;
  results.did = did;

  // 5. Repo Initialization
  const existingRoot = await getRootCid();
  if (existingRoot) {
    results.rootCid = existingRoot;
    return results;
  }

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
  const storage = new TursoStorage();
  
  let repo = await loadRepo(storage, did, keypair, null);
  repo = await repo.applyWrites([{
    action: WriteOpAction.Create,
    collection: 'app.bsky.actor.profile',
    rkey: 'self',
    record: {
      $type: 'app.bsky.actor.profile',
      displayName: process.env.DISPLAY_NAME || domain,
      description: process.env.DESCRIPTION || 'Personal PDS',
      createdAt: new Date().toISOString(),
    },
  }], keypair);

  const recordCid = await repo.data.get('app.bsky.actor.profile/self');
  const carBlocks = await storage.getRepoBlocks();
  const blocks = await blocksToCarFile(repo.cid, carBlocks);

  await sequencer.sequenceEvent({
    did,
    type: 'commit',
    event: {
      repo: did,
      commit: repo.cid,
      blocks,
      rev: repo.commit.rev,
      since: null,
      ops: [{ action: 'create', path: 'app.bsky.actor.profile/self', cid: recordCid || repo.cid }],
      time: new Date().toISOString(),
    }
  });

  results.rootCid = repo.cid.toString();
  return results;
}

function updateEnvFile(key, value) {
  if (process.env.NODE_ENV === 'test' || !fs.existsSync('.env')) return;
  let content = fs.readFileSync('.env', 'utf8');
  if (content.includes(`${key}=`)) {
    content = content.replace(new RegExp(`${key}=.*`), `${key}=${value}`);
  } else {
    content += `\n${key}=${value}`;
  }
  fs.writeFileSync('.env', content);
}

async function registerPlc(domain, signingKeyHex, rl) {
  try {
    const signingKeypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(signingKeyHex, 'hex')));
    const rotationKeypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    const rotationKeyHex = Buffer.from(await rotationKeypair.export()).toString('hex');
    
    const op = {
      type: 'plc_operation',
      rotationKeys: [rotationKeypair.did()],
      verificationMethods: {
        atproto: signingKeypair.did(),
      },
      alsoKnownAs: [`at://${domain}`],
      services: {
        atproto_pds: {
          type: 'AtprotoPersonalDataServer',
          endpoint: `https://${domain}`,
        },
      },
      prev: null,
    };

    const signature = await rotationKeypair.sign(cborEncode(op));
    const signedOp = {
      ...op,
      sig: Buffer.from(signature).toString('base64url'),
    };

    console.log('\nRegistering identity on https://plc.directory...');
    
    const hash = createHash('sha256').update(cborEncode(signedOp)).digest();
    const plcDid = `did:plc:${Buffer.from(hash).toString('hex').slice(0, 24)}`;
    
    await axios.post(`https://plc.directory/${plcDid}`, signedOp);
    
    updateEnvFile('PLC_ROTATION_KEY', rotationKeyHex);
    return plcDid;
  } catch (err) {
    console.error('PLC Registration failed:', err.response?.data || err.message);
    return null;
  }
}
