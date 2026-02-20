import fs from 'fs';
import { createHash } from 'crypto';
import * as crypto from '@atproto/crypto';
import { cborEncode } from '@atproto/common';
import axios from 'axios';
import dns from 'dns/promises';
import { base32 } from 'multiformats/bases/base32';
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

  if (!pdsDid || !pdsDid.startsWith('did:plc:')) {
    if (skipPlc) {
        const hash = createHash('sha256').update(domain).digest('hex').slice(0, 24);
        pdsDid = `did:plc:${hash}`;
        console.log(`Using placeholder identity: ${pdsDid}`);
    } else if (interactive && rl) {
        console.log(`No valid PDS_DID found. Starting did:plc registration for ${domain}...`);
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

  // Verification Suite
  if (!skipPlc && pdsDid.startsWith('did:plc:')) {
      await verifyIdentity(pdsDid, domain, interactive, rl, options, privKeyHex);
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

async function verifyIdentity(pdsDid, domain, interactive, rl, options, privKeyHex) {
    console.log(`\n--- Identity Verification for ${pdsDid} ---`);
    let allOk = true;

    // 1. PLC Directory Check
    try {
        console.log(`[1/5] Checking PLC Directory...`);
        const resolveRes = await axios.get(`https://plc.directory/${pdsDid}`);
        const service = resolveRes.data.service?.[0]?.serviceEndpoint;
        const aka = resolveRes.data.alsoKnownAs?.[0];
        console.log(`  ✅ Resolved on PLC! Service: ${service}, Handle: ${aka}`);
    } catch (err) {
        console.error(`  ❌ Failed to resolve on PLC Directory.`);
        allOk = false;
    }

    // 2. Handle Resolution Check (HTTP)
    try {
        console.log(`[2/5] Checking Handle Link (HTTP .well-known)...`);
        const wellKnownRes = await axios.get(`https://${domain}/.well-known/atproto-did`);
        if (wellKnownRes.data.trim() === pdsDid) {
            console.log(`  ✅ HTTP Link verified!`);
        } else {
            console.warn(`  ⚠️  HTTP Link mismatch: expected ${pdsDid}, got ${wellKnownRes.data.trim()}`);
            allOk = false;
        }
    } catch (err) {
        console.warn(`  ⚠️  HTTP Link check failed: ${err.message}`);
        allOk = false;
    }

    // 3. Handle Resolution Check (DNS)
    try {
        console.log(`[3/5] Checking Handle Link (DNS TXT)...`);
        const records = await dns.resolveTxt(`_atproto.${domain}`);
        const found = records.flat().find(r => r.startsWith('did='));
        if (found === `did=${pdsDid}`) {
            console.log(`  ✅ DNS Link verified!`);
        } else {
            console.warn(`  ⚠️  DNS Link mismatch or missing: ${found || 'none'}`);
            allOk = false;
        }
    } catch (err) {
        console.warn(`  ⚠️  DNS Link check failed: ${err.message}`);
        allOk = false;
    }

    // 4. Relay Crawl Request
    try {
        console.log(`[4/5] Pinging Bluesky Relay (Requesting Crawl)...`);
        await axios.post('https://bsky.network/xrpc/com.atproto.sync.requestCrawl', { hostname: domain });
        console.log(`  ✅ Relay pinged successfully!`);
    } catch (err) {
        console.warn(`  ⚠️  Relay ping failed: ${err.response?.data?.message || err.message}`);
        // Relay might fail if it can't reach you yet, but we continue
    }

    // 5. Bluesky AppView Visibility
    try {
        console.log(`[5/5] Checking visibility on Bluesky AppView (oyster)...`);
        const appViewBase = 'https://oyster.us-east.host.bsky.network';
        
        // Check handle resolution on specific AppView node
        const resolveRes = await axios.get(`${appViewBase}/xrpc/com.atproto.identity.resolveHandle?handle=${domain}`);
        if (resolveRes.data.did === pdsDid) {
            console.log(`  ✅ Handle successfully resolved to DID on AppView node!`);
            
            // Now check profile on that same node
            try {
                const profileRes = await axios.get(`${appViewBase}/xrpc/app.bsky.actor.getProfile?actor=${pdsDid}`);
                console.log(`  ✅ Profile is LIVE on AppView node! Display Name: ${profileRes.data.displayName || 'none'}`);
            } catch (pErr) {
                console.warn(`  ⚠️  DID resolves, but profile is not yet indexed on this AppView node. (Status: ${pErr.response?.status})`);
            }
        } else {
            console.warn(`  ⚠️  AppView node resolved handle ${domain} to DIFFERENT DID: ${resolveRes.data.did}`);
            allOk = false;
        }
    } catch (err) {
        if (err.response?.status === 404 || err.response?.status === 400) {
            console.warn(`  ⚠️  Not yet indexed on Bluesky AppView. (This is normal for new accounts)`);
        } else {
            console.warn(`  ⚠️  AppView check failed: ${err.message}`);
        }
    }

    if (!allOk) {
        console.log(`\n--- 🛠️  Troubleshooting Advice ---`);
        console.log(`1. Ensure Vercel environment variables are correct (PDS_DID, PRIVATE_KEY).`);
        console.log(`2. DNS: Add a TXT record at _atproto.${domain} with value: did=${pdsDid}`);
        console.log(`3. Wait: Network propagation can take 5-10 minutes.`);
        
        if (interactive && rl && !rl.closed) {
            const retry = await new Promise(r => rl.question('\nIdentity is not fully setup. Try verifying again? (y/N): ', r));
            if (retry.toLowerCase() === 'y') {
                return runFullSetup({ ...options, domain, rl });
            }
        }
    } else {
        console.log(`\n✨ Identity looks perfect! You are live on the AT Protocol.`);
    }
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

    const hash = createHash('sha256').update(cborEncode(signedOp)).digest();
    const encoded = base32.encode(hash).slice(1);
    const plcDid = `did:plc:${encoded.slice(0, 24)}`;

    console.log(`\nCalculated DID: ${plcDid}`);
    console.log('Registering identity on https://plc.directory...');
    
    await axios.post(`https://plc.directory/${plcDid}`, signedOp);
    
    updateEnvFile('PLC_ROTATION_KEY', rotationKeyHex);
    return plcDid;
  } catch (err) {
    console.error('PLC Registration failed:', err.response?.data || err.message);
    return null;
  }
}
