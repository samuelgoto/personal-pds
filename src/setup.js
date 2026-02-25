import fs from 'fs';
import { createHash } from 'crypto';
import * as crypto from '@atproto/crypto';
import * as cborg from 'cborg';
import { db } from './db.js';

import { WebSocket } from 'ws';
import dns from 'dns/promises';
import { Resolver } from 'dns/promises';
import { base32 } from 'multiformats/bases/base32';
import { db as defaultDb, initDb } from './db.js';
import { TursoStorage, loadRepo, getRootCid, maybeInitRepo } from './repo.js';
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
      fs.writeFileSync('.env', `PORT=3000\nTURSO_DATABASE_URL=file:local.db\n`);
    }
  }

  // 2. Initialize Database
  await initDb(db);

  // 3. Initialize repository
  await maybeInitRepo();

  // 4. Handle Private Key
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
    let pdsEndpoint = null;

    // 1. PLC Directory Check
    try {
        console.log(`[1/5] Checking PLC Directory...`);
        const resolveRes = await axios.get(`https://plc.directory/${pdsDid}`);
        pdsEndpoint = resolveRes.data.service?.[0]?.serviceEndpoint;
        const aka = resolveRes.data.alsoKnownAs?.[0];
        console.log(`  ✅ Resolved on PLC! Service: ${pdsEndpoint}, Handle: ${aka}`);
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
        let records;
        try {
            records = await dns.resolveTxt(`_atproto.${domain}`);
        } catch (e) {
            // Fallback to Google DNS if local DNS fails
            const resolver = new Resolver();
            resolver.setServers(['8.8.8.8']);
            records = await resolver.resolveTxt(`_atproto.${domain}`);
            console.log(`     (Note: Verified via Google DNS fallback)`);
        }

        const found = records.flat().find(r => r.startsWith('did='));
        if (found === `did=${pdsDid}`) {
            console.log(`  ✅ DNS Link verified!`);
        } else {
            console.warn(`  ⚠️  DNS Link mismatch or missing: ${found || 'none'}`);
            allOk = false;
        }
    } catch (err) {
        console.warn(`  ⚠️  DNS Link check failed globally: ${err.message}`);
        allOk = false;
    }

    // 4. Relay Crawl & Health
    try {
        console.log(`[4/6] Checking Relay Status (bsky.network)...`);
        
        // Check if relay has indexed the head
        let relayHead = null;
        try {
            const headRes = await axios.get(`https://bsky.network/xrpc/com.atproto.sync.getHead?did=${pdsDid}`);
            relayHead = headRes.data.root;
            console.log(`  ✅ Relay has indexed your head: ${relayHead}`);
        } catch (e) {
            console.log(`  ⚠️  Relay has NOT yet indexed your repo head.`);
        }

        console.log(`      Pinging Relay for fresh crawl...`);
        await axios.post('https://bsky.network/xrpc/com.atproto.sync.requestCrawl', { hostname: domain });
        console.log(`  ✅ Relay crawl request accepted!`);
    } catch (err) {
        console.warn(`  ⚠️  Relay interaction failed: ${err.response?.data?.message || err.message}`);
    }

    // 5. Firehose Accessibility Check
    try {
        console.log(`[5/6] Checking Firehose (WebSocket) accessibility...`);
        const wsUrl = `wss://${domain}/xrpc/com.atproto.sync.subscribeRepos`;
        const ws = new WebSocket(wsUrl);
        const wsOk = await new Promise((resolve) => {
            const timeout = setTimeout(() => {
                ws.terminate();
                resolve(false);
            }, 5000);
            ws.on('open', () => {
                clearTimeout(timeout);
                ws.close();
                resolve(true);
            });
            ws.on('error', (err) => {
                clearTimeout(timeout);
                resolve(false);
            });
        });

        if (wsOk) {
            console.log(`  ✅ Firehose is accessible via WebSocket!`);
        } else {
            console.warn(`  ❌ Firehose is NOT accessible (WebSocket upgrade failed).`);
            console.log(`     Advice: Heroku requires WebSockets. Ensure your PDS is correctly handling 'upgrade' events.`);
            allOk = false;
        }
    } catch (err) {
        console.warn(`  ⚠️  Firehose check encountered an error: ${err.message}`);
        allOk = false;
    }

    // 6. Bluesky AppView Visibility & Indexing
    try {
        console.log(`[6/6] Checking visibility & indexing on Bluesky AppView (oyster)...`);
        const appViewBase = 'https://oyster.us-east.host.bsky.network';
        
        // Check handle resolution
        const resolveRes = await axios.get(`${appViewBase}/xrpc/com.atproto.identity.resolveHandle?handle=${domain}`);
        if (resolveRes.data.did === pdsDid) {
            console.log(`  ✅ Handle resolved correctly to DID on AppView!`);
            
            // Check profile indexing
            try {
                // 1. Check by DID
                const profileByDid = await axios.get(`${appViewBase}/xrpc/app.bsky.actor.getProfile?actor=${pdsDid}`);
                console.log(`  ✅ Profile indexed by DID! Display Name: ${profileByDid.data.displayName || 'none'}`);
                
                // 2. Check by Handle
                const profileByHandle = await axios.get(`${appViewBase}/xrpc/app.bsky.actor.getProfile?actor=${domain}`);
                console.log(`  ✅ Profile indexed by HANDLE!`);
            } catch (pErr) {
                const status = pErr.response?.status;
                if (status === 401 || status === 400 || status === 404) {
                    console.warn(`  ⚠️  Identity known, but Repo NOT YET INDEXED (Status: ${status})`);
                    console.log(`     Advice: The AppView knows who you are, but hasn't successfully pulled your data from ${pdsEndpoint || 'your PDS'}.`);
                    console.log(`     This usually resolves after the Relay completes its crawl. Ensure your PDS is public and reachable.`);
                } else {
                    console.warn(`  ⚠️  Profile check failed: ${pErr.message}`);
                }
                allOk = false; // Indexing is required for "Perfect" status
            }
        } else {
            console.warn(`  ⚠️  AppView resolved handle ${domain} to DIFFERENT DID: ${resolveRes.data.did}`);
            allOk = false;
        }
    } catch (err) {
        console.warn(`  ⚠️  AppView check failed: ${err.message}`);
        allOk = false;
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
