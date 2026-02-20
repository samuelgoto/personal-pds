import express from 'express';
import { db } from './db.js';
import { createToken, verifyToken } from './auth.js';
import { TursoStorage, getRootCid } from './repo.js';
import { Repo, WriteOpAction, blocksToCarFile } from '@atproto/repo';
import * as crypto from '@atproto/crypto';
import { createHash } from 'crypto';
import { CID } from 'multiformats';
import { sequencer } from './sequencer.js';
import { WebSocketServer } from 'ws';
import { formatDid, getStaticAvatar, createTid } from './util.js';

const app = express();

// 1. CORS middleware (Absolute top)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, atproto-accept-labelers, atproto-proxy-type, atproto-proxy, atproto-proxy-exp, atproto-content-type, x-bsky-topics, x-bsky-active-labelers');
  res.setHeader('Access-Control-Expose-Headers', 'atproto-content-type, atproto-proxy, atproto-proxy-exp, x-bsky-topics, x-bsky-active-labelers');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// 2. Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// 3. JSON parser
app.use(express.json());

export const wss = new WebSocketServer({ noServer: true });


wss.on('connection', (ws, req) => {
  const url = new URL(req.url || '', `http://${req.headers.host}`);
  const cursor = url.searchParams.get('cursor');
  sequencer.addClient(ws, cursor ? parseInt(cursor, 10) : undefined);
});

// Helper to get system state
const getSystemMeta = async (key) => {
  try {
    const res = await db.execute({
      sql: 'SELECT value FROM system_state WHERE key = ?',
      args: [key]
    });
    return res.rows.length > 0 ? res.rows[0].value : null;
  } catch (e) {
    return null;
  }
};

// Helper to get the current host safely
export const getHost = (req) => {
  return (req.headers['x-forwarded-host'] || req.get('host') || 'localhost').split(':')[0];
};

// Helper to get the single allowed user from Env
const getSingleUser = async (req) => {
  const host = getHost(req);
  const domain = host;
  const handle = domain === 'localhost' ? 'localhost.test' : domain;
  
  const did = formatDid(domain);
  const privKeyHex = process.env.PRIVATE_KEY;
  const password = process.env.PASSWORD;
  
  if (!password) {
    throw new Error('PASSWORD environment variable is not set');
  }
  
  const root_cid = await getRootCid();
  
  if (!privKeyHex || !root_cid) return null;
  
  return {
    handle,
    password,
    did,
    signing_key: Buffer.from(privKeyHex, 'hex'),
    root_cid
  };
};

const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.log(`Auth failed: No Authorization header for ${req.url}`);
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }
  const token = authHeader.split(' ')[1];
  const payload = verifyToken(token);
  if (!payload) {
    console.log(`Auth failed: Invalid token for ${req.url}`);
    return res.status(401).json({ error: 'InvalidToken' });
  }
  req.user = payload;
  next();
};

// --- Endpoints ---
app.get('/.well-known/atproto-did', async (req, res) => {
  const host = getHost(req);
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Cache-Control', 'no-cache');
  // Use res.write and res.end to ensure absolutely no extra formatting
  res.write(formatDid(host));
  res.end();
});

app.get('/xrpc/com.atproto.identity.getRecommendedDidCredentials', async (req, res) => {
  res.json({
    rotationKeys: [],
    alsoKnownAs: [],
    verificationMethods: {},
    services: {}
  });
});

// --- Dashboard ---
app.get('/', async (req, res) => {
  const user = await getSingleUser(req);
  const blockCountRes = await db.execute('SELECT count(*) as count FROM repo_blocks');
  const eventCountRes = await db.execute('SELECT count(*) as count FROM sequencer');
  const lastPing = await getSystemMeta('last_relay_ping');

  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Minimal PDS Status</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; max-width: 800px; margin: 40px auto; padding: 20px; background: #f4f4f9; color: #333; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h1 { color: #007bff; }
        .stat { display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 10px 0; }
        .stat:last-child { border-bottom: none; }
        .label { font-weight: bold; }
        .value { font-family: monospace; color: #666; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warn { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Personal PDS Dashboard</h1>
    
    <div class="card">
        <h2>Identity</h2>
        <div class="stat"><span class="label">Handle</span><span class="value">${user?.handle || 'Not Initialized'}</span></div>
        <div class="stat"><span class="label">DID</span><span class="value">${user?.did || 'N/A'}</span></div>
        <div class="stat"><span class="label">PDS Domain</span><span class="value">${process.env.DOMAIN || req.get('host')}</span></div>
    </div>

    <div class="card">
        <h2>Storage & Activity</h2>
        <div class="stat"><span class="label">Total Blocks</span><span class="value">${blockCountRes.rows[0].count}</span></div>
        <div class="stat"><span class="label">Event Log Length</span><span class="value">${eventCountRes.rows[0].count}</span></div>
        <div class="stat"><span class="label">Current Root CID</span><span class="value" style="font-size: 0.8em;">${user?.root_cid || 'None'}</span></div>
    </div>

    <div class="card">
        <h2>Network Status</h2>
        <div class="stat">
            <span class="label">Relay Crawler Status</span>
            <span class="value ${lastPing ? 'status-ok' : 'status-warn'}">
                ${lastPing ? 'Registered' : 'Not Registered (Run on public domain)'}
            </span>
        </div>
        <div class="stat"><span class="label">Last Relay Ping</span><span class="value">${lastPing || 'Never'}</span></div>
    </div>

    <div class="card">
        <h2>System</h2>
        <div class="stat"><span class="label">Node.js Version</span><span class="value">${process.version}</span></div>
        <div class="stat"><span class="label">Database Type</span><span class="value">Turso/libSQL</span></div>
    </div>
</body>
</html>
  `;
  res.send(html);
});

app.get('/debug/ping-relay', async (req, res) => {
  try {
    const { pingRelay } = await import('../api/index.js');
    const host = getHost(req);
    const result = await pingRelay(host);
    res.json({
        host,
        result
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper to generate the DID document
const getDidDoc = async (req, host) => {
  const did = formatDid(host);
  const privKeyHex = process.env.PRIVATE_KEY;
  if (!privKeyHex) return null;

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production' || !host.includes('localhost')) ? 'https' : 'http';
  const serviceEndpoint = `${protocol}://${host}`;

  return {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multiconf/v1",
        "https://w3id.org/security/suites/secp256k1-2019/v1"
    ],
    "id": did,
    "alsoKnownAs": [`at://${host}`],
    "verificationMethod": [
      {
        "id": "#atproto",
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": keypair.did().split(':').pop()
      }
    ],
    "authentication": ["#atproto"],
    "assertionMethod": ["#atproto"],
    "capabilityInvocation": ["#atproto"],
    "capabilityDelegation": ["#atproto"],
    "service": [{
      "id": "#atproto_pds",
      "type": "AtprotoPersonalDataServer",
      "serviceEndpoint": serviceEndpoint
    }]
  };
};

app.get('/xrpc/com.atproto.identity.resolveDid', async (req, res) => {
  try {
    const { did } = req.query;
    const user = await getSingleUser(req);
    if (!user || did !== user.did) return res.status(404).json({ error: 'DidNotFound' });

    const host = getHost(req);
    const doc = await getDidDoc(req, host);
    if (!doc) return res.status(404).json({ error: 'DidNotFound' });

    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.identity.resolveHandle', async (req, res) => {
  const { handle } = req.query;
  const user = await getSingleUser(req);
  if (!user) return res.status(404).json({ error: 'HandleNotFound' });
  
  // If no handle provided, or it matches our domain, return our DID
  if (!handle || handle === user.handle || handle === 'self') {
    return res.json({ did: user.did.trim() });
  }

  return res.status(404).json({ error: 'HandleNotFound' });
});

app.post('/xrpc/com.atproto.server.createSession', async (req, res) => {
  const { identifier, password } = req.body;
  const user = await getSingleUser(req);
  if (!user) {
    console.log('Login failed: Server not initialized (no user)');
    return res.status(500).json({ error: 'ServerNotInitialized' });
  }

  if (identifier !== user.handle && identifier !== user.did) {
    console.log(`Login failed: Invalid identifier. Received: ${identifier}, Expected: ${user.handle} or ${user.did}`);
    return res.status(401).json({ error: 'InvalidIdentifier' });
  }

  if (password !== user.password) {
    console.log(`Login failed: Password mismatch for ${identifier}`);
    return res.status(401).json({ error: 'InvalidPassword' });
  }

  const accessJwt = createToken(user.did, user.handle);  res.json({ accessJwt, refreshJwt: accessJwt, handle: user.handle, did: user.did });
});

app.post('/xrpc/com.atproto.server.refreshSession', auth, async (req, res) => {
  const user = await getSingleUser(req);
  if (!user) return res.status(500).json({ error: 'ServerNotInitialized' });
  
  const accessJwt = createToken(user.did, user.handle);
  res.json({ accessJwt, refreshJwt: accessJwt, handle: user.handle, did: user.did });
});

app.get('/xrpc/com.atproto.server.getAccount', auth, async (req, res) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.status(404).json({ error: 'UserNotFound' });
    
    const birthDate = await getSystemMeta(`birthDate:${user.did}`) || '1990-01-01';

    res.json({
      handle: user.handle,
      did: user.did,
      email: 'pds@example.com',
      emailConfirmed: true,
      birthDate: birthDate,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.server.getSession', auth, async (req, res) => {
  res.json({ handle: req.user.handle, did: req.user.sub });
});

app.post('/xrpc/com.atproto.repo.createRecord', auth, async (req, res) => {
  try {
    const { repo, collection, record, rkey } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const finalRkey = rkey || createTid();
    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Create, collection, rkey: finalRkey, record }], keypair);
    
    // The path in MST is "collection/rkey", accessed via .data.get()
    const recordCid = await updatedRepo.data.get(collection + '/' + finalRkey);
    if (!recordCid) {
        console.error(`Failed to find CID in MST for path: ${collection}/${finalRkey}`);
    }

    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'create', path: `${collection}/${finalRkey}`, cid: recordCid || updatedRepo.cid }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({ 
        uri: `at://${user.did}/${collection}/${finalRkey}`, 
        cid: recordCid?.toString() || updatedRepo.cid.toString(),
        commit: {
            cid: updatedRepo.cid.toString(),
            rev: updatedRepo.commit.rev
        }
    });
  } catch (err) {
    console.error('Error in createRecord:', err);
    res.status(500).json({ error: 'InternalServerError', message: err.message });
  }
});

app.post('/xrpc/com.atproto.repo.putRecord', auth, async (req, res) => {
  try {
    const { repo, collection, rkey, record } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Update, collection, rkey, record }], keypair);

    const recordCid = await updatedRepo.data.get(collection + '/' + rkey);
    if (!recordCid) {
        console.error(`Failed to find CID in MST for path: ${collection}/${rkey}`);
    }

    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'update', path: `${collection}/${rkey}`, cid: recordCid || updatedRepo.cid }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({ 
        uri: `at://${user.did}/${collection}/${rkey}`, 
        cid: recordCid?.toString() || updatedRepo.cid.toString(),
        commit: {
            cid: updatedRepo.cid.toString(),
            rev: updatedRepo.commit.rev
        }
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.post('/xrpc/com.atproto.repo.deleteRecord', auth, async (req, res) => {
  try {
    const { repo, collection, rkey } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Delete, collection, rkey }], keypair);

    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'delete', path: `${collection}/${rkey}`, cid: null }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.post('/xrpc/com.atproto.repo.applyWrites', auth, async (req, res) => {
  try {
    const { repo, writes, swapCommit } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });

    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));

    const repoWrites = writes.map(w => {
        if (w.$type === 'com.atproto.repo.applyWrites#create') {
            return { action: WriteOpAction.Create, collection: w.collection, rkey: w.rkey || createTid(), record: w.value };
        } else if (w.$type === 'com.atproto.repo.applyWrites#update') {
            return { action: WriteOpAction.Update, collection: w.collection, rkey: w.rkey, record: w.value };
        } else if (w.$type === 'com.atproto.repo.applyWrites#delete') {
            return { action: WriteOpAction.Delete, collection: w.collection, rkey: w.rkey };
        }
        throw new Error(`Unknown write action: ${w.$type}`);
    });

    const updatedRepo = await repoObj.applyWrites(repoWrites, keypair);

    // Prepare ops for the sequencer event
    const ops = [];
    for (const w of repoWrites) {
        let cid = null;
        if (w.action !== WriteOpAction.Delete) {
            cid = await updatedRepo.data.get(w.collection + '/' + w.rkey);
        }
        ops.push({
            action: w.action.toLowerCase(),
            path: `${w.collection}/${w.rkey}`,
            cid: cid
        });
    }

    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: ops,
        time: new Date().toISOString(),
      }
    });

    res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
  } catch (err) {
    console.error('Error in applyWrites:', err);
    res.status(500).json({ error: 'InternalServerError', message: err.message });
  }
});

app.get('/xrpc/app.bsky.actor.getProfile', async (req, res) => {
  try {
    const { actor } = req.query;
    const user = await getSingleUser(req);
    if (!user || (actor !== user.did && actor !== user.handle)) {
        return res.status(404).json({ error: 'ProfileNotFound' });
    }

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();
    
    res.json({
        did: user.did,
        handle: user.handle,
        displayName: profile?.displayName || user.handle,
        description: profile?.description || '',
        avatar: profile?.avatar,
        banner: profile?.banner,
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        viewer: {
            muted: false,
            blockedBy: false,
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Error in getProfile:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.actor.getProfiles', async (req, res) => {
  try {
    const actors = Array.isArray(req.query.actors) ? req.query.actors : [req.query.actors];
    const user = await getSingleUser(req);
    const profiles = [];

    if (user) {
        const storage = new TursoStorage();
        const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
        const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
        const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();

        const localProfile = {
            did: user.did,
            handle: user.handle,
            displayName: profile?.displayName || user.handle,
            description: profile?.description || '',
            avatar: profile?.avatar,
            banner: profile?.banner,
            associated: {
                activitySubscription: { allowSubscriptions: 'followers' }
            },
            viewer: {
                muted: false,
                blockedBy: false,
            },
            labels: [],
            createdAt: repoCreatedAt,
            indexedAt: new Date().toISOString(),
        };

        for (const actor of actors) {
            if (actor === user.did || actor === user.handle) {
                profiles.push(localProfile);
            }
        }
    }

    res.json({ profiles });
  } catch (err) {
    console.error('Error in getProfiles:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.actor.getPreferences', auth, async (req, res) => {
  try {
    const prefsJson = await getSystemMeta(`prefs:${req.user.sub}`);
    let preferences = prefsJson ? JSON.parse(prefsJson) : [];
    
    // Ensure there is at least an adultContentPref if missing
    if (!preferences.find(p => p.$type === 'app.bsky.actor.defs#adultContentPref')) {
        preferences.push({
            $type: 'app.bsky.actor.defs#adultContentPref',
            enabled: true
        });
    }

    res.json({ preferences });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.post('/xrpc/app.bsky.actor.putPreferences', auth, async (req, res) => {
  try {
    const { preferences } = req.body;
    
    // Extract and store birthDate if provided in personalDetailsPref
    const personalDetailsPref = preferences.find(p => p.$type === 'app.bsky.actor.defs#personalDetailsPref');
    if (personalDetailsPref?.birthDate) {
        await db.execute({
            sql: "INSERT OR REPLACE INTO system_state (key, value) VALUES (?, ?)",
            args: [`birthDate:${req.user.sub}`, personalDetailsPref.birthDate]
        });
    }

    await db.execute({
      sql: "INSERT OR REPLACE INTO system_state (key, value) VALUES (?, ?)",
      args: [`prefs:${req.user.sub}`, JSON.stringify(preferences)]
    });
    res.json({});
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

const getAuthorFeed = async (req, res, actor, limit) => {
  try {
    const user = await getSingleUser(req);
    if (!user || (actor !== user.did && actor !== user.handle)) {
        return res.json({ feed: [] });
    }

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();
    
    const author = {
        did: user.did,
        handle: user.handle,
        displayName: profile?.displayName || user.handle,
        avatar: profile?.avatar,
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        viewer: {
            muted: false,
            blockedBy: false,
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    };

    const feed = [];
    for await (const rec of repoObj.walkRecords()) {
      if (rec.collection === 'app.bsky.feed.post') {
        feed.push({
            post: {
                uri: `at://${user.did}/${rec.collection}/${rec.rkey}`,
                cid: rec.cid.toString(),
                author,
                record: rec.record,
                replyCount: 0,
                repostCount: 0,
                likeCount: 0,
                indexedAt: rec.record.createdAt || new Date().toISOString(),
                viewer: {},
                labels: [],
            }
        });
      }
    }
    
    feed.sort((a, b) => new Date(b.post.record.createdAt).getTime() - new Date(a.post.record.createdAt).getTime());

    res.json({ 
        feed: feed.slice(0, parseInt(limit || '50', 10)),
    });
  } catch (err) {
    console.error('Error in getAuthorFeed:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
};

app.get('/xrpc/app.bsky.feed.getAuthorFeed', async (req, res) => {
  return getAuthorFeed(req, res, req.query.actor, req.query.limit);
});

app.get('/xrpc/app.bsky.feed.getTimeline', auth, async (req, res) => {
  const host = getHost(req);
  const userDid = formatDid(host);
  return getAuthorFeed(req, res, userDid, req.query.limit);
});

app.get('/xrpc/app.bsky.feed.getFeed', auth, async (req, res) => {
  res.json({ feed: [] });
});

app.post('/xrpc/com.atproto.repo.uploadBlob', auth, express.raw({ type: '*/*', limit: '5mb' }), async (req, res) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.status(403).json({ error: 'InvalidRepo' });

    const content = req.body;
    const mimeType = req.headers['content-type'] || 'application/octet-stream';
    
    // Simple hash for CID-like identifier
    const hash = createHash('sha256').update(content).digest('hex');
    const cid = `bafybe${hash}`; // Fake CID for now

    await db.execute({
      sql: "INSERT OR REPLACE INTO blobs (cid, mime_type, content, created_at) VALUES (?, ?, ?, ?)",
      args: [cid, mimeType, content, new Date().toISOString()]
    });

    res.json({
      blob: {
        $type: 'blob',
        ref: { $link: cid },
        mimeType: mimeType,
        size: content.length,
      }
    });
  } catch (err) {
    console.error('Error in uploadBlob:', err);
    res.status(500).json({ error: 'InternalServerError', message: err.message });
  }
});

app.get('/xrpc/com.atproto.sync.getBlob', async (req, res) => {
  try {
    const { cid } = req.query;
    
    // Check for static avatar fallback
    const staticAvatar = getStaticAvatar();
    if (staticAvatar && staticAvatar.cid === cid) {
        res.setHeader('Content-Type', staticAvatar.mimeType);
        return res.send(staticAvatar.content);
    }

    const result = await db.execute({
      sql: "SELECT mime_type, content FROM blobs WHERE cid = ?",
      args: [cid]
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'BlobNotFound' });
    }

    const { mime_type, content } = result.rows[0];
    res.setHeader('Content-Type', mime_type);
    res.send(Buffer.from(content));
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

const getPostThread = async (req, res, uri) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.status(404).json({ error: 'PostNotFound' });

    // Support both at://did:web:pds.sgo.to and at://pds.sgo.to
    const isLocalDid = uri.startsWith(`at://${user.did}`);
    const isLocalHandle = uri.startsWith(`at://${user.handle}`);

    if (!isLocalDid && !isLocalHandle) {
        return res.status(404).json({ error: 'PostNotFound' });
    }

    const parts = uri.replace('at://', '').split('/');
    const collection = parts[1];
    const rkey = parts[2];

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const record = await repoObj.getRecord(collection, rkey);

    if (!record) {
        return res.status(404).json({ error: 'PostNotFound' });
    }

    const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();

    const author = {
        did: user.did,
        handle: user.handle,
        displayName: profile?.displayName || user.handle,
        avatar: profile?.avatar,
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        viewer: {
            muted: false,
            blockedBy: false,
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    };

    res.json({
        thread: {
            $type: 'app.bsky.feed.defs#threadViewPost',
            post: {
                uri,
                cid: user.root_cid, // Approximate
                author,
                record,
                replyCount: 0,
                repostCount: 0,
                likeCount: 0,
                quoteCount: 0,
                bookmarkCount: 0,
                indexedAt: record.createdAt || new Date().toISOString(),
                viewer: {},
                labels: [],
            },
            replies: [],
            threadContext: {},
        }
    });
  } catch (err) {
    console.error('Error in getPostThread:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
};

app.get('/xrpc/app.bsky.feed.getPostThread', async (req, res) => {
  return getPostThread(req, res, req.query.uri);
});

app.get('/xrpc/app.bsky.unspecced.getPostThreadV2', async (req, res) => {
  return getPostThread(req, res, req.query.anchor);
});

app.get('/xrpc/app.bsky.graph.getFollows', async (req, res) => {
  try {
    const { actor } = req.query;
    const user = await getSingleUser(req);
    
    let profile = undefined;
    if (user && (actor === user.did || actor === user.handle)) {
        profile = {
            did: user.did,
            handle: user.handle,
            indexedAt: new Date().toISOString(),
        };
    }

    res.json({
        follows: [],
        subject: profile,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.graph.getFollowers', async (req, res) => {
  res.json({ followers: [] });
});

app.get('/xrpc/app.bsky.graph.getSuggestedFollowsByActor', async (req, res) => {
  res.json({ suggestions: [] });
});

app.get('/xrpc/app.bsky.graph.getMutes', auth, async (req, res) => {
  res.json({ mutes: [] });
});

app.get('/xrpc/app.bsky.graph.getBlocks', auth, async (req, res) => {
  res.json({ blocks: [] });
});

app.get('/xrpc/app.bsky.actor.getSuggestions', auth, async (req, res) => {
  res.json({ actors: [] });
});

app.get('/xrpc/app.bsky.notification.getUnreadCount', auth, async (req, res) => {
  res.json({ count: 0 });
});


app.get('/xrpc/app.bsky.unspecced.getConfig', async (req, res) => {
  res.json({});
});

app.get('/xrpc/app.bsky.labeler.getServices', async (req, res) => {
  res.json({ views: [] });
});

app.get('/xrpc/app.bsky.ageassurance.getState', async (req, res) => {
  res.json({ status: 'verified' });
});

app.get('/xrpc/chat.bsky.convo.getLog', auth, async (req, res) => {
  res.json({ logs: [] });
});

app.get('/xrpc/chat.bsky.convo.listConvos', auth, async (req, res) => {
  res.json({ convos: [] });
});

app.get('/xrpc/app.bsky.notification.listNotifications', auth, async (req, res) => {
  res.json({ 
    notifications: [], 
    cursor: undefined,
    seenAt: new Date().toISOString()
  });
});

app.post('/xrpc/app.bsky.notification.updateSeen', auth, async (req, res) => {
  res.json({});
});

app.get('/xrpc/app.bsky.draft.getDrafts', auth, async (req, res) => {
  res.json({ drafts: [] });
});

app.get('/xrpc/com.atproto.server.describeServer', async (req, res) => {
  const host = getHost(req);
  res.json({ availableUserDomains: [host], did: formatDid(host) });
});

app.get('/xrpc/com.atproto.repo.listRecords', async (req, res) => {
  try {
    const { repo, collection, limit } = req.query;
    const user = await getSingleUser(req);
    if (!user || (repo !== user.did && repo !== user.handle)) return res.status(404).json({ error: 'RepoNotFound' });

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const records = [];
    for await (const rec of repoObj.walkRecords()) {
      if (rec.collection === collection) {
        records.push({ uri: `at://${user.did}/${rec.collection}/${rec.rkey}`, cid: rec.cid.toString(), value: rec.record });
      }
    }
    res.json({ records: records.slice(0, parseInt(limit || '50', 10)) });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.repo.getRecord', async (req, res) => {
  const { repo, collection, rkey } = req.query;
  const user = await getSingleUser(req);
  if (!user || (repo !== user.did && repo !== user.handle)) return res.status(404).json({ error: 'RepoNotFound' });
  
  const storage = new TursoStorage();
  const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
  const record = await repoObj.getRecord(collection, rkey);
  
  if (!record) return res.status(404).json({ error: 'RecordNotFound' });
  res.json({ uri: `at://${user.did}/${collection}/${rkey}`, value: record });
});

app.get('/xrpc/com.atproto.repo.describeRepo', async (req, res) => {
  try {
    const { repo } = req.query;
    const user = await getSingleUser(req);
    if (!user || (repo !== user.did && repo !== user.handle)) {
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    const host = getHost(req);
    const didDoc = await getDidDoc(req, host);

    res.json({
        handle: user.handle,
        did: user.did,
        didDoc: didDoc,
        collections: [
            'app.bsky.actor.profile',
            'app.bsky.feed.post',
            'app.bsky.feed.like',
            'app.bsky.feed.repost',
            'app.bsky.graph.follow'
        ],
        handleIsCorrect: true,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.getHead', async (req, res) => {
  try {
    const { did } = req.query;
    const user = await getSingleUser(req);
    if (!user || did !== user.did) {
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    res.json({
        root: user.root_cid,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.listRepos', async (req, res) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.json({ repos: [] });

    res.json({
        repos: [{
            did: user.did,
            head: user.root_cid,
        }]
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.subscribeRepos', async (req, res) => {
  try {
    const { cursor } = req.query;
    const startSeq = cursor ? parseInt(cursor, 10) : 0;

    const result = await db.execute({
      sql: 'SELECT * FROM sequencer WHERE seq > ? ORDER BY seq ASC LIMIT 100',
      args: [startSeq]
    });

    res.setHeader('Content-Type', 'application/vnd.ipld.car');
    
    // We send back the events as a stream of frames
    for (const row of result.rows) {
        const frame = sequencer.formatEvent(row);
        res.write(frame);
    }
    
    res.end();
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.getRepo', async (req, res) => {
  const { did } = req.query;
  const host = getHost(req);
  if (did !== formatDid(host)) return res.status(404).json({ error: 'RepoNotFound' });
  
  const rootCid = await getRootCid();
  if (!rootCid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(rootCid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

export default app;
