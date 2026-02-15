import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { initDb, createDb, setDb } from '../src/db.js';
import { sequencer } from '../src/sequencer.js';
import * as crypto from '@atproto/crypto';
import { maybeInitRepo } from '../src/repo.js';
import { formatDid } from '../src/util.js';
import { cborDecode } from '@atproto/common';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3007;
const HOST = `http://localhost:${PORT}`;
const DOMAIN = `localhost`; // Clean domain for tests

describe('Bluesky Compatibility / Rigorous Identity Tests', () => {
  let server;
  let userDid;
  let testDb;
  let dbPath;

  beforeAll(async () => {
    process.env.PASSWORD = 'compat-pass';
    const dbName = `compat-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);
    testDb = createDb(`file:${dbPath}`);
    setDb(testDb);
    await initDb(testDb);

    const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    const privKey = await keypair.export();
    process.env.PRIVATE_KEY = Buffer.from(privKey).toString('hex');
    process.env.DOMAIN = DOMAIN;
    userDid = formatDid(DOMAIN);
    
    await maybeInitRepo();

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    wss.close();
    sequencer.close();
    testDb.close();
    await new Promise((resolve) => server.close(() => resolve()));
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('PDS should auto-initialize repo and profile with custom metadata', async () => {
    // Clear the DB to simulate first run
    await testDb.execute("DELETE FROM repo_blocks");
    await testDb.execute("DELETE FROM sequencer");
    
    process.env.DISPLAY_NAME = 'Test User';
    process.env.DESCRIPTION = 'Test Bio';

    // Trigger auto-init via maybeInitRepo (called by middleware on first request)
    await maybeInitRepo();

    // Verify profile was created with custom metadata
    const profileRes = await axios.get(`${HOST}/xrpc/app.bsky.actor.getProfile?actor=${userDid}`);
    expect(profileRes.status).toBe(200);
    expect(profileRes.data.displayName).toBe('Test User');
    expect(profileRes.data.description).toBe('Test Bio');
  });

  test('atproto-did should return raw DID with trailing newline', async () => {
    const res = await axios.get(`${HOST}/.well-known/atproto-did`);
    expect(res.status).toBe(200);
    expect(res.data).toBe(userDid + '\n');
    expect(res.headers['content-type']).toContain('text/plain');
  });

  test('did.json should include alsoKnownAs and all verification method types', async () => {
    const res = await axios.get(`${HOST}/.well-known/did.json`);
    expect(res.status).toBe(200);
    expect(res.data.id).toBe(userDid);
    expect(res.data.alsoKnownAs).toContain(`at://${DOMAIN}`);
    
    const verificationMethods = res.data.verificationMethod;
    expect(verificationMethods.some(m => m.type === 'Multikey')).toBe(true);
    
    // Check for correct ID standardization
    expect(verificationMethods.some(m => m.id === '#atproto')).toBe(true);
  });

  test('CORS preflight should allow all required atproto and bsky headers', async () => {
    const requestedHeaders = 'Content-Type, Authorization, atproto-accept-labelers, atproto-proxy-type, atproto-proxy, atproto-proxy-exp, atproto-content-type, x-bsky-topics, x-bsky-active-labelers';
    
    const res = await axios.options(`${HOST}/xrpc/app.bsky.ageassurance.getState`, {
        headers: {
            'Origin': 'https://bsky.app',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': requestedHeaders
        }
    });
    
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://bsky.app');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
    
    const allowedHeaders = res.headers['access-control-allow-headers'].toLowerCase();
    expect(allowedHeaders).toContain('atproto-accept-labelers');
    expect(allowedHeaders).toContain('atproto-proxy');
    expect(allowedHeaders).toContain('x-bsky-topics');
    expect(allowedHeaders).toContain('x-bsky-active-labelers');

    const exposedHeaders = res.headers['access-control-expose-headers'].toLowerCase();
    expect(exposedHeaders).toContain('atproto-proxy');
    expect(exposedHeaders).toContain('x-bsky-active-labelers');
  });

  test('resolveDid should return full DID document', async () => {
    const res = await axios.get(`${HOST}/xrpc/com.atproto.identity.resolveDid?did=${userDid}`);
    expect(res.status).toBe(200);
    expect(res.data.id).toBe(userDid);
    expect(res.data.verificationMethod[0].id).toBe('#atproto');
  });

  test('getAccount should return birthDate', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const res = await axios.get(`${HOST}/xrpc/com.atproto.server.getAccount`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    expect(res.data.birthDate).toBeDefined();
  });

  test('getHead should return current root CID', async () => {
    const res = await axios.get(`${HOST}/xrpc/com.atproto.sync.getHead?did=${userDid}`);
    expect(res.status).toBe(200);
    expect(res.data.root).toBeDefined();
  });

  test('describeRepo should return correct handle and full didDoc', async () => {
    const res = await axios.get(`${HOST}/xrpc/com.atproto.repo.describeRepo?repo=${userDid}`);
    expect(res.status).toBe(200);
    expect(res.data.handle).toBe(DOMAIN === 'localhost' ? 'localhost.test' : DOMAIN);
    expect(res.data.did).toBe(userDid);
    expect(res.data.didDoc.id).toBe(userDid);
    expect(res.data.handleIsCorrect).toBe(true);
  });

  test('getProfile should return a valid profile from the repo', async () => {
    const res = await axios.get(`${HOST}/xrpc/app.bsky.actor.getProfile?actor=${userDid}`);
    expect(res.status).toBe(200);
    expect(res.data.did).toBe(userDid);
    expect(res.data.handle).toBe(DOMAIN === 'localhost' ? 'localhost.test' : DOMAIN);
    expect(res.data.displayName).toBeDefined();
  });

  test('resolveHandle should be flexible', async () => {
    const res = await axios.get(`${HOST}/xrpc/com.atproto.identity.resolveHandle?handle=${DOMAIN === 'localhost' ? 'localhost.test' : DOMAIN}`);
    expect(res.status).toBe(200);
    expect(res.data.did).toBe(userDid);
  });

  test('refreshSession should return a new valid token', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const refreshRes = await axios.post(`${HOST}/xrpc/com.atproto.server.refreshSession`, {}, {
        headers: { Authorization: `Bearer ${token}` }
    });
    expect(refreshRes.status).toBe(200);
    expect(refreshRes.data.accessJwt).toBeDefined();
  });

  test('describeServer should be public and ignore invalid tokens', async () => {
    // No token
    const res1 = await axios.get(`${HOST}/xrpc/com.atproto.server.describeServer`);
    expect(res1.status).toBe(200);

    // Invalid token (should still work as the route is public)
    const res2 = await axios.get(`${HOST}/xrpc/com.atproto.server.describeServer`, {
        headers: { Authorization: `Bearer invalid-token` }
    });
    expect(res2.status).toBe(200);
  });

  test('protected routes should return 401 for missing/invalid tokens', async () => {
    await expect(axios.get(`${HOST}/xrpc/com.atproto.server.getSession`))
        .rejects.toThrow();
    
    await expect(axios.get(`${HOST}/xrpc/com.atproto.server.getSession`, {
        headers: { Authorization: `Bearer invalid` }
    })).rejects.toThrow();
  });

  test('should upload and retrieve blobs', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const blobData = Buffer.from('fake-image-data');
    const uploadRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.uploadBlob`, blobData, {
        headers: { 
            Authorization: `Bearer ${token}`,
            'Content-Type': 'image/png'
        }
    });

    expect(uploadRes.status).toBe(200);
    expect(uploadRes.data.blob.ref.$link).toBeDefined();

    const cid = uploadRes.data.blob.ref.$link;
    const getRes = await axios.get(`${HOST}/xrpc/com.atproto.sync.getBlob?cid=${cid}`, {
        responseType: 'arraybuffer'
    });

    expect(getRes.status).toBe(200);
    expect(Buffer.from(getRes.data)).toEqual(blobData);
    expect(getRes.headers['content-type']).toBe('image/png');
  });

  test('should persist and retrieve birthDate via preferences', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const testBirthDate = '1985-05-05';
    
    // 1. Write birthDate via putPreferences
    await axios.post(`${HOST}/xrpc/app.bsky.actor.putPreferences`, {
        preferences: [
            {
                $type: 'app.bsky.actor.defs#personalDetailsPref',
                birthDate: testBirthDate
            }
        ]
    }, {
        headers: { Authorization: `Bearer ${token}` }
    });

    // 2. Read birthDate via getAccount
    const accountRes = await axios.get(`${HOST}/xrpc/com.atproto.server.getAccount`, {
        headers: { Authorization: `Bearer ${token}` }
    });

    expect(accountRes.status).toBe(200);
    expect(accountRes.data.birthDate).toBe(testBirthDate);

    // 3. Verify getState returns verified
    const stateRes = await axios.get(`${HOST}/xrpc/app.bsky.ageassurance.getState`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    expect(stateRes.data.status).toBe('verified');
  });

  test('commit events should report record CID in ops, not commit CID', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    // 1. Create a record
    const createRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'CID test', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const recordCid = createRes.data.cid;
    const commitCid = createRes.data.commit.cid;

    // The record CID and commit CID must be different
    expect(recordCid).not.toBe(commitCid);

    // 2. Fetch the event from sequencer
    const syncRes = await axios.get(`${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    
    // subscribeRepos returns a binary stream of frames.
    // Each frame is [header_cbor][body_cbor].
    // Our formatEvent implementation: Buffer.concat([header, body])
    const data = Buffer.from(syncRes.data);
    
    // This is a bit of a hacky parse but works for our test
    // Search for the commit cid in the binary blob to find the right event
    // or just look at the last 100 events.
    
    const eventsRes = await testDb.execute("SELECT event FROM sequencer ORDER BY seq DESC LIMIT 1");
    const lastEvent = cborDecode(new Uint8Array(eventsRes.rows[0].event));
    
    expect(lastEvent.repo).toBe(userDid);
    expect(lastEvent.commit.toString()).toBe(commitCid);
    expect(lastEvent.ops[0].cid.toString()).toBe(recordCid);
    expect(lastEvent.ops[0].cid.toString()).not.toBe(commitCid);
  });

  test('should auto-initialize profile with static avatar file', async () => {
    // 1. Create a dummy avatar file
    const avatarContent = Buffer.from('fake-avatar-data');
    fs.writeFileSync('avatar.png', avatarContent);

    try {
        // 2. Reset and re-init
        await testDb.execute("DELETE FROM repo_blocks");
        await testDb.execute("DELETE FROM sequencer");
        await testDb.execute("DELETE FROM blobs");
        await maybeInitRepo();

        // 3. Verify profile has avatar
        const profileRes = await axios.get(`${HOST}/xrpc/app.bsky.actor.getProfile?actor=${userDid}`);
        expect(profileRes.data.avatar).toBeDefined();
        const avatarCid = profileRes.data.avatar.ref.$link;

        // 4. Verify getBlob serves it
        const blobRes = await axios.get(`${HOST}/xrpc/com.atproto.sync.getBlob?cid=${avatarCid}`, {
            responseType: 'arraybuffer'
        });
        expect(blobRes.status).toBe(200);
        expect(Buffer.from(blobRes.data)).toEqual(avatarContent);
        expect(blobRes.headers['content-type']).toBe('image/png');

    } finally {
        if (fs.existsSync('avatar.png')) fs.unlinkSync('avatar.png');
    }
  });

  test('getSuggestedFollowsByActor should return empty suggestions', async () => {
    const res = await axios.get(`${HOST}/xrpc/app.bsky.graph.getSuggestedFollowsByActor?actor=${userDid}`);
    expect(res.status).toBe(200);
    expect(res.data.suggestions).toEqual([]);
  });

  test('getDrafts should return empty drafts', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const res = await axios.get(`${HOST}/xrpc/app.bsky.draft.getDrafts`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    expect(res.data.drafts).toEqual([]);
  });
});
