import 'dotenv/config';
import { jest } from '@jest/globals';
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
import { runFullSetup } from '../src/setup.js';

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
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = 'compat-pass';
    process.env.DOMAIN = 'localhost';
    const dbName = `compat-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);
    testDb = createDb(`file:${dbPath}`);
    setDb(testDb);

    await runFullSetup({ db: testDb, skipPlc: true });
    userDid = formatDid(DOMAIN);

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    for (const client of wss.clients) {
      client.terminate();
    }
    wss.close();
    sequencer.close();
    testDb.close();
    await new Promise((resolve) => server.close(resolve));
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

  test('atproto-did should return raw DID without formatting', async () => {
    const res = await axios.get(`${HOST}/.well-known/atproto-did`);
    expect(res.status).toBe(200);
    expect(res.data).toBe(userDid);
    expect(res.headers['content-type']).toContain('text/plain');
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
    expect(res.data.verificationMethod[0].id).toBe(`${userDid}#atproto`);
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

    // Use a larger buffer to simulate a real image
    const blobData = crypto.randomBytes(1024 * 10); 
    const uploadRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.uploadBlob`, blobData, {
        headers: { 
            Authorization: `Bearer ${token}`,
            'Content-Type': 'image/jpeg'
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
    expect(getRes.headers['content-type']).toBe('image/jpeg');
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

    // 2. Fetch the event from sequencer (commented out as it returns 426 on HTTP)
    // const syncRes = await axios.get(`${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    
    // Check the event directly in the database instead
    const eventsRes = await testDb.execute("SELECT event FROM sequencer ORDER BY seq DESC LIMIT 1");
    const lastEvent = cborDecode(new Uint8Array(eventsRes.rows[0].event));
    
    expect(lastEvent.repo).toBe(userDid);
    expect(lastEvent.commit.toString()).toBe(commitCid);
    expect(lastEvent.ops[0].cid.toString()).toBe(recordCid);
    expect(lastEvent.ops[0].cid.toString()).not.toBe(commitCid);
  });

  test.todo('Verify avatar handling without static fallback');

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

  test('applyWrites should handle bulk operations and sequence events', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    // Create multiple records in one batch
    const applyRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.applyWrites`, {
      repo: userDid,
      writes: [
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: { $type: 'app.bsky.feed.post', text: 'Apply 1', createdAt: new Date().toISOString() }
        },
        {
          $type: 'com.atproto.repo.applyWrites#create',
          collection: 'app.bsky.feed.post',
          value: { $type: 'app.bsky.feed.post', text: 'Apply 2', createdAt: new Date().toISOString() }
        }
      ]
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    expect(applyRes.status).toBe(200);
    expect(applyRes.data.commit.cid).toBeDefined();

    // Verify sequencer recorded both operations
    const eventsRes = await testDb.execute("SELECT event FROM sequencer ORDER BY seq DESC LIMIT 1");
    const lastEvent = cborDecode(new Uint8Array(eventsRes.rows[0].event));
    expect(lastEvent.ops.length).toBe(2);
    expect(lastEvent.ops[0].action).toBe('create');
    expect(lastEvent.ops[1].action).toBe('create');
  });

  test('getPostThreadV2 should return post data via anchor', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    // 1. Create a post
    const createRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Thread test', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const uri = createRes.data.uri;

    // 2. Fetch via getPostThreadV2
    const res = await axios.get(`${HOST}/xrpc/app.bsky.unspecced.getPostThreadV2?anchor=${encodeURIComponent(uri)}`);
    expect(res.status).toBe(200);
    // V2 thread is a list of items
    const rootItem = res.data.thread.find(item => item.uri === uri);
    expect(rootItem.value.post.uri).toBe(uri);
  });

  test('getTimeline should return a valid feed', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const res = await axios.get(`${HOST}/xrpc/app.bsky.feed.getTimeline`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.data.feed)).toBe(true);
  });

  test('getFeed should return empty feed', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    const res = await axios.get(`${HOST}/xrpc/app.bsky.feed.getFeed?feed=at://did:plc:abc/app.bsky.feed.generator/test`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    expect(res.data.feed).toEqual([]);
  });

  test('getPostThreadV2 should resolve handle-based URIs', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
        identifier: 'localhost.test',
        password: 'compat-pass'
    });
    const token = loginRes.data.accessJwt;

    // 1. Create a post
    const createRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Handle URI test', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const uri = createRes.data.uri;
    const handleUri = uri.replace(userDid, 'localhost.test');

    // 2. Fetch via getPostThreadV2 using handle
    const res = await axios.get(`${HOST}/xrpc/app.bsky.unspecced.getPostThreadV2?anchor=${encodeURIComponent(handleUri)}`);
    expect(res.status).toBe(200);
    const rootItem = res.data.thread.find(item => item.uri.includes(userDid));
    expect(rootItem.value.post.record.text).toBe('Handle URI test');
  });

  test('listRepos should return the local user repo', async () => {
    const res = await axios.get(`${HOST}/xrpc/com.atproto.sync.listRepos`);
    expect(res.status).toBe(200);
    expect(res.data.repos[0].did).toBe(userDid);
    expect(res.data.repos[0].head).toBeDefined();
  });
});
