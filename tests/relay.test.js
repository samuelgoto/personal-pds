import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import nock from 'nock';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { initDb, createDb, setDb } from '../src/db.js';
import { sequencer } from '../src/sequencer.js';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo, maybeInitRepo } from '../src/repo.js';
import { WebSocket } from 'ws';
import { readCarWithRoot } from '@atproto/repo';
import { formatDid } from '../src/util.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { runFullSetup } from '../src/setup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3003;
const HOST = `localhost:${PORT}`;
const PDS_URL = `http://${HOST}`;
const RELAY_URL = 'https://mock-relay.com';

describe('Relay Interaction & Protocol Compliance', () => {
  let server;
  let userDid;
  let testDb;
  let dbPath;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    // jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = 'relay-pass';
    process.env.HANDLE = 'localhost.test';
    const dbName = `relay-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);
    testDb = createDb(`file:${dbPath}`);
    setDb(testDb);

    await runFullSetup({ db: testDb, skipPlc: true });
    userDid = formatDid(`localhost`); // Server strips port

    server = http.createServer(app);
    server.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });
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
    nock.cleanAll();
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('should simulate a full relay indexing flow', async () => {
    nock(RELAY_URL)
      .post('/xrpc/com.atproto.sync.requestCrawl', { hostname: HOST })
      .reply(200, { success: true });

    await axios.post(`${RELAY_URL}/xrpc/com.atproto.sync.requestCrawl`, { hostname: HOST });

    const repoRes = await axios.get(`${PDS_URL}/xrpc/com.atproto.sync.getRepo?did=${userDid}`, {
      responseType: 'arraybuffer'
    });
    expect(repoRes.status).toBe(200);
    const { root } = await readCarWithRoot(new Uint8Array(repoRes.data));
    expect(root).toBeDefined();
  });

  test('should verify firehose event framing (DAG-CBOR)', async () => {
    const ws = new WebSocket(`ws://${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    await new Promise((resolve) => ws.on('open', resolve));

    const messagePromise = new Promise((resolve) => {
      ws.on('message', (data) => resolve(data));
    });

    const loginRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD
    });
    const token = loginRes.data.accessJwt;

    await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Relay compliance test', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const data = await messagePromise;
    expect(data.length).toBeGreaterThan(0);
    expect(data[0]).toBe(0xa2); 
    ws.close();
  });

  test('should verify firehose event sequence and structure', async () => {
    const ws = new WebSocket(`ws://${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    await new Promise((resolve) => ws.on('open', resolve));

    const events = [];
    ws.on('message', (data) => {
      events.push(data);
    });

    const loginRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD
    });
    const token = loginRes.data.accessJwt;

    // Create 2 records to trigger 2 events
    await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Event 1', createdAt: new Date().toISOString() }
    }, { headers: { Authorization: `Bearer ${token}` } });

    await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Event 2', createdAt: new Date().toISOString() }
    }, { headers: { Authorization: `Bearer ${token}` } });

    // Wait for events
    await new Promise(resolve => setTimeout(resolve, 500));
    
    expect(events.length).toBeGreaterThanOrEqual(2);
    
    // Minimal validation of the second event (the latest commit)
    const lastEvent = events[events.length - 1];
    expect(lastEvent[0]).toBe(0xa2); // CBOR map
    
    ws.close();
  });

  test('should verify like creation and firehose broadcast', async () => {
    const ws = new WebSocket(`ws://${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    await new Promise((resolve) => ws.on('open', resolve));

    const events = [];
    ws.on('message', (data) => {
      events.push(data);
    });

    const loginRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD
    });
    const token = loginRes.data.accessJwt;

    // 1. Create a post to like
    const postRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Post to like', createdAt: new Date().toISOString() }
    }, { headers: { Authorization: `Bearer ${token}` } });
    
    const postUri = postRes.data.uri;
    const postCid = postRes.data.cid;

    // 2. Create a like
    const likeRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.like',
      record: { 
        $type: 'app.bsky.feed.like', 
        subject: { uri: postUri, cid: postCid },
        createdAt: new Date().toISOString() 
      }
    }, { headers: { Authorization: `Bearer ${token}` } });

    expect(likeRes.status).toBe(200);

    // 2.5 Verify blocks exist in database
    const dbBlocks = await testDb.execute('SELECT count(*) as count FROM repo_blocks');
    expect(dbBlocks.rows[0].count).toBeGreaterThan(1); // Should have more than just the initial repo blocks

    // 3. Wait for firehose events
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // We expect at least 3 events: identity/profile (from setup), post, and like
    expect(events.length).toBeGreaterThanOrEqual(3);
    
    ws.close();
  });

  test.todo('Verify subscribeRepos "since" parameter compliance');
  test.todo('Verify com.atproto.sync.getRepo pagination and CAR structure compliance');
});
