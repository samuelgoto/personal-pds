import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import { BskyAgent } from '@atproto/api';
import app, { wss } from '../src/server.js';
import { sequencer } from '../src/sequencer.js';
import * as crypto from '@atproto/crypto';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { WebSocket } from 'ws';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3001;
const HOST = `http://localhost:${PORT}`;
const WS_HOST = `ws://localhost:${PORT}`;
const HANDLE = 'localhost.test';
const PASSWORD = 'test-password-123';

describe('PDS Local Tests', () => {
  let server;
  let testDb;
  let dbPath;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = PASSWORD;
    process.env.HANDLE = 'localhost.test';
    const dbName = `test-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);

    await setUpForTesting(`file:${dbPath}`); await create(); await setUpRepo();

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
    db.close();
    await new Promise((resolve) => server.close(resolve));
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('should create a session', async () => {
    const agent = new BskyAgent({ service: HOST });
    const login = await agent.login({ identifier: HANDLE, password: PASSWORD });
    expect(login.success).toBe(true);
    expect(agent.session?.handle).toBe(HANDLE);
  });

  test('should serve the dashboard at /', async () => {
    const res = await axios.get(HOST);
    expect(res.status).toBe(200);
    expect(res.data).toContain('Personal PDS Dashboard');
  });

  test('should create a record and see it on firehose', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    const ws = new WebSocket(`${WS_HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    await new Promise((resolve, reject) => { ws.on('open', resolve); ws.on('error', reject); });

    const messagePromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timeout')), 5000);
      ws.on('message', (data) => { clearTimeout(timeout); resolve(data); });
    });

    await agent.api.com.atproto.repo.createRecord({
      repo: agent.session?.did,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Firehose test!', createdAt: new Date().toISOString() },
    });

    const data = await messagePromise;
    expect(data).toBeDefined();
    ws.close();
  }, 15000);

  test('should delete a record', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    const createRes = await agent.api.com.atproto.repo.createRecord({
      repo: agent.session?.did,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'To be deleted', createdAt: new Date().toISOString() },
    });
    const rkey = createRes.data.uri.split('/').pop();

    const deleteRes = await agent.api.com.atproto.repo.deleteRecord({
      repo: agent.session?.did,
      collection: 'app.bsky.feed.post',
      rkey: rkey,
    });
    expect(deleteRes.success).toBe(true);

    await expect(agent.api.com.atproto.repo.getRecord({
      repo: agent.session?.did,
      collection: 'app.bsky.feed.post',
      rkey: rkey,
    })).rejects.toThrow();
  });

  test('should describe server', async () => {
    const agent = new BskyAgent({ service: HOST });
    const res = await agent.api.com.atproto.server.describeServer();
    expect(res.success).toBe(true);
    expect(res.data.did).toBeDefined();
  });

  test('should list records', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    await agent.api.com.atproto.repo.createRecord({
        repo: agent.session?.did,
        collection: 'app.bsky.feed.post',
        record: { $type: 'app.bsky.feed.post', text: 'List test', createdAt: new Date().toISOString() },
    });

    const res = await agent.api.com.atproto.repo.listRecords({
      repo: agent.session?.did,
      collection: 'app.bsky.feed.post',
    });

    expect(res.success).toBe(true);
    expect(res.data.records.length).toBeGreaterThan(0);
  });
});
