import 'dotenv/config';
import http from 'http';
import { BskyAgent } from '@atproto/api';
import app, { wss } from '../src/server';
import { initDb, createDb, setDb } from '../src/db';
import { sequencer } from '../src/sequencer';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from '../src/repo';
import { WebSocket } from 'ws';
import { Client } from '@libsql/client';

const PORT = 3001;
const HOST = `http://localhost:${PORT}`;
const WS_HOST = `ws://localhost:${PORT}`;
const HANDLE = 'test.test';
const PASSWORD = 'password';

describe('PDS Local Tests', () => {
  let server: http.Server;
  let testDb: Client;

  beforeAll(async () => {
    const dbUrl = `file:test-${Date.now()}.db`;
    testDb = createDb(dbUrl);
    setDb(testDb);
    await initDb(testDb);

    const did = `did:web:localhost%3A${PORT}`;
    const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    const privKey = await keypair.export();
    const storage = new TursoStorage();
    const repo = await loadRepo(storage, did, keypair, null);
    
    await testDb.execute({
      sql: 'INSERT OR REPLACE INTO account (handle, password, did, signing_key, root_cid) VALUES (?, ?, ?, ?, ?)',
      args: [HANDLE, PASSWORD, did, privKey, repo.cid.toString()]
    });

    server = http.createServer(app);
    server.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });
    await new Promise<void>((resolve) => {
        server.listen(PORT, resolve);
    });
  });

  afterAll(async () => {
    wss.close();
    sequencer.close();
    testDb.close();
    await new Promise<void>((resolve) => {
        server.close(() => resolve());
    });
  });

  test('should create a session', async () => {
    const agent = new BskyAgent({ service: HOST });
    const login = await agent.login({ identifier: HANDLE, password: PASSWORD });
    expect(login.success).toBe(true);
    expect(agent.session?.handle).toBe(HANDLE);
  });

  test('should create a record and see it on firehose', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    const ws = new WebSocket(`${WS_HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
    });

    const messagePromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timeout waiting for firehose')), 5000);
      ws.on('message', (data) => {
        clearTimeout(timeout);
        resolve(data);
      });
      ws.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });

    const record = {
      $type: 'app.bsky.feed.post',
      text: 'Firehose test!',
      createdAt: new Date().toISOString(),
    };

    await agent.api.com.atproto.repo.createRecord({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
      record,
    });

    const data = await messagePromise;
    expect(data).toBeDefined();
    ws.close();
  }, 15000);

  test('should delete a record', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    // 1. Create
    const createRes = await agent.api.com.atproto.repo.createRecord({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
      record: { text: 'To be deleted', createdAt: new Date().toISOString() },
    });
    const rkey = createRes.data.uri.split('/').pop()!;

    // 2. Delete
    const deleteRes = await agent.api.com.atproto.repo.deleteRecord({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
      rkey: rkey,
    });
    expect(deleteRes.success).toBe(true);

    // 3. Verify
    await expect(agent.api.com.atproto.repo.getRecord({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
      rkey: rkey,
    })).rejects.toThrow();
  });

  test('should describe server', async () => {
    const agent = new BskyAgent({ service: HOST });
    const res = await agent.api.com.atproto.server.describeServer();
    expect(res.success).toBe(true);
    expect(res.data.availableUserDomains).toBeDefined();
  });

  test('should list records', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    // Ensure at least one record exists
    await agent.api.com.atproto.repo.createRecord({
        repo: agent.session?.did!,
        collection: 'app.bsky.feed.post',
        record: { text: 'List test', createdAt: new Date().toISOString() },
    });

    const res = await agent.api.com.atproto.repo.listRecords({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
    });

    expect(res.success).toBe(true);
    expect(res.data.records.length).toBeGreaterThan(0);
  });
});
