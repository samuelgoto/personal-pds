import 'dotenv/config';
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
    process.env.PASSWORD = 'relay-pass';
    process.env.DOMAIN = HOST;
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
    wss.close();
    sequencer.close();
    testDb.close();
    await new Promise((resolve) => server.close(() => resolve()));
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
});
