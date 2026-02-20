import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { initDb, createDb, setDb } from '../src/db.js';
import { sequencer } from '../src/sequencer.js';
import * as crypto from '@atproto/crypto';
import { maybeInitRepo } from '../src/repo.js';
import { readCarWithRoot } from '@atproto/repo';
import { formatDid } from '../src/util.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { runFullSetup } from '../src/setup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3002;
const HOST = `http://localhost:${PORT}`;

describe('PDS Interoperability Tests', () => {
  let server;
  let userDid;
  let testDb;
  let dbPath;

  beforeAll(async () => {
    process.env.PASSWORD = 'interop-pass';
    process.env.DOMAIN = `localhost:${PORT}`;
    const dbName = `interop-${Date.now()}.db`;
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
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('should serve a valid CAR file via getRepo', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD
    });
    const token = loginRes.data.accessJwt;

    await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { $type: 'app.bsky.feed.post', text: 'Interop test post', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const repoRes = await axios.get(`${HOST}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(userDid)}`, {
      responseType: 'arraybuffer'
    });
    expect(repoRes.status).toBe(200);

    const { root } = await readCarWithRoot(new Uint8Array(repoRes.data));
    expect(root).toBeDefined();
  });
});
