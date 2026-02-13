import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server';
import { initDb, createDb, setDb } from '../src/db';
import { sequencer } from '../src/sequencer';
import * as crypto from '@atproto/crypto';
import { maybeInitRepo } from '../src/repo';
import { readCarWithRoot } from '@atproto/repo';
import { Client } from '@libsql/client';
import { formatDid } from '../src/util';

const PORT = 3002;
const HOST = `http://localhost:${PORT}`;

describe('PDS Interoperability Tests', () => {
  let server: http.Server;
  let userDid: string;
  let testDb: Client;

  beforeAll(async () => {
    const dbUrl = `file:interop-${Date.now()}.db`;
    testDb = createDb(dbUrl);
    setDb(testDb);
    await initDb(testDb);

    const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    const privKey = await keypair.export();
    process.env.PRIVATE_KEY = Buffer.from(privKey).toString('hex');
    process.env.DOMAIN = `localhost:${PORT}`;
    userDid = formatDid(`localhost:${PORT}`);
    
    await maybeInitRepo();

    server = http.createServer(app);
    server.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });
    await new Promise<void>((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    wss.close();
    sequencer.close();
    testDb.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test('should serve a valid DID document at /.well-known/did.json', async () => {
    const res = await axios.get(`${HOST}/.well-known/did.json`);
    expect(res.status).toBe(200);
    expect(res.data.id).toBe(userDid);
  });

  test('should serve a valid CAR file via getRepo', async () => {
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD || 'admin'
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
