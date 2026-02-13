import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server';
import { initDb, createDb, setDb } from '../src/db';
import { sequencer } from '../src/sequencer';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from '../src/repo';
import { readCarWithRoot } from '@atproto/repo';
import { Client } from '@libsql/client';

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

    userDid = `did:web:localhost%3A${PORT}`;
    const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    const privKey = await keypair.export();
    const storage = new TursoStorage();
    const repo = await loadRepo(storage, userDid, keypair, null);
    
    await testDb.execute({
      sql: 'INSERT OR REPLACE INTO account (handle, password, did, signing_key, root_cid) VALUES (?, ?, ?, ?, ?)',
      args: ['interop-unique.test', 'pass', userDid, privKey, repo.cid.toString()]
    });

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
    expect(res.data.service[0].type).toBe('AtprotoPersonalDataServer');
    expect(res.data.verificationMethod[0].publicKeyMultibase).toBeDefined();
  });

  test('should serve a valid CAR file via getRepo', async () => {
    // 1. Create a record first
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
      identifier: 'interop-unique.test',
      password: 'pass'
    });
    const token = loginRes.data.accessJwt;

    await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { text: 'Interop test post', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    // 2. Fetch the repo CAR file
    const repoRes = await axios.get(`${HOST}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(userDid)}`, {
      responseType: 'arraybuffer'
    });
    expect(repoRes.status).toBe(200);
    expect(repoRes.headers['content-type']).toBe('application/vnd.ipld.car');

    // 3. Verify CAR content
    const carData = new Uint8Array(repoRes.data);
    const { root, blocks } = await readCarWithRoot(carData);
    
    expect(root).toBeDefined();
    expect(blocks.size).toBeGreaterThan(0);
    
    // The root CID should match what we have in the DB
    const dbRes = await testDb.execute({
      sql: 'SELECT root_cid FROM account WHERE did = ?',
      args: [userDid]
    });
    expect(root.toString()).toBe(dbRes.rows[0].root_cid);
  });
});
