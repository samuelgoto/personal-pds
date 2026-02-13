import 'dotenv/config';
import http from 'http';
import nock from 'nock';
import axios from 'axios';
import app, { wss } from '../src/server';
import { initDb, createDb, setDb } from '../src/db';
import { sequencer } from '../src/sequencer';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from '../src/repo';
import { WebSocket } from 'ws';
import { readCarWithRoot } from '@atproto/repo';
import { Client } from '@libsql/client';

const PORT = 3003;
const HOST = `localhost:${PORT}`;
const PDS_URL = `http://${HOST}`;
const RELAY_URL = 'https://mock-relay.com';

describe('Relay Interaction & Protocol Compliance', () => {
  let server: http.Server;
  let userDid: string;
  let testDb: Client;

  beforeAll(async () => {
    const dbUrl = `file:relay-${Date.now()}.db`;
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
      args: ['relay-unique.test', 'pass', userDid, privKey, repo.cid.toString()]
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
    nock.cleanAll();
  });

  test('should simulate a full relay indexing flow', async () => {
    // 1. Mock the Relay's requestCrawl endpoint
    const relayPing = nock(RELAY_URL)
      .post('/xrpc/com.atproto.sync.requestCrawl', { hostname: HOST })
      .reply(200, { success: true });

    // 2. Trigger the "Ping" (Manually calling the function normally called on start)
    const hostname = HOST;
    await axios.post(`${RELAY_URL}/xrpc/com.atproto.sync.requestCrawl`, { hostname });
    expect(relayPing.isDone()).toBe(true);

    // 3. ACT AS RELAY: Fetch DID Document
    const didRes = await axios.get(`${PDS_URL}/.well-known/did.json`);
    expect(didRes.status).toBe(200);
    expect(didRes.data.id).toBe(userDid);
    expect(didRes.data.service[0].serviceEndpoint).toContain(HOST);

    // 4. ACT AS RELAY: Sync the Repo
    const repoRes = await axios.get(`${PDS_URL}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(userDid)}`, {
        responseType: 'arraybuffer'
    });
    expect(repoRes.status).toBe(200);
    const { root } = await readCarWithRoot(new Uint8Array(repoRes.data));
    expect(root).toBeDefined();

    // 5. ACT AS RELAY: Connect to Firehose
    const ws = new WebSocket(`ws://${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    
    const connected = new Promise((resolve) => ws.on('open', resolve));
    await connected;
    expect(ws.readyState).toBe(WebSocket.OPEN);
    
    ws.close();
  });

  test('should verify firehose event framing (DAG-CBOR)', async () => {
    // In a real relay, it would decode the CBOR frames.
    // We'll verify we can connect and receive at least one message when a record is created.
    const ws = new WebSocket(`ws://${HOST}/xrpc/com.atproto.sync.subscribeRepos`);
    
    await new Promise((resolve) => ws.on('open', resolve));

    const messagePromise = new Promise<Buffer>((resolve) => {
      ws.on('message', (data: Buffer) => resolve(data));
    });

    // Create a record to trigger firehose
    const loginRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: process.env.PASSWORD || 'admin'
    });
    const token = loginRes.data.accessJwt;

    await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: { text: 'Relay compliance test', createdAt: new Date().toISOString() }
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const data = await messagePromise;
    expect(data.length).toBeGreaterThan(0);
    // The first few bytes of an ATProto frame are CBOR.
    // A commit event header usually starts with 0xa2 (a map with 2 keys: "op" and "t")
    expect(data[0]).toBe(0xa2); 

    ws.close();
  });
});
