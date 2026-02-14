import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { initDb, createDb, setDb } from '../src/db.js';
import { sequencer } from '../src/sequencer.js';
import * as crypto from '@atproto/crypto';
import { maybeInitRepo } from '../src/repo.js';
import { formatDid } from '../src/util.js';
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
});
