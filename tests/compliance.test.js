import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { createDb, setDb } from '../src/db.js';
import { sequencer } from '../src/sequencer.js';
import { formatDid } from '../src/util.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { runFullSetup } from '../src/setup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3004;
const HOST = `localhost:${PORT}`;
const PDS_URL = `http://${HOST}`;

describe('ATProto XRPC Lexicon Compliance', () => {
  let server;
  let userDid;
  let testDb;
  let dbPath;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = 'compliance-pass';
    process.env.DOMAIN = HOST;
    const dbName = `compliance-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);
    testDb = createDb(`file:${dbPath}`);
    setDb(testDb);

    await runFullSetup({ db: testDb, skipPlc: true });
    userDid = formatDid(`localhost`);

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    sequencer.close();
    testDb.close();
    await new Promise((resolve) => server.close(resolve));
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('com.atproto.server.describeServer compliance', async () => {
    const res = await axios.get(`${PDS_URL}/xrpc/com.atproto.server.describeServer`);
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('did');
    expect(res.data).toHaveProperty('availableUserDomains');
    expect(Array.isArray(res.data.availableUserDomains)).toBe(true);
  });

  test('com.atproto.server.getServiceContext compliance', async () => {
    const res = await axios.get(`${PDS_URL}/xrpc/com.atproto.server.getServiceContext`);
    // Nuance: This is a newer endpoint, lexicons might vary but common fields are expected
    expect(res.status).toBe(200);
  });

  test('com.atproto.identity.resolveHandle compliance', async () => {
    const res = await axios.get(`${PDS_URL}/xrpc/com.atproto.identity.resolveHandle`, {
      params: { handle: 'localhost.test' }
    });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('did', userDid);
  });

  test('com.atproto.server.createSession compliance', async () => {
    const res = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: 'compliance-pass'
    });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('accessJwt');
    expect(res.data).toHaveProperty('refreshJwt');
    expect(res.data).toHaveProperty('handle', 'localhost.test');
    expect(res.data).toHaveProperty('did', userDid);
  });

  test('com.atproto.server.getAccount compliance', async () => {
    const login = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: 'compliance-pass'
    });
    const token = login.data.accessJwt;

    const res = await axios.get(`${PDS_URL}/xrpc/com.atproto.server.getAccount`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('handle', 'localhost.test');
    expect(res.data).toHaveProperty('did', userDid);
    expect(res.data).toHaveProperty('email');
  });

  test('com.atproto.server.checkAccountStatus compliance', async () => {
    const res = await axios.get(`${PDS_URL}/xrpc/com.atproto.server.checkAccountStatus`);
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('activated', true);
    expect(res.data).toHaveProperty('validEmail', true);
  });

  // Example of a TODO test for non-compliant or missing features
  test.todo('com.atproto.server.requestAccountDelete compliance');
  test.todo('com.atproto.server.requestPasswordReset compliance');
  
  test('com.atproto.repo.getRecord compliance', async () => {
    // First create a record
    const login = await axios.post(`${PDS_URL}/xrpc/com.atproto.server.createSession`, {
      identifier: 'localhost.test',
      password: 'compliance-pass'
    });
    const token = login.data.accessJwt;

    const post = {
      $type: 'app.bsky.feed.post',
      text: 'compliance test post',
      createdAt: new Date().toISOString()
    };

    const createRes = await axios.post(`${PDS_URL}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: post
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const rkey = createRes.data.uri.split('/').pop();

    const res = await axios.get(`${PDS_URL}/xrpc/com.atproto.repo.getRecord`, {
      params: {
        repo: userDid,
        collection: 'app.bsky.feed.post',
        rkey: rkey
      }
    });

    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('uri');
    expect(res.data).toHaveProperty('cid');
    expect(res.data).toHaveProperty('value');
    expect(res.data.value.text).toBe(post.text);
  });

  test.skip('com.atproto.repo.listRecords pagination compliance', async () => {
    // Skip this for now as we might not have full pagination implemented correctly per spec
  });
});
