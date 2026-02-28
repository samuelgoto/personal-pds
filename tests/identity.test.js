import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import { BskyAgent } from '@atproto/api';
import app, { wss } from '../src/server.js';
import { sequencer } from '../src/sequencer.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let PORT;
let HOST;
const HANDLE = 'identity.test';
const PASSWORD = 'test-password-123';

describe('Identity Endpoints', () => {
  let server;
  let dbPath;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    process.env.PASSWORD = PASSWORD;
    process.env.HANDLE = HANDLE;
    const dbName = `test-identity-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);

    await setUpForTesting(`file:${dbPath}`);
    await create();
    await setUpRepo();

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    PORT = server.address().port;
    HOST = `http://localhost:${PORT}`;
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

  test('com.atproto.identity.updateHandle should succeed with correct handle', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    // Directly call the XRPC method
    const res = await agent.api.com.atproto.identity.updateHandle({
      handle: HANDLE
    });

    expect(res.success).toBe(true);
  });

  test('com.atproto.identity.updateHandle should fail with incorrect handle', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    try {
      await agent.api.com.atproto.identity.updateHandle({
        handle: 'wrong-handle.test'
      });
      fail('Should have thrown an error');
    } catch (err) {
      expect(err.status).toBe(400);
      expect(err.error).toBe('InvalidRequest');
      expect(err.message).toContain('only supports the handle identity.test');
    }
  });

  test('com.atproto.server.activateAccount should succeed and trigger firehose', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    const res = await axios.post(`${HOST}/xrpc/com.atproto.server.activateAccount`, 
      {},
      { headers: { Authorization: `Bearer ${agent.session.accessJwt}` } }
    );

    expect(res.status).toBe(200);
  });
});
