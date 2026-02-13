import 'dotenv/config';
import axios from 'axios';
import { BskyAgent } from '@atproto/api';
import app from '../src/server';
import { initDb, db } from '../src/db';
import * as crypto from '@atproto/crypto';
import { TursoStorage, loadRepo } from '../src/repo';
import { Server } from 'http';

const PORT = 3001;
const HOST = `http://localhost:${PORT}`;
const HANDLE = 'test.test';
const PASSWORD = 'password';

describe('PDS Local Tests', () => {
  let server: Server;

  beforeAll(async () => {
    // Override DB to use a unique in-memory DB for this test run
    process.env.DATABASE_URL = `file:test-${Date.now()}.db`;
    await initDb();

    // Setup user
    const did = `did:web:localhost%3A${PORT}`;
    const keypair = await crypto.Secp256k1Keypair.create({ exportable: true });
    const privKey = await keypair.export();
    const storage = new TursoStorage();
    const repo = await loadRepo(storage, did, keypair, null);
    
    await db.execute({
      sql: 'INSERT OR REPLACE INTO account (handle, password, did, signing_key, root_cid) VALUES (?, ?, ?, ?, ?)',
      args: [HANDLE, PASSWORD, did, privKey, repo.cid.toString()]
    });

    server = app.listen(PORT);
  });

  afterAll(() => {
    server.close();
  });

  test('should create a session', async () => {
    const agent = new BskyAgent({ service: HOST });
    const login = await agent.login({ identifier: HANDLE, password: PASSWORD });
    expect(login.success).toBe(true);
    expect(agent.session?.handle).toBe(HANDLE);
  });

  test('should create and get a record', async () => {
    const agent = new BskyAgent({ service: HOST });
    await agent.login({ identifier: HANDLE, password: PASSWORD });

    const record = {
      $type: 'app.bsky.feed.post',
      text: 'Hello from my minimal PDS!',
      createdAt: new Date().toISOString(),
    };

    const res = await agent.api.com.atproto.repo.createRecord({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
      record,
    });

    expect(res.success).toBe(true);
    expect(res.data.uri).toBeDefined();

    const getRes = await agent.api.com.atproto.repo.getRecord({
      repo: agent.session?.did!,
      collection: 'app.bsky.feed.post',
      rkey: res.data.uri.split('/').pop()!,
    });

    expect(getRes.success).toBe(true);
    expect(getRes.data.value).toMatchObject(record);
  });
});
