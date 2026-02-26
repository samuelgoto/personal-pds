import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app from '../src/server.js';
import { db, setUpForTesting, create, disconnect } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3011;
const HOST = `http://localhost:${PORT}`;
const PASSWORD = 'admin-test-password';

describe('Admin Interface', () => {
  let server;
  let dbPath;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    process.env.PASSWORD = PASSWORD;
    process.env.HANDLE = 'admin.test';
    const dbName = `admin-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);

    await setUpForTesting(`file:${dbPath}`);
    await create();
    await setUpRepo();

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    await disconnect();
    await new Promise((resolve) => server.close(resolve));
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('should serve the admin dashboard', async () => {
    const res = await axios.get(HOST);
    expect(res.status).toBe(200);
    expect(res.data).toContain('Personal PDS Dashboard');
    expect(res.data).toContain('admin.test');
  });

  test('should fail to wipe data with incorrect password', async () => {
    try {
      await axios.post(`${HOST}/debug/reset`, { password: 'wrong-password' });
      fail('Should have thrown 403');
    } catch (err) {
      expect(err.response.status).toBe(403);
      expect(err.response.data).toContain('Incorrect password');
    }
  });

  test('should wipe all data and re-initialize with correct password', async () => {
    // 1. Add some dummy data first
    await db.execute({
      sql: "INSERT INTO preferences (key, value) VALUES (?, ?)",
      args: ['test-key', 'test-value']
    });

    // 2. Perform wipe
    const res = await axios.post(`${HOST}/debug/reset`, { password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.data).toContain('wiped clean and re-initialized');

    // 3. Verify preferences are gone
    const prefRes = await db.execute("SELECT count(*) as count FROM preferences");
    expect(prefRes.rows[0].count).toBe(0);

    // 4. Verify repo is re-initialized (should have 1 event in sequencer)
    const seqRes = await db.execute("SELECT count(*) as count FROM sequencer");
    expect(seqRes.rows[0].count).toBe(1);
  });
});
