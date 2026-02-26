import 'dotenv/config';
import { jest } from '@jest/globals';
import { db, setUpForTesting, create, disconnect, destroy } from '../src/db.js';
import { setUpRepo, getRootCid } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import * as cbor from '@ipld/dag-cbor';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('PDS Bootstrapping', () => {
  let dbPath;

  beforeEach(async () => {
    // Create a unique database for each test to ensure a truly "empty" state
    const dbName = `bootstrap-${Date.now()}-${Math.floor(Math.random() * 1000)}.db`;
    dbPath = path.join(__dirname, dbName);
    
    // Ensure the file doesn't exist
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  });

  afterEach(async () => {
    await disconnect();
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('should initialize a valid empty repository on a fresh database', async () => {
    // 1. Initial State: No database, no repo
    expect(fs.existsSync(dbPath)).toBe(false);

    // 2. Connect (creates tables)
    await setUpForTesting(`file:${dbPath}`); await create();
    
    // Verify tables exist
    const tables = await db.execute("SELECT name FROM sqlite_master WHERE type='table'");
    const tableNames = tables.rows.map(r => r.name);
    expect(tableNames).toContain('repo_blocks');
    expect(tableNames).toContain('sequencer');

    // 3. Verify repo is initially empty
    const initialRoot = await getRootCid();
    expect(initialRoot).toBeNull();

    // 4. Initialize Repo
    await setUpRepo();

    // 5. Verify Bootstrapping Results
    const newRoot = await getRootCid();
    expect(newRoot).not.toBeNull();
    expect(typeof newRoot).toBe('string');
    expect(newRoot.startsWith('bafy')).toBe(true); // Valid CIDv1

    // 6. Inspect the Sequencer Event
    const res = await db.execute("SELECT * FROM sequencer WHERE seq = 1");
    expect(res.rows.length).toBe(1);
    
    const event = cbor.decode(new Uint8Array(res.rows[0].event));
    expect(event.type).toBe('commit');
    expect(event.repo).toBe(process.env.PDS_DID);
    expect(event.ops).toEqual([]); // Should be a truly empty genesis commit
    expect(event.since).toBeNull();
  });

  test('should not re-initialize if a repository already exists', async () => {
    await setUpForTesting(`file:${dbPath}`); await create();
    await setUpRepo();
    
    const firstRoot = await getRootCid();
    const firstEventCount = (await db.execute("SELECT count(*) as count FROM sequencer")).rows[0].count;

    // Call it again
    await setUpRepo();

    const secondRoot = await getRootCid();
    const secondEventCount = (await db.execute("SELECT count(*) as count FROM sequencer")).rows[0].count;

    expect(secondRoot).toBe(firstRoot);
    expect(secondEventCount).toBe(firstEventCount);
  });

  test('should clear all data on destroy', async () => {
    await setUpForTesting(`file:${dbPath}`); await create();
    await setUpRepo();
    
    // Verify data exists
    const beforeCount = (await db.execute("SELECT count(*) as count FROM sequencer")).rows[0].count;
    expect(beforeCount).toBeGreaterThan(0);

    // Wipe
    await destroy();

    // Verify empty
    const afterCount = (await db.execute("SELECT count(*) as count FROM sequencer")).rows[0].count;
    expect(afterCount).toBe(0);
    const blockCount = (await db.execute("SELECT count(*) as count FROM repo_blocks")).rows[0].count;
    expect(blockCount).toBe(0);
  });
});
