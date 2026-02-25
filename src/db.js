import { createClient } from '@libsql/client';

export let db;

export function setDb(client) {
  db = client;
}

export const createDb = (url, authToken) => {
  return createClient({ url, authToken });
};

export async function initDb(client) {
  // Transparent migration: rename system_state to preferences if it exists
  try {
    const check = await client.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_state'");
    if (check.rows.length > 0) {
      console.log('Migrating system_state table to preferences...');
      await client.execute("ALTER TABLE system_state RENAME TO preferences");
    }
  } catch (e) {
    // Ignore errors (e.g. table already renamed or doesn't exist)
  }

  await client.batch([
    `CREATE TABLE IF NOT EXISTS repo_blocks (
      cid TEXT PRIMARY KEY,
      block BLOB NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS blobs (
      cid TEXT PRIMARY KEY,
      did TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      content BLOB NOT NULL,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      handle TEXT NOT NULL,
      did TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS sequencer (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      did TEXT NOT NULL,
      type TEXT NOT NULL,
      event BLOB NOT NULL,
      time TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS preferences (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      did TEXT NOT NULL,
      dpop_jwk TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
      token TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      did TEXT NOT NULL,
      scope TEXT NOT NULL,
      dpop_jwk TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_par_requests (
      request_uri TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      request_data TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`
  ], "write");
}

const defaultUrl = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

db = createDb(defaultUrl || 'file:local.db', authToken);


