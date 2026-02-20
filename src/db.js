import { createClient } from '@libsql/client';

export let db;

export function setDb(client) {
  db = client;
}

export const createDb = (url, authToken) => {
  return createClient({ url, authToken });
};

export async function initDb(client) {
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
    `CREATE TABLE IF NOT EXISTS system_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`
  ], "write");
}

const defaultUrl = process.env.TURSO_DATABASE_URL || process.env.DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN || process.env.DATABASE_AUTH_TOKEN;

if (process.env.VERCEL && (!defaultUrl || defaultUrl.startsWith('file:'))) {
  throw new Error('DATABASE_URL or TURSO_DATABASE_URL must be a remote Turso URL (libsql:// or https://) when running on Vercel.');
}

db = createDb(defaultUrl || 'file:local.db', authToken);


