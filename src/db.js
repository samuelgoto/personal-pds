import { createClient } from '@libsql/client';
import 'dotenv/config';

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

const defaultUrl = process.env.DATABASE_URL || 'file:local.db';
db = createDb(defaultUrl, process.env.DATABASE_AUTH_TOKEN);
