import { createClient } from '@libsql/client';
import 'dotenv/config';

export const db = createClient({
  url: process.env.DATABASE_URL || 'file:local.db',
  authToken: process.env.DATABASE_AUTH_TOKEN,
});

export async function initDb() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS account (
      handle TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      did TEXT NOT NULL,
      signing_key TEXT NOT NULL,
      root_cid TEXT
    )`,
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
    )`
  ], "write");
}
