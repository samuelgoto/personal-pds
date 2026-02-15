import { Repo, ReadableBlockstore, BlockMap, blocksToCarFile, WriteOpAction } from '@atproto/repo';
import { CID } from 'multiformats';
import { db } from './db.js';
import * as crypto from '@atproto/crypto';
import { cborDecode } from '@atproto/common';
import axios from 'axios';
import { createHash } from 'crypto';
import { sequencer } from './sequencer.js';
import { formatDid, getStaticAvatar } from './util.js';

export class TursoStorage extends ReadableBlockstore {
  blocks = new BlockMap();
  root = null;

  async getBytes(cid) {
    const cached = this.blocks.get(cid);
    if (cached) return cached;
    const res = await db.execute({
      sql: 'SELECT block FROM repo_blocks WHERE cid = ?',
      args: [cid.toString()]
    });
    if (res.rows.length === 0) return null;
    const bytes = new Uint8Array(res.rows[0].block);
    this.blocks.set(cid, bytes);
    return bytes;
  }

  async has(cid) {
    if (this.blocks.has(cid)) return true;
    const res = await db.execute({
      sql: 'SELECT 1 FROM repo_blocks WHERE cid = ?',
      args: [cid.toString()]
    });
    return res.rows.length > 0;
  }

  async getBlocks(cids) {
    const blocks = new BlockMap();
    const missing = [];
    for (const cid of cids) {
      const bytes = await this.getBytes(cid);
      if (bytes) {
        blocks.set(cid, bytes);
      } else {
        missing.push(cid);
      }
    }
    return { blocks, missing };
  }

  async getRoot() {
    return this.root;
  }

  async putBlock(cid, block) {
    this.blocks.set(cid, block);
    await db.execute({
      sql: 'INSERT OR IGNORE INTO repo_blocks (cid, block) VALUES (?, ?)',
      args: [cid.toString(), block]
    });
  }

  async putMany(blocks) {
    for (const [cid, bytes] of blocks) {
      await this.putBlock(cid, bytes);
    }
  }

  async updateRoot(cid) {
    this.root = cid;
  }

  async applyCommit(commit) {
    this.root = commit.cid;
    await this.putMany(commit.newBlocks);
  }

  async getRepoBlocks() {
    const res = await db.execute('SELECT cid, block FROM repo_blocks');
    const blocks = new BlockMap();
    for (const row of res.rows) {
      blocks.set(CID.parse(row.cid), new Uint8Array(row.block));
    }
    return blocks;
  }
}

export async function loadRepo(storage, did, keypair, rootCid) {
  if (!rootCid) {
    const commit = await Repo.formatInitCommit(storage, did, keypair);
    return await Repo.createFromCommit(storage, commit);
  }
  return await Repo.load(storage, CID.parse(rootCid));
}

export const getRootCid = async () => {
  try {
    const res = await db.execute({
      sql: "SELECT event FROM sequencer WHERE type = 'commit' ORDER BY seq DESC LIMIT 1"
    });
    if (res.rows.length === 0) return null;
    const event = cborDecode(new Uint8Array(res.rows[0].event));
    return event.commit.toString();
  } catch (e) {
    return null; 
  }
};

export async function maybeInitRepo() {
  const rootCid = await getRootCid();
  if (rootCid) return;

  const privKeyHex = process.env.PRIVATE_KEY;
  const domain = (process.env.DOMAIN || 'localhost:3000').split(':')[0];
  
  if (!privKeyHex) {
    console.log('PRIVATE_KEY not found. Skipping repo auto-init.');
    return;
  }

  const did = formatDid(domain);
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));

  console.log(`Auto-initializing PDS repo for ${did}...`);
  const storage = new TursoStorage();
  
  // 1. Initial empty repo
  let repo = await loadRepo(storage, did, keypair, null);
  
  // 2. Handle Avatar if provided
  let avatarBlob = undefined;
  const staticAvatar = getStaticAvatar();
  
  if (staticAvatar) {
    console.log(`Using static avatar file: ${staticAvatar.cid}`);
    await db.execute({
        sql: "INSERT OR REPLACE INTO blobs (cid, mime_type, content, created_at) VALUES (?, ?, ?, ?)",
        args: [staticAvatar.cid, staticAvatar.mimeType, staticAvatar.content, new Date().toISOString()]
    });
    avatarBlob = {
        $type: 'blob',
        ref: { $link: staticAvatar.cid },
        mimeType: staticAvatar.mimeType,
        size: staticAvatar.size,
    };
  } else if (process.env.AVATAR_URL) {
    try {
        console.log(`Fetching avatar from ${process.env.AVATAR_URL}...`);
        const response = await axios.get(process.env.AVATAR_URL, { responseType: 'arraybuffer' });
        const content = Buffer.from(response.data);
        const mimeType = response.headers['content-type'] || 'image/png';
        const hash = createHash('sha256').update(content).digest('hex');
        const cid = `bafybe${hash}`;

        await db.execute({
            sql: "INSERT OR REPLACE INTO blobs (cid, mime_type, content, created_at) VALUES (?, ?, ?, ?)",
            args: [cid, mimeType, content, new Date().toISOString()]
        });

        avatarBlob = {
            $type: 'blob',
            ref: { $link: cid },
            mimeType: mimeType,
            size: content.length,
        };
        console.log(`Avatar stored as blob: ${cid}`);
    } catch (err) {
        console.error('Failed to fetch avatar during auto-init:', err.message);
    }
  }

  // 3. Create default profile
  console.log(`Creating default profile...`);
  repo = await repo.applyWrites([
    {
      action: WriteOpAction.Create,
      collection: 'app.bsky.actor.profile',
      rkey: 'self',
      record: {
        $type: 'app.bsky.actor.profile',
        displayName: process.env.DISPLAY_NAME || domain,
        description: process.env.DESCRIPTION || 'Personal PDS',
        avatar: avatarBlob,
        createdAt: new Date().toISOString(),
      },
    }
  ], keypair);

  const recordCid = await repo.data.get('app.bsky.actor.profile/self');
  const carBlocks = await storage.getRepoBlocks();
  const blocks = await blocksToCarFile(repo.cid, carBlocks);

  await sequencer.sequenceEvent({
    type: 'commit',
    did: did,
    event: {
      repo: did,
      commit: repo.cid,
      blocks: blocks,
      rev: repo.commit.rev,
      since: null,
      ops: [{ action: 'create', path: 'app.bsky.actor.profile/self', cid: recordCid || repo.cid }],
      time: new Date().toISOString(),
    }
  });

  await db.execute({
    sql: "INSERT OR IGNORE INTO system_state (key, value) VALUES ('repo_created_at', ?)",
    args: [new Date().toISOString()]
  });

  console.log(`Repo auto-initialized successfully. Root CID: ${repo.cid.toString()}`);
}
