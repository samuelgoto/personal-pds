import { Repo, ReadableBlockstore, BlockMap, blocksToCarFile, WriteOpAction } from '@atproto/repo';
import { CID } from 'multiformats';
import { db } from './db.js';
import * as crypto from '@atproto/crypto';
import { cborDecode, cborEncode, formatDid, createBlobCid, fixCids } from './util.js';
import axios from 'axios';
import { createHash } from 'crypto';
import { sequencer } from './sequencer.js';

export class TursoStorage extends ReadableBlockstore {
  blocks = new BlockMap();
  newBlocks = new BlockMap();
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
    this.newBlocks.set(cid, block);
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
    if (!event.commit) return null;
    if (typeof event.commit === 'string') return event.commit;
    
    // If it's a cborg-style CID object, convert it
    if (event.commit.asCID === event.commit || event.commit._Symbol_for_multiformats_cid) {
        return event.commit.toString();
    }
    
    // Fallback for plain objects from cborg
    try {
        return CID.decode(event.commit.bytes || event.commit).toString();
    } catch (e) {
        // If all else fails, try to see if it has a / link (common in some CID JSON formats)
        return (event.commit['/'] || event.commit).toString();
    }
  } catch (e) {
    console.error('Error in getRootCid:', e);
    return null; 
  }
};

export async function maybeInitRepo() {
  const rootCid = await getRootCid();
  if (rootCid) return;

  const privKeyHex = process.env.PRIVATE_KEY;
  const domain = (process.env.HANDLE || 'localhost:3000').split(':')[0];
  const did = (process.env.PDS_DID || formatDid(domain)).trim();
  
  if (!privKeyHex) {
    console.log('PRIVATE_KEY not found. Skipping repo auto-init.');
    return;
  }
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));

  console.log(`Auto-initializing PDS repo for ${did}...`);
  const storage = new TursoStorage();
  
  // 1. Initial empty repo
  let repo = await loadRepo(storage, did, keypair, null);
  
  // 2. Handle Avatar if provided
  let avatarBlob = undefined;
  if (process.env.AVATAR_URL) {
    try {
        console.log(`Fetching avatar from ${process.env.AVATAR_URL}...`);
        const response = await axios.get(process.env.AVATAR_URL, { responseType: 'arraybuffer' });
        const content = Buffer.from(response.data);
        const mimeType = response.headers['content-type'] || 'image/png';
        const cid = await createBlobCid(content);

        await db.execute({
            sql: "INSERT OR REPLACE INTO blobs (cid, did, mime_type, content, created_at) VALUES (?, ?, ?, ?, ?)",
            args: [cid, did, mimeType, content, new Date().toISOString()]
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
      record: fixCids({
        $type: 'app.bsky.actor.profile',
        displayName: process.env.DISPLAY_NAME || domain,
        description: process.env.DESCRIPTION || 'Personal PDS',
        avatar: avatarBlob,
        createdAt: new Date().toISOString(),
      }),
    }
  ], keypair);

  const recordCid = await repo.data.get('app.bsky.actor.profile/self');
  const blocks = await blocksToCarFile(repo.cid, storage.newBlocks);

  await sequencer.sequenceEvent({
    type: 'commit',
    did: did,
    event: {
      repo: did,
      commit: repo.cid,
      blocks: blocks,
      rev: repo.commit.rev,
      since: null,
      ops: [{ action: 'create', path: 'app.bsky.actor.profile/self', cid: recordCid }],
      blobs: avatarBlob ? [CID.parse(avatarBlob.ref.$link.toString())] : [],
      time: new Date().toISOString(),
      rebase: false,
      tooBig: false,
    }
  });

  console.log(`Repo auto-initialized successfully. Root CID: ${repo.cid.toString()}`);
}
