import { Repo, ReadableBlockstore, RepoStorage, BlockMap, CommitData, blocksToCarFile } from '@atproto/repo';
import { CID } from 'multiformats';
import { db } from './db.js';
import * as crypto from '@atproto/crypto';
import { cborDecode } from '@atproto/common';
import { sequencer } from './sequencer.js';
import { formatDid } from './util.js';

export class TursoStorage extends ReadableBlockstore implements RepoStorage {
  blocks: BlockMap = new BlockMap();
  root: CID | null = null;

  async getBytes(cid: CID): Promise<Uint8Array | null> {
    const cached = this.blocks.get(cid);
    if (cached) return cached;
    const res = await db.execute({
      sql: 'SELECT block FROM repo_blocks WHERE cid = ?',
      args: [cid.toString()]
    });
    if (res.rows.length === 0) return null;
    const bytes = new Uint8Array(res.rows[0].block as any);
    this.blocks.set(cid, bytes);
    return bytes;
  }

  async has(cid: CID): Promise<boolean> {
    if (this.blocks.has(cid)) return true;
    const res = await db.execute({
      sql: 'SELECT 1 FROM repo_blocks WHERE cid = ?',
      args: [cid.toString()]
    });
    return res.rows.length > 0;
  }

  async getBlocks(cids: CID[]): Promise<{ blocks: BlockMap; missing: CID[] }> {
    const blocks = new BlockMap();
    const missing: CID[] = [];
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

  async getRoot(): Promise<CID | null> {
    return this.root;
  }

  async putBlock(cid: CID, block: Uint8Array): Promise<void> {
    this.blocks.set(cid, block);
    await db.execute({
      sql: 'INSERT OR IGNORE INTO repo_blocks (cid, block) VALUES (?, ?)',
      args: [cid.toString(), block]
    });
  }

  async putMany(blocks: BlockMap): Promise<void> {
    for (const [cid, bytes] of blocks) {
      await this.putBlock(cid, bytes);
    }
  }

  async updateRoot(cid: CID): Promise<void> {
    this.root = cid;
  }

  async applyCommit(commit: CommitData): Promise<void> {
    this.root = commit.cid;
    await this.putMany(commit.newBlocks);
  }

  async getRepoBlocks(): Promise<BlockMap> {
    const res = await db.execute('SELECT cid, block FROM repo_blocks');
    const blocks = new BlockMap();
    for (const row of res.rows) {
      blocks.set(CID.parse(row.cid as string), new Uint8Array(row.block as any));
    }
    return blocks;
  }
}

export async function loadRepo(storage: TursoStorage, did: string, keypair: crypto.Keypair, rootCid: string | null) {
  if (!rootCid) {
    const commit = await Repo.formatInitCommit(storage, did, keypair);
    return await Repo.createFromCommit(storage, commit);
  }
  return await Repo.load(storage, CID.parse(rootCid));
}

export const getRootCid = async (): Promise<string | null> => {
  try {
    const res = await db.execute({
      sql: "SELECT event FROM sequencer WHERE type = 'commit' ORDER BY seq DESC LIMIT 1"
    });
    if (res.rows.length === 0) return null;
    const event = cborDecode(new Uint8Array(res.rows[0].event as any)) as any;
    return event.commit.toString();
  } catch (e) {
    return null; // Table might not exist yet
  }
};

export async function maybeInitRepo() {
  const rootCid = await getRootCid();
  if (rootCid) return;

  const privKeyHex = process.env.PRIVATE_KEY;
  const domain = process.env.DOMAIN || 'localhost:3000';
  
  if (!privKeyHex) {
    console.log('PRIVATE_KEY not found. Skipping repo auto-init.');
    return;
  }

  const did = formatDid(domain);
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));

  console.log(`Auto-initializing PDS repo for ${did}...`);
  const storage = new TursoStorage();
  const repo = await loadRepo(storage, did, keypair, null);
  
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
      ops: [],
      time: new Date().toISOString(),
    }
  });
  console.log(`Repo auto-initialized successfully. Root CID: ${repo.cid.toString()}`);
}
