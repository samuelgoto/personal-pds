import { Repo, ReadableBlockstore, RepoStorage, BlockMap, CommitData } from '@atproto/repo';
import { CID } from 'multiformats/cid';
import { db } from './db';
import * as crypto from '@atproto/crypto';

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
