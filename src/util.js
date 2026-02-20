import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { TID, cborEncode, cborDecode } from '@atproto/common';
import { CID } from 'multiformats/cid';
import * as sha256 from 'multiformats/hashes/sha2';

export function formatDid(hostname) {
  if (process.env.PDS_DID) {
    return process.env.PDS_DID.trim();
  }
  throw new Error('PDS_DID environment variable is required for did:plc identity.');
}

export function createTid() {
  return TID.nextStr();
}

export async function createBlobCid(content) {
  const hash = await sha256.sha256.digest(content);
  return CID.createV1(0x55, hash).toString(); // 0x55 is raw codec (typical for blobs)
}

export async function getStaticAvatar() {
  const possiblePaths = ['avatar.png', 'avatar.jpg', 'avatar.jpeg'];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p);
      const cid = await createBlobCid(content);
      const ext = path.extname(p).slice(1);
      return {
        cid,
        mimeType: `image/${ext === 'jpg' ? 'jpeg' : ext}`,
        content,
        size: content.length
      };
    }
  }
  return null;
}

export { cborEncode, cborDecode };
