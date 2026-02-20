import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { TID, cborEncode, cborDecode } from '@atproto/common';

export function formatDid(hostname) {
  if (process.env.PDS_DID) {
    return process.env.PDS_DID.trim();
  }
  throw new Error('PDS_DID environment variable is required for did:plc identity.');
}

export function createTid() {
  return TID.nextStr();
}

export function getStaticAvatar() {
  const possiblePaths = ['avatar.png', 'avatar.jpg', 'avatar.jpeg'];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p);
      const hash = createHash('sha256').update(content).digest('hex');
      const ext = path.extname(p).slice(1);
      return {
        cid: `bafybe${hash}`,
        mimeType: `image/${ext === 'jpg' ? 'jpeg' : ext}`,
        content,
        size: content.length
      };
    }
  }
  return null;
}

export { cborEncode, cborDecode };
