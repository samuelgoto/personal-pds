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

/**
 * Wraps a raw 33-byte compressed Secp256k1 public key in a DER-encoded
 * SubjectPublicKeyInfo (SPKI) structure so that Node.js crypto functions 
 * can parse it.
 * 
 * ASN.1 Structure:
 * SEQUENCE (2 elem)
 *   SEQUENCE (2 elem)
 *     OBJECT IDENTIFIER 1.2.840.10045.2.1 (id-ecPublicKey)
 *     OBJECT IDENTIFIER 1.3.132.0.10 (secp256k1)
 *   BIT STRING (264 bit) 00000011... (The raw 33-byte key)
 */
export function wrapCompressedSecp256k1(publicKeyBytes) {
  // 1. OID for id-ecPublicKey (1.2.840.10045.2.1)
  const idEcPublicKey = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  
  // 2. OID for secp256k1 (1.3.132.0.10)
  const secp256k1 = Buffer.from([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]);

  // 3. Algorithm Identifier (SEQUENCE of the two OIDs)
  const algorithmIdentifier = Buffer.concat([
    Buffer.from([0x30, idEcPublicKey.length + secp256k1.length]),
    idEcPublicKey,
    secp256k1
  ]);

  // 4. SubjectPublicKey (BIT STRING wrapper for the raw key)
  const subjectPublicKey = Buffer.concat([
    Buffer.from([0x03, publicKeyBytes.length + 1, 0x00]), // 0x00 is 'unused bits' count
    Buffer.from(publicKeyBytes)
  ]);

  // 5. Final SPKI wrapper (SEQUENCE of algorithm and key)
  return Buffer.concat([
    Buffer.from([0x30, algorithmIdentifier.length + subjectPublicKey.length]),
    algorithmIdentifier,
    subjectPublicKey
  ]);
}

export { cborEncode, cborDecode };
