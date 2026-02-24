import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { TID } from '@atproto/common';
import * as cborg from 'cborg';
import { CID } from 'multiformats/cid';

export function cborEncode(obj) {
  return cborg.encode(obj);
}

export function cborDecode(bytes) {
  return cborg.decode(bytes, {
    tags: {
      42: (value) => {
        if (value instanceof Uint8Array) {
          // ATProto CID tag 42 usually has a leading 0x00 byte
          const cidBytes = value[0] === 0 ? value.subarray(1) : value;
          return CID.decode(cidBytes);
        }
        return value;
      }
    }
  });
}
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

export function cidToString(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(cidToString);
  if (obj.asCID === obj || obj._Symbol_for_multiformats_cid) {
    return obj.toString();
  }
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = cidToString(v);
  }
  return out;
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
  // SPKI Header for Secp256k1 (23 bytes)
  // SEQUENCE (2 elem)
  //   SEQUENCE (2 elem)
  //     OBJECT IDENTIFIER 1.2.840.10045.2.1 (id-ecPublicKey)
  //     OBJECT IDENTIFIER 1.3.132.0.10 (secp256k1)
  const header = Buffer.from([
    0x30, 0x36, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x22, 0x00
  ]);
  return Buffer.concat([header, Buffer.from(publicKeyBytes)]);
}
