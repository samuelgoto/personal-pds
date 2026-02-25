import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { TID } from '@atproto/common';
import { CID } from 'multiformats/cid';
import * as cborg from 'cborg';
import { Token, Type } from 'cborg';
import * as sha256 from 'multiformats/hashes/sha2';

export function cborEncode(obj) {
  return cborg.encode(obj, {
    typeEncoders: {
      Object: (obj) => {
        // Robustly identify CIDs (both multiformats instances and plain objects)
        const isCid = obj.asCID === obj || 
                      obj._Symbol_for_multiformats_cid ||
                      (obj.code !== undefined && obj.version !== undefined && obj.hash !== undefined);

        if (isCid) {
          // Get the raw bytes
          let bytes = obj.bytes;
          if (!bytes) {
            // If it's a plain object from a DB/JSON cycle, it might not have .bytes
            // But it will have .code, .version, .hash
            try {
                // Try to reconstruct it to get the bytes
                const cid = CID.create(obj.version, obj.code, obj.hash);
                bytes = cid.bytes;
            } catch (e) {
                return undefined;
            }
          }

          if (!bytes) return undefined;

          // ATProto CID tag 42: leading 0x00 followed by the raw multihash
          const taggedBytes = new Uint8Array(bytes.length + 1);
          taggedBytes[0] = 0;
          taggedBytes.set(bytes, 1);
          // Manually return tokens for Tag 42
          return [
            new Token(Type.tag, 42),
            new Token(Type.bytes, taggedBytes)
          ];
        }
        return undefined;
      }
    }
  });
}

export function cborDecode(bytes) {
  const tags = [];
  tags[42] = (value) => {
    if (value instanceof Uint8Array) {
      const cidBytes = value[0] === 0 ? value.subarray(1) : value;
      return CID.decode(cidBytes);
    }
    return value;
  };
  return cborg.decode(bytes, { tags });
}

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

export function wrapCompressedSecp256k1(publicKeyBytes) {
  const header = Buffer.from([
    0x30, 0x36, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x22, 0x00
  ]);
  return Buffer.concat([header, Buffer.from(publicKeyBytes)]);
}
