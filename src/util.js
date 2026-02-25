import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { TID } from '@atproto/common';
import { CID } from 'multiformats/cid';
import * as cbor from '@ipld/dag-cbor';
import * as sha256 from 'multiformats/hashes/sha2';
import * as crypto from '@atproto/crypto';

export let lastRelayPing = null;

export function setLastRelayPing(time) {
  lastRelayPing = time;
}

export const getDidDoc = async (user, host) => {
  if (!user) return null;

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
  const serviceEndpoint = `${user.protocol}://${host}`;

  return {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multiconf/v1",
        "https://w3id.org/security/suites/secp256k1-2019/v1"
    ],
    "id": user.did,
    "alsoKnownAs": [`at://${host}`],
    verificationMethod: [
      {
        "id": `${user.did}#atproto`,
        "type": "Multikey",
        "controller": user.did,
        "publicKeyMultibase": keypair.did().split(':').pop()
      }
    ],
    "authentication": [`${user.did}#atproto`],
    "assertionMethod": [`${user.did}#atproto`],
    "capabilityInvocation": [`${user.did}#atproto`],
    "capabilityDelegation": [`${user.did}#atproto`],
    "service": [{
      "id": "#atproto_pds",
      "type": "AtprotoPersonalDataServer",
      "serviceEndpoint": serviceEndpoint
    }]
  };
};

export function fixCids(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(fixCids);
  
  // If it's already a CID-like object, convert it to a real CID instance
  if (obj.asCID === obj || obj._Symbol_for_multiformats_cid || (obj.code !== undefined && obj.version !== undefined && obj.hash !== undefined)) {
    try {
      if (obj.asCID === obj) return obj;
      // Re-decode from its own bytes to ensure it's a clean instance
      if (obj.bytes) return CID.decode(obj.bytes);
      // Reconstruct if bytes are missing
      return CID.create(obj.version, obj.code, obj.hash);
    } catch (e) {
      return obj;
    }
  }

  // If it's a string that looks like a CID, try to parse it
  if (typeof obj === 'string' && obj.startsWith('bafy')) {
    try {
      return CID.parse(obj);
    } catch (e) {
      return obj;
    }
  }

  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    // Standard ATProto link structure: { $link: "..." }
    if (k === '$link' && typeof v === 'string' && v.startsWith('bafy')) {
        try {
            return CID.parse(v);
        } catch (e) {
            // fall through
        }
    }
    out[k] = fixCids(v);
  }
  return out;
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
