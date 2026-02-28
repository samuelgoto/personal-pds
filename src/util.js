import fs from 'fs';
import path from 'path';
import { createHash, timingSafeEqual } from 'crypto';
import { CID } from 'multiformats/cid';
import * as cbor from '@ipld/dag-cbor';
import * as sha256 from 'multiformats/hashes/sha2';
import * as crypto from '@atproto/crypto';

export function verifyPassword(inputPassword, storedPassword) {
  if (typeof inputPassword !== 'string' || typeof storedPassword !== 'string') {
    return false;
  }
  const inputHash = createHash('sha256').update(inputPassword).digest();
  const storedHash = createHash('sha256').update(storedPassword).digest();
  return timingSafeEqual(inputHash, storedHash);
}

export function isSafeUrl(urlStr) {
  try {
    const url = new URL(urlStr);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return false;
    }
    const isProd = process.env.NODE_ENV === 'production' || process.env.VERCEL;
    if (isProd) {
      const hostname = url.hostname;
      const forbidden = ['localhost', '127.0.0.1', '::1', '169.254.169.254', '0.0.0.0'];
      if (forbidden.includes(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
        return false;
      }
    }
    return true;
  } catch (e) {
    return false;
  }
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
    "alsoKnownAs": [`at://${user.handle}`],
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

export async function createBlobCid(content) {
  const hash = await sha256.sha256.digest(content);
  return CID.createV1(0x55, hash).toString(); // 0x55 is raw codec (typical for blobs)
}
