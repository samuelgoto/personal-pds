import { createPrivateKey, createPublicKey } from 'crypto';
import * as crypto from '@atproto/crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'crypto';

function getJkt(jwk) {
  const { kty, n, e, crv, x, y } = jwk;
  let components;
  if (kty === 'RSA') {
    components = { e, kty, n };
  } else if (kty === 'EC') {
    components = { crv, kty, x, y };
  } else if (kty === 'OKP') {
    components = { crv, kty, x };
  } else {
    throw new Error('Unsupported JWK kty');
  }
  const json = JSON.stringify(components);
  return createHash('sha256').update(json).digest('base64url');
}

export function normalizePemValue(value) {
  if (!value) return '';
  return value.includes('\\n') ? value.replace(/\\n/g, '\n') : value;
}

export function getOauthEs256kPrivateKeyHex() {
  return (process.env.OAUTH_ES256K_PRIVATE_KEY || '').trim();
}

export async function getOauthEs256kKeypair() {
  const privKeyHex = getOauthEs256kPrivateKeyHex();
  if (!privKeyHex) {
    throw new Error('No OAuth ES256K private key configured');
  }
  return crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
}

export async function getOauthEs256kPublicJwk() {
  const keypair = await getOauthEs256kKeypair();
  const publicKeyBytes = keypair.publicKeyBytes();
  const uncompressed = secp256k1.ProjectivePoint.fromHex(publicKeyBytes).toRawBytes(false);
  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: Buffer.from(uncompressed.slice(1, 33)).toString('base64url'),
    y: Buffer.from(uncompressed.slice(33, 65)).toString('base64url'),
    use: 'sig',
    alg: 'ES256K',
    kid: keypair.did(),
  };
}

export function getOptionalRs256PrivateKey() {
  const pem = normalizePemValue(process.env.OAUTH_RS256_PRIVATE_KEY || '').trim();
  if (!pem) return null;
  return createPrivateKey({ key: pem, format: 'pem' });
}

export function getOptionalRs256PublicJwk() {
  const privateKey = getOptionalRs256PrivateKey();
  if (!privateKey) return null;
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  return {
    ...jwk,
    use: 'sig',
    alg: 'RS256',
    kid: getJkt(jwk),
  };
}

export function getSupportedAuthorizationSigningAlgs() {
  return ['ES256K', 'RS256'];
}
