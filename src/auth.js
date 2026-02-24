import jwt from 'jsonwebtoken';
import { createHash, createPublicKey, verify as cryptoVerify } from 'crypto';
import * as cryptoAtp from '@atproto/crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

export function createToken(did, handle) {
  return jwt.sign({ sub: did, handle }, JWT_SECRET, { expiresIn: '24h' });
}

export function createAccessToken(did, handle, jkt, issuer) {
  const payload = {
    iss: issuer,
    sub: did,
    aud: issuer,
    handle,
    cnf: { jkt },
    scope: 'atproto'
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

export function getJkt(jwk) {
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

export async function validateDpop(req, access_token = null) {
  const dpop = req.headers.dpop;
  if (!dpop) throw new Error('Missing DPoP header');

  const decoded = jwt.decode(dpop, { complete: true });
  if (!decoded || !decoded.header || !decoded.header.jwk) {
    throw new Error('Invalid DPoP header');
  }

  const jwk = decoded.header.jwk;
  const jkt = getJkt(jwk);

  // If access_token is provided, verify it's bound to this jkt
  if (access_token) {
    const payload = verifyToken(access_token);
    if (!payload || !payload.cnf || payload.cnf.jkt !== jkt) {
      throw new Error('Token binding mismatch');
    }
  }

  // Basic DPoP claim verification
  const { htu, htm, iat, jti } = decoded.payload;
  if (htm !== req.method) {
    throw new Error('DPoP htm mismatch');
  }

  // Verify DPoP signature using the JWK
  try {
    const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
    const [headerB64, payloadB64, sigB64] = dpop.split('.');
    const data = Buffer.from(`${headerB64}.${payloadB64}`);
    const signature = Buffer.from(sigB64, 'base64url');
    
    // Determine algorithm
    const alg = decoded.header.alg;
    let hashAlg = 'sha256'; // Default for ES256, ES256K, RS256
    
    const verified = cryptoVerify(null, data, publicKey, signature);
    if (!verified) throw new Error('DPoP signature verification failed');
  } catch (err) {
    throw new Error(`DPoP signature verification failed: ${err.message}`);
  }

  return { jkt, jwk };
}
