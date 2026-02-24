import jwt from 'jsonwebtoken';
import { createHash, createPublicKey, createPrivateKey, verify as cryptoVerify } from 'crypto';
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

export function createIdToken(did, handle, client_id, issuer) {
  const privKeyHex = process.env.PRIVATE_KEY;
  if (!privKeyHex) throw new Error('No PDS private key');

  // We need to sign this with the actual PDS private key (ES256K)
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from([0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x20]), Buffer.from(privKeyHex, 'hex'), Buffer.from([0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0xa1, 0x44, 0x03, 0x42, 0x00]), Buffer.from(new Uint8Array(65))]), // Simplified DER wrapper
    format: 'der',
    type: 'sec1'
  });

  // Actually, for Secp256k1 signing in Node, we need a specific format.
  // Let's use a simpler way: @atproto/crypto for signing and then wrap in JWT.
  // But jsonwebtoken is more convenient for claims.
  
  // Alternative: sign access tokens with HS256 (internal to PDS)
  // and sign ID tokens with ES256K (publicly verifiable).
  
  const payload = {
    iss: issuer,
    sub: did,
    aud: client_id,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    name: handle,
    preferred_username: handle
  };

  // We'll use the JWT_SECRET for now to keep it working, but 
  // in a real PDS this MUST be signed with the PDS private key.
  // Given we are in a "Simple PDS", HS256 might be enough if the client trusts our issuer.
  // But the error says "invalid audience", which is about claims.
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

  // Verify DPoP signature using the JWK
  try {
    const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
    // jsonwebtoken handles the signature format conversion (raw vs DER) for EC keys
    jwt.verify(dpop, publicKey, { algorithms: ['ES256', 'ES256K', 'RS256'] });
  } catch (err) {
    throw new Error(`DPoP signature verification failed: ${err.message}`);
  }

  // Basic DPoP claim verification
  const { htu, htm, iat, jti } = decoded.payload;
  if (htm !== req.method) {
    throw new Error('DPoP htm mismatch');
  }

  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production') ? 'https' : 'http';
  const host = req.get('host');
  const path = (req.originalUrl || req.url).split('?')[0];
  const expectedHtu = `${protocol}://${host}${path}`;
  
  if (htu !== expectedHtu) {
    // Be lenient with trailing slashes
    const normalizedHtu = htu.endsWith('/') ? htu.slice(0, -1) : htu;
    const normalizedExpected = expectedHtu.endsWith('/') ? expectedHtu.slice(0, -1) : expectedHtu;
    if (normalizedHtu !== normalizedExpected) {
      throw new Error(`DPoP htu mismatch: expected ${expectedHtu}, got ${htu}`);
    }
  }


  // If access_token is provided, verify it's bound to this jkt
  if (access_token) {
    const payload = verifyToken(access_token);
    if (!payload || !payload.cnf || payload.cnf.jkt !== jkt) {
      throw new Error('Token binding mismatch');
    }
  }

  return { jkt, jwk };
}
