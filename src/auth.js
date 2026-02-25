import jwt from 'jsonwebtoken';
import { createHash, createPublicKey, createPrivateKey, createECDH, verify as cryptoVerify } from 'crypto';
import * as cryptoAtp from '@atproto/crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

export function createToken(did, handle) {
  return jwt.sign({ sub: did, handle }, JWT_SECRET, { expiresIn: '24h' });
}

export function createAccessToken(did, handle, jkt, issuer, client_id) {
  // ATProto OAuth nuance: The resource server identifier is its did:web
  const pdsHost = issuer.replace(/^https?:\/\//, '');
  const pdsDidWeb = `did:web:${pdsHost}`;
  
  const payload = {
    iss: issuer,
    sub: did,
    aud: [pdsDidWeb, client_id], // Identifying the PDS by its did:web
    handle,
    cnf: { jkt },
    scope: 'atproto'
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

export async function createIdToken(did, handle, client_id, issuer) {
  const privKeyHex = process.env.PRIVATE_KEY;
  if (!privKeyHex) throw new Error('No PDS private key');
  if (!client_id) throw new Error('client_id is required for id_token');

  const payload = {
    iss: issuer,
    sub: did,
    aud: client_id,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    name: handle,
    preferred_username: handle
  };

  const header = { typ: 'JWT', alg: 'ES256K' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = Buffer.from(`${headerB64}.${payloadB64}`);

  const keypair = await cryptoAtp.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
  const sig = await keypair.sign(data);
  const sigB64 = Buffer.from(sig).toString('base64url');

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

export async function createServiceAuthToken(aud, lxm, exp = null) {
  const privKeyHex = process.env.PRIVATE_KEY;
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (!privKeyHex) throw new Error('No PDS private key');
  if (!pdsDid) throw new Error('No PDS DID');

  const payload = {
    iss: pdsDid,
    aud: aud,
    lxm: lxm,
    iat: Math.floor(Date.now() / 1000),
    exp: exp || (Math.floor(Date.now() / 1000) + 60), // Default 60 seconds
    jti: createHash('sha256').update(Math.random().toString()).digest('hex'),
  };

  const header = { typ: 'JWT', alg: 'ES256K' };
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = Buffer.from(`${headerB64}.${payloadB64}`);

  const keypair = await cryptoAtp.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
  const sig = await keypair.sign(data);
  const sigB64 = Buffer.from(sig).toString('base64url');

  return `${headerB64}.${payloadB64}.${sigB64}`;
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
    if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') {
      const publicKeyBytes = new Uint8Array(Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]));
      const keypair = cryptoAtp.Secp256k1Keypair.fromPublicKey(publicKeyBytes);
      const [headerB64, payloadB64, sigB64] = dpop.split('.');
      const data = Buffer.from(`${headerB64}.${payloadB64}`);
      const signature = Buffer.from(sigB64, 'base64url');
      const verified = await keypair.verify(data, signature);
      if (!verified) throw new Error('DPoP signature verification failed');
    } else {
      const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
      // jsonwebtoken handles the signature format conversion (raw vs DER) for EC keys
      jwt.verify(dpop, publicKey, { algorithms: ['ES256', 'RS256'] });
    }
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
      console.error(`DPoP htu mismatch debug: expected ${expectedHtu}, got ${htu}`);
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
