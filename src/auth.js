import jwt from 'jsonwebtoken';
import { createHash, createPublicKey, createPrivateKey, createECDH, verify as cryptoVerify, randomBytes } from 'crypto';
import * as cryptoAtp from '@atproto/crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';

export function createToken(did, handle) {
  return jwt.sign({ sub: did, handle }, JWT_SECRET, { expiresIn: '24h' });
}

export async function createServiceAuthToken(aud, lxm, sub, exp = null) {
  const privKeyHex = process.env.PRIVATE_KEY;
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (!privKeyHex) throw new Error('No PDS private key');
  if (!pdsDid) throw new Error('No PDS DID');

  const payload = {
    iss: pdsDid,
    sub,
    aud: aud.split('#')[0],
    lxm,
    iat: Math.floor(Date.now() / 1000),
    exp: exp || (Math.floor(Date.now() / 1000) + 60),
    jti: randomBytes(16).toString('hex'),
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
  const { htu, htm } = decoded.payload;
  if (htm !== req.method) {
    throw new Error('DPoP htm mismatch');
  }

  const protocol = req.user?.protocol || (req.protocol === 'https' || process.env.NODE_ENV === 'production' ? 'https' : 'http');
  const host = req.user?.host || req.get('host');
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

export const auth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.log(`Auth failed: No Authorization header for ${req.url}`);
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }
  const [type, token] = authHeader.split(' ');
  const jwtToken = (type === 'Bearer' || type === 'DPoP') ? token : type;
  
  if (!jwtToken) {
    console.log(`Auth failed: Empty token for ${req.url}`);
    return res.status(401).json({ error: 'AuthenticationRequired', message: 'Token missing' });
  }
  
  if (type === 'DPoP') {
    const { jkt } = await validateDpop(req, jwtToken);
    const payload = verifyToken(jwtToken);
    if (!payload || payload.cnf?.jkt !== jkt) {
      return res.status(401).json({ error: 'InvalidToken', message: 'DPoP binding mismatch' });
    }
    if (!req.user) req.user = {};
    req.user.auth = payload;
    return next();
  }

  const payload = verifyToken(jwtToken);
  if (!payload) {
    console.log(`Auth failed: Invalid token for ${req.url}`);
    return res.status(401).json({ error: 'InvalidToken' });
  }
  if (!req.user) req.user = {};
  req.user.auth = payload;
  next();
};
