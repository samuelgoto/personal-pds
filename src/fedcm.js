import express from 'express';
import { randomBytes } from 'crypto';
import { Repo } from '@atproto/repo';
import { CID } from 'multiformats';
import { db } from './db.js';
import { TursoStorage } from './repo.js';
import { escapeHtml, isSafeUrl } from './util.js';

const router = express.Router();

const ACCOUNT_PUSH_EXPIRATION_MS = 24 * 60 * 60 * 1000;
const FEDCM_TYPES = ['indieauth'];

const getIssuer = (req) => req.user?.issuer || `${req.user?.protocol}://${req.user?.host}`;
export const getConfigUrl = (req) => `${getIssuer(req)}/config.json`;
const getMetadataEndpoint = (req) => `${getIssuer(req)}/.well-known/oauth-authorization-server`;
const getMeUrl = (req) => `${getIssuer(req)}/profile`;

const getApiConfig = (req) => {
  const issuer = getIssuer(req);
  return {
    id_assertion_endpoint: `${issuer}/assertion`,
    disconnect_endpoint: `${issuer}/disconnect`,
    login_url: `${issuer}/login`,
    branding: {
      background_color: '#0f172a',
      color: '#f8fafc',
      icons: [{ url: `${issuer}/favicon.ico`, size: 64 }],
    },
  };
};

async function getApprovedClients(did) {
  const key = `fedcm:approved_clients:${did}`;
  const result = await db.execute({
    sql: 'SELECT value FROM preferences WHERE key = ?',
    args: [key],
  });

  if (result.rows.length === 0) return [];
  try {
    const value = JSON.parse(result.rows[0].value);
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

async function setApprovedClients(did, approvedClients) {
  await db.execute({
    sql: 'INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)',
    args: [`fedcm:approved_clients:${did}`, JSON.stringify(approvedClients)],
  });
}

async function rememberApprovedClient(did, clientId) {
  if (!clientId) return;
  const approvedClients = await getApprovedClients(did);
  if (approvedClients.includes(clientId)) return;
  approvedClients.push(clientId);
  await setApprovedClients(did, approvedClients);
}

async function forgetApprovedClient(did, clientId) {
  const approvedClients = await getApprovedClients(did);
  await setApprovedClients(did, approvedClients.filter((candidate) => candidate !== clientId));
}

async function loadProfileRecord(user) {
  try {
    const storage = new TursoStorage();
    const repo = await Repo.load(storage, CID.parse(user.root_cid));
    return await repo.getRecord('app.bsky.actor.profile', 'self');
  } catch {
    return null;
  }
}

function getBlobUrl(req, blob) {
  const cid = blob?.ref?.$link;
  if (!cid) return undefined;
  return `${getIssuer(req)}/xrpc/com.atproto.sync.getBlob?cid=${encodeURIComponent(cid)}`;
}

export async function buildFedCmAccount(req) {
  const profile = await loadProfileRecord(req.user);
  const handle = req.user.handle.startsWith('@') ? req.user.handle : `@${req.user.handle}`;
  const displayName = profile?.displayName || handle;
  const approvedClients = await getApprovedClients(req.user.did);
  const meUrl = getMeUrl(req);

  return {
    id: meUrl,
    name: displayName,
    email: handle,
    given_name: displayName.split(' ')[0],
    picture: getBlobUrl(req, profile?.avatar),
    login_hints: [meUrl, handle, req.user.handle, req.user.did].filter(Boolean),
    approved_clients: approvedClients,
  };
}

async function buildIndieAuthProfile(req) {
  const profile = await loadProfileRecord(req.user);
  return {
    name: profile?.displayName || req.user.handle,
    url: getMeUrl(req),
    photo: getBlobUrl(req, profile?.avatar),
  };
}

export async function buildAccountPushPayload(req) {
  return {
    accounts: [await buildFedCmAccount(req)],
    apiConfig: getApiConfig(req),
    expiration: ACCOUNT_PUSH_EXPIRATION_MS,
  };
}

function validateWebIdentityRequest(req) {
  return req.get('sec-fetch-dest') === 'webidentity';
}

function setAssertionCorsHeaders(req, res) {
  const origin = req.get('origin');
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
}

function normalizeClientId(clientId, origin) {
  const effectiveClientId = clientId || origin;
  if (!effectiveClientId) {
    throw new Error('Missing client_id');
  }

  if (isSafeUrl(effectiveClientId)) {
    const clientOrigin = new URL(effectiveClientId).origin;
    if (origin && clientOrigin !== origin) {
      throw new Error('client_id origin mismatch');
    }
  } else if (origin && effectiveClientId !== origin) {
    throw new Error('Unsupported non-URL client_id');
  }

  return effectiveClientId;
}


router.get('/.well-known/web-identity', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    provider_urls: [getConfigUrl(req)],
  });
});

router.get('/config.json', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    ...getApiConfig(req),
    types: FEDCM_TYPES,
  });
});

router.get('/profile', async (req, res) => {
  const profile = await buildIndieAuthProfile(req);
  const metadataEndpoint = getMetadataEndpoint(req);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.setHeader('Link', `<${metadataEndpoint}>; rel="indieauth-metadata"`);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(profile.name)}</title>
  <link rel="icon" href="/favicon.ico" sizes="any">
  <link rel="indieauth-metadata" href="${escapeHtml(metadataEndpoint)}">
</head>
<body>
  <main>
    <h1>${escapeHtml(profile.name)}</h1>
    <p><a href="${escapeHtml(profile.url)}">${escapeHtml(profile.url)}</a></p>
  </main>
</body>
</html>`);
});

router.get('/icon', async (req, res) => {
  const label = escapeHtml(req.user.handle.slice(0, 2).toUpperCase());
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="${label}"><defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#0f172a"/><stop offset="100%" stop-color="#2563eb"/></linearGradient></defs><rect width="64" height="64" rx="18" fill="url(#g)"/><text x="32" y="39" text-anchor="middle" font-size="24" font-family="system-ui, sans-serif" fill="#ffffff">${label}</text></svg>`
  );
});

router.post('/assertion', async (req, res) => {
  setAssertionCorsHeaders(req, res);
  res.setHeader('Cache-Control', 'no-store');

  if (!validateWebIdentityRequest(req)) {
    return res.status(400).json({ error: 'InvalidRequest', message: 'Missing Sec-Fetch-Dest: webidentity' });
  }

  if (!req.session) {
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }

  const origin = req.get('origin');
  let effectiveClientId;
  try {
    effectiveClientId = normalizeClientId(req.body.client_id, origin);
  } catch (err) {
    return res.status(400).json({ error: 'InvalidRequest', message: err.message });
  }

  const meUrl = getMeUrl(req);
  const accountId = req.body.account_id || meUrl;
  if (accountId !== meUrl) {
    return res.status(400).json({ error: 'InvalidRequest', message: 'Unknown account_id' });
  }

  let params = {};
  if (req.body.params) {
    try {
      params = JSON.parse(req.body.params);
    } catch {
      return res.status(400).json({ error: 'InvalidRequest', message: 'params must be valid JSON' });
    }
  }

  if (params.code_challenge && params.code_challenge_method && params.code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'InvalidRequest', message: 'Only S256 PKCE is supported' });
  }

  const code = randomBytes(16).toString('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  const scope = typeof params.scope === 'string' && params.scope.trim() ? params.scope.trim() : 'profile';
  const redirectUri = (typeof params.redirect_uri === 'string' && params.redirect_uri) || effectiveClientId;
  const metadataEndpoint = getMetadataEndpoint(req);
  const profile = await buildIndieAuthProfile(req);

  await db.execute({
    sql: 'INSERT INTO oauth_codes (code, client_id, redirect_uri, scope, did, dpop_jwk, expires_at, format, me, metadata_endpoint, profile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    args: [code, effectiveClientId, redirectUri, scope, req.user.did, params.code_challenge || '', expiresAt, 'indieauth', meUrl, metadataEndpoint, JSON.stringify(profile)],
  });

  await rememberApprovedClient(req.user.did, effectiveClientId);

  res.json({
    token: JSON.stringify({
      code,
      metadata_endpoint: metadataEndpoint,
    }),
  });
});

router.post('/disconnect', async (req, res) => {
  setAssertionCorsHeaders(req, res);
  res.setHeader('Cache-Control', 'no-store');

  if (!validateWebIdentityRequest(req)) {
    return res.status(400).json({ error: 'InvalidRequest', message: 'Missing Sec-Fetch-Dest: webidentity' });
  }

  if (!req.session) {
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }

  const origin = req.get('origin');
  let effectiveClientId;
  try {
    effectiveClientId = normalizeClientId(req.body.client_id, origin);
  } catch (err) {
    return res.status(400).json({ error: 'InvalidRequest', message: err.message });
  }

  await forgetApprovedClient(req.user.did, effectiveClientId);
  res.json({});
});

export default router;
