import express from 'express';
import { db } from './db.js';
import { createAccessToken, createIdToken, validateDpop, verifyToken } from './auth.js';
import { createHash, randomBytes, createECDH } from 'crypto';
import * as crypto from '@atproto/crypto';
import axios from 'axios';
import { getHost, getDidDoc } from './server.js';

const router = express.Router();

const validateClient = async (client_id, redirect_uri) => {
  try {
    const res = await axios.get(client_id);
    const metadata = res.data;
    if (!metadata.redirect_uris || !metadata.redirect_uris.includes(redirect_uri)) {
      throw new Error('Invalid redirect_uri');
    }
    return metadata;
  } catch (err) {
    console.error('Client validation failed:', err.message);
    return null;
  }
};

router.post('/oauth/par', async (req, res) => {
  const { client_id, redirect_uri } = req.body;
  if (redirect_uri) {
    await validateClient(client_id, redirect_uri);
  }
  const request_uri = `urn:ietf:params:oauth:request_uri:${randomBytes(16).toString('hex')}`;
  const expires_at = Math.floor(Date.now() / 1000) + 600; // 10 mins

  await db.execute({
    sql: 'INSERT INTO oauth_par_requests (request_uri, client_id, request_data, expires_at) VALUES (?, ?, ?, ?)',
    args: [request_uri, client_id, JSON.stringify(req.body), expires_at]
  });

  res.status(201).json({ request_uri, expires_in: 600 });
});

router.get('/oauth/authorize', async (req, res) => {
  let query = req.query;
  if (query.request_uri) {
    const par = await db.execute({
      sql: 'SELECT request_data FROM oauth_par_requests WHERE request_uri = ? AND expires_at > ?',
      args: [query.request_uri, Math.floor(Date.now() / 1000)]
    });
    if (par.rows.length > 0) {
      query = JSON.parse(par.rows[0].request_data);
    }
  }

  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, response_mode } = query;
  
  if (client_id.startsWith('http')) {
    await validateClient(client_id, redirect_uri);
  }

  res.send(`
    <html>
      <body>
        <h1>Authorize ${client_id}?</h1>
        <p>Scope: ${scope}</p>
        <form method="POST" action="/oauth/authorize">
          <input type="hidden" name="client_id" value="${client_id}">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="scope" value="${scope}">
          <input type="hidden" name="state" value="${state}">
          <input type="hidden" name="code_challenge" value="${code_challenge}">
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
          <input type="hidden" name="response_mode" value="${response_mode || ''}">
          <input type="password" name="password" placeholder="Your PDS Password" required>
          <button type="submit">Approve</button>
        </form>
      </body>
    </html>
  `);
});

router.post('/oauth/authorize', async (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, response_mode, password } = req.body;
  const user = req.user;

  if (!user || password !== user.password) {
    return res.status(401).send('Invalid password');
  }

  const code = randomBytes(16).toString('hex');
  const expires_at = Math.floor(Date.now() / 1000) + 600;

  await db.execute({
    sql: 'INSERT INTO oauth_codes (code, client_id, redirect_uri, scope, did, dpop_jwk, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    args: [code, client_id, redirect_uri, scope || 'atproto', user.did, code_challenge || '', expires_at]
  });

  const url = new URL(redirect_uri);
  const params = new URLSearchParams();
  params.set('code', code);
  if (state) params.set('state', state);
  
  params.set('iss', req.user.issuer);

  if (response_mode === 'fragment') {
    url.hash = params.toString();
  } else {
    params.forEach((v, k) => url.searchParams.set(k, v));
  }
  
  console.log(`[OAUTH] Redirecting to ${url.toString()}`);
  res.redirect(url.toString());
});

router.post('/oauth/token', async (req, res) => {
    const { grant_type, code, client_id, refresh_token, code_verifier } = req.body;
    const user = req.user;
    const issuer = user.issuer;

    const { jkt } = await validateDpop(req);

    if (grant_type === 'authorization_code') {
      const result = await db.execute({
        sql: 'SELECT * FROM oauth_codes WHERE code = ? AND client_id = ? AND expires_at > ?',
        args: [code, client_id, Math.floor(Date.now() / 1000)]
      });

      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      const row = result.rows[0];

      if (row.dpop_jwk) {
        if (!code_verifier) return res.status(400).json({ error: 'invalid_request', message: 'Missing code_verifier' });
        const hash = createHash('sha256').update(code_verifier).digest('base64url');
        if (hash !== row.dpop_jwk) {
            return res.status(400).json({ error: 'invalid_grant', message: 'PKCE verification failed' });
        }
      }

      const access_token = createAccessToken(row.did, user.handle, jkt, issuer, client_id);
      const new_refresh_token = randomBytes(32).toString('hex');

      await db.execute({
        sql: 'INSERT INTO oauth_refresh_tokens (token, client_id, did, scope, dpop_jwk, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        args: [new_refresh_token, client_id, row.did, row.scope, jkt, Math.floor(Date.now() / 1000) + 30 * 24 * 3600]
      });

      await db.execute({ sql: 'DELETE FROM oauth_codes WHERE code = ?', args: [code] });

      const response = {
        access_token,
        token_type: 'DPoP',
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: row.scope,
        sub: row.did,
        did: row.did
      };

      if (row.scope.includes('openid')) {
        response.id_token = await createIdToken(row.did, user.handle, client_id, issuer);
      }

      res.json(response);
    } else if (grant_type === 'refresh_token') {
       const result = await db.execute({
        sql: 'SELECT * FROM oauth_refresh_tokens WHERE token = ? AND client_id = ? AND expires_at > ?',
        args: [refresh_token, client_id, Math.floor(Date.now() / 1000)]
      });

      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      const row = result.rows[0];
      if (row.dpop_jwk !== jkt) {
        return res.status(400).json({ error: 'invalid_dpop_key' });
      }

      const access_token = createAccessToken(row.did, user.handle, jkt, issuer, client_id);
      const new_refresh_token = randomBytes(32).toString('hex');

      await db.execute({
        sql: 'UPDATE oauth_refresh_tokens SET token = ?, expires_at = ? WHERE token = ?',
        args: [new_refresh_token, Math.floor(Date.now() / 1000) + 30 * 24 * 3600, refresh_token]
      });

      const response = {
        access_token,
        token_type: 'DPoP',
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: row.scope,
        sub: row.did,
        did: row.did
      };

      if (row.scope.includes('openid')) {
        response.id_token = await createIdToken(row.did, user.handle, client_id, issuer);
      }

      res.json(response);
    } else {
      res.status(400).json({ error: 'unsupported_grant_type' });
    }
});

router.get('/.well-known/oauth-authorization-server', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const issuer = req.user.issuer;
  
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
    require_pushed_authorization_requests: true,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    scopes_supported: ['atproto'],
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'fragment'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_id_metadata_document', 'private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'ES256K'],
    dpop_signing_alg_values_supported: ['RS256', 'ES256', 'ES256K'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
    protected_resources: [issuer]
  });
});

router.get('/.well-known/oauth-protected-resource', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const issuer = req.user.issuer;

  res.json({
    resource: issuer,
    authorization_servers: [issuer],
    scopes_supported: ['atproto'],
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://atproto.com/specs/oauth'
  });
});

router.get('/.well-known/openid-configuration', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const issuer = req.user.issuer;

  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    scopes_supported: ['openid', 'atproto'],
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256']
  });
});

router.get('/.well-known/jwks.json', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  const user = req.user;
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(user.signing_key);
  const uncompressed = ecdh.getPublicKey();
  const x = uncompressed.slice(1, 33).toString('base64url');
  const y = uncompressed.slice(33, 65).toString('base64url');

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
  const did = keypair.did();

  res.json({
    keys: [{
      kty: 'EC',
      crv: 'secp256k1',
      x,
      y,
      use: 'sig',
      alg: 'ES256K',
      kid: did
    }]
  });
});

export default router;
