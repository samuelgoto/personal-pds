import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { initDb, createDb, setDb } from '../src/db.js';
import { sequencer } from '../src/sequencer.js';
import * as cryptoAtp from '@atproto/crypto';
import { formatDid } from '../src/util.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { runFullSetup } from '../src/setup.js';
import { createHash, randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3008;
const HOST = `http://localhost:${PORT}`;
const DOMAIN = `localhost`;


/**
 * ATProto OAuth Regression Tests
 * 
 * References:
 * - https://atproto.com/specs/oauth
 * - https://docs.bsky.app/docs/advanced-guides/oauth-client
 * - https://github.com/bluesky-social/proposals/blob/main/0004-oauth/README.md
 */
describe('ATProto OAuth Implementation Tests', () => {
  let server;
  let userDid;
  let testDb;
  let dbPath;
  const password = 'oauth-test-pass';

  beforeAll(async () => {
    // Silence console for clean test output
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    process.env.PASSWORD = password;
    process.env.DOMAIN = `localhost:${PORT}`;
    const dbName = `oauth-${Date.now()}.db`;

    dbPath = path.join(__dirname, dbName);
    testDb = createDb(`file:${dbPath}`);
    setDb(testDb);

    await runFullSetup({ db: testDb, skipPlc: true });
    userDid = formatDid(DOMAIN);

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    for (const client of wss.clients) {
      client.terminate();
    }
    wss.close();
    sequencer.close();
    testDb.close();
    await new Promise((resolve) => server.close(resolve));
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  describe('Discovery Metadata', () => {
    test('oauth-authorization-server matches exact spec requirements', async () => {
      const res = await axios.get(`${HOST}/.well-known/oauth-authorization-server`);
      expect(res.status).toBe(200);
      
      const meta = res.data;
      // Nuance: Issuer matches process.env.DOMAIN if provided, otherwise derived from request
      expect(meta.issuer).toBe(HOST);
      
      // Nuance: Required for modern atproto-labs/oauth libraries
      expect(meta.client_id_metadata_document_supported).toBe(true);
      expect(meta.authorization_response_iss_parameter_supported).toBe(true);
      expect(meta.token_endpoint_auth_methods_supported).toContain('private_key_jwt');
      
      // Nuance: Must support PAR
      expect(meta.pushed_authorization_request_endpoint).toBe(`${HOST}/oauth/par`);
      expect(meta.require_pushed_authorization_requests).toBe(true);
      
      // Nuance: JWKS for signature verification
      expect(meta.jwks_uri).toBe(`${HOST}/.well-known/jwks.json`);
    });

    test('oauth-protected-resource satisfies strict Zod schemas', async () => {
      const res = await axios.get(`${HOST}/.well-known/oauth-protected-resource`);
      expect(res.status).toBe(200);
      
      const meta = res.data;
      // Nuance: Exactly one AS entry
      expect(meta.authorization_servers).toHaveLength(1);
      expect(meta.authorization_servers[0]).toBe(HOST);
      
      // Nuance: 'header' instead of 'authorization_header' (Zod enum requirement)
      expect(meta.bearer_methods_supported).toContain('header');
      expect(meta.bearer_methods_supported).not.toContain('authorization_header');
    });

    test('jwks.json returns valid ES256K public key', async () => {
      const res = await axios.get(`${HOST}/.well-known/jwks.json`);
      expect(res.status).toBe(200);
      expect(res.data.keys).toHaveLength(1);
      expect(res.data.keys[0].kty).toBe('EC');
      expect(res.data.keys[0].crv).toBe('secp256k1');
    });
  });

  describe('Authorization Flow', () => {
    const client_id = 'https://client.example.com/meta.json';
    const redirect_uri = 'https://client.example.com/callback';

    test('PAR (Pushed Authorization Request) accepts form-encoded data', async () => {
      const params = new URLSearchParams();
      params.append('client_id', client_id);
      params.append('redirect_uri', redirect_uri);
      params.append('scope', 'atproto');
      params.append('response_type', 'code');
      params.append('code_challenge', 'challenge');
      params.append('code_challenge_method', 'S256');

      const res = await axios.post(`${HOST}/oauth/par`, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      expect(res.status).toBe(201);
      expect(res.data.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    });

    test('Full login flow with PKCE and DPoP binding', async () => {
      // 1. Setup PKCE
      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

      // 2. Authorize (Skip the GET UI, go straight to POST approval)
      const authRes = await axios.post(`${HOST}/oauth/authorize`, new URLSearchParams({
        client_id,
        redirect_uri,
        scope: 'atproto',
        state: 'test-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        password: password
      }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        maxRedirects: 0,
        validateStatus: s => s === 302
      });

      const redirectUrl = new URL(authRes.headers.location);
      const code = redirectUrl.searchParams.get('code');
      // Nuance: Redirect must include 'iss'
      expect(redirectUrl.searchParams.get('iss')).toBe(HOST);
      expect(code).toBeDefined();

      // 3. Create DPoP Keypair for Token request (Using RSA for easy test verification)
      const { generateKeyPairSync } = await import('crypto');
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const dpopJwk = publicKey.export({ format: 'jwk' });

      const createDpopHeader = async (htu, htm, access_token = null) => {
        const payload = {
            iat: Math.floor(Date.now() / 1000),
            jti: randomBytes(12).toString('hex'),
            htu,
            htm
        };
        if (access_token) {
            payload.ath = createHash('sha256').update(access_token).digest('base64url');
        }
        const header = { typ: 'dpop+jwt', alg: 'RS256', jwk: dpopJwk };
        return jwt.sign(payload, privateKey, { algorithm: 'RS256', header });
      };

      const dpopHeader = await createDpopHeader(`${HOST}/oauth/token`, 'POST');

      // 4. Exchange code for token
      const tokenRes = await axios.post(`${HOST}/oauth/token`, new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id,
        code_verifier: codeVerifier
      }).toString(), {
        headers: { 
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': dpopHeader
        }
      });

      expect(tokenRes.status).toBe(200);
      expect(tokenRes.data.access_token).toBeDefined();
      expect(tokenRes.data.token_type).toBe('DPoP');
      // Nuance: Must include 'did' in token response
      expect(tokenRes.data.did).toBe(userDid);

      const accessToken = tokenRes.data.access_token;

      // 5. Verify DPoP-bound access to protected route
      const protectedDpop = await createDpopHeader(`${HOST}/xrpc/com.atproto.server.getSession`, 'GET');
      const sessionRes = await axios.get(`${HOST}/xrpc/com.atproto.server.getSession`, {
        headers: {
            'Authorization': `DPoP ${accessToken}`,
            'DPoP': protectedDpop
        }
      });
      expect(sessionRes.status).toBe(200);
      expect(sessionRes.data.did).toBe(userDid);
    });
  });

  describe('DPoP Nuances', () => {
    test('htu validation is lenient with trailing slashes', async () => {
        const { generateKeyPairSync } = await import('crypto');
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
          modulusLength: 2048,
        });
        const dpopJwk = publicKey.export({ format: 'jwk' });
        
        // Generate header with trailing slash even if endpoint doesn't have it
        const htuWithSlash = `${HOST}/oauth/token/`;
        const payload = {
            iat: Math.floor(Date.now() / 1000),
            jti: 'test-jti',
            htu: htuWithSlash,
            htm: 'POST'
        };
        const header = { typ: 'dpop+jwt', alg: 'RS256', jwk: dpopJwk };
        const dpop = jwt.sign(payload, privateKey, { algorithm: 'RS256', header });

        const res = await axios.post(`${HOST}/oauth/token`, new URLSearchParams({
            grant_type: 'authorization_code',
            code: 'invalid',
            client_id: 'any'
        }).toString(), {
            headers: { 'DPoP': dpop },
            validateStatus: s => s === 400
        });

        // Error should be invalid_grant, NOT DPoP verification failed (which would be 401/400 with message)
        expect(res.data.error).toBe('invalid_grant');
    });
  });
});
