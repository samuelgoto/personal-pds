import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { db, setUpForTesting, create } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import * as cryptoAtp from '@atproto/crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import nock from 'nock';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3008;
const HOST = `http://localhost:${PORT}`;
const HANDLE_VAR = `localhost`;


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
  const password = 'oauth-pass';

  beforeAll(async () => {
    // Silence console for clean test output
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    // Mock client metadata fetches
    nock('https://client.example.com')
      .persist()
      .get('/meta.json')
      .reply(200, {
        client_id: 'https://client.example.com/meta.json',
        client_name: 'Example Client',
        redirect_uris: ['https://client.example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'atproto',
        token_endpoint_auth_method: 'none',
        dpop_bound_access_tokens: true
      });

    nock('http://localhost')
      .persist()
      .get('/client-metadata.json')
      .reply(200, {
        client_id: 'http://localhost/client-metadata.json',
        redirect_uris: ['http://localhost/callback'],
        scope: 'atproto openid'
      });






    process.env.PASSWORD = password;
    process.env.HANDLE = `localhost:${PORT}`;
    const dbName = `oauth-${Date.now()}.db`;

    dbPath = path.join(__dirname, dbName);

    await setUpForTesting(`file:${dbPath}`); await create(); await setUpRepo();
    userDid = process.env.PDS_DID;

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));
  });

  afterAll(async () => {
    for (const client of wss.clients) {
      client.terminate();
    }
    wss.close();
    sequencer.close();
    db.close();
    await new Promise((resolve) => server.close(resolve));
    nock.cleanAll();
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
      // Nuance: Issuer matches process.env.HANDLE if provided, otherwise derived from request
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

    test('Authorize with request_uri (PAR flow) resolves correctly', async () => {
      // 1. Push the request (PAR)
      const fullScope = "atproto blob:*/* repo?collection=app.bsky.feed.post&action=create repo?collection=app.bsky.actor.status repo?collection=app.bsky.graph.block repo?collection=app.bsky.graph.follow rpc:app.bsky.actor.getProfile?aud=did:web:api.bsky.app%23bsky_appview rpc:app.bsky.actor.getProfiles?aud=did:web:api.bsky.app%23bsky_appview include:place.stream.authFull rpc:com.atproto.moderation.createReport?aud=* repo?collection=place.stream.broadcast.origin repo?collection=place.stream.broadcast.syndication repo?collection=place.stream.chat.gate repo?collection=place.stream.chat.message repo?collection=place.stream.chat.profile repo?collection=place.stream.key repo?collection=place.stream.live.recommendations repo?collection=place.stream.live.teleport repo?collection=place.stream.livestream repo?collection=place.stream.metadata.configuration repo?collection=place.stream.moderation.permission repo?collection=place.stream.multistream.target repo?collection=place.stream.segment repo?collection=place.stream.server.settings";
      
      const params = new URLSearchParams();
      params.append('client_id', client_id);
      params.append('redirect_uri', redirect_uri);
      params.append('scope', fullScope);
      params.append('state', 'stream-place-state');
      params.append('code_challenge', 'challenge');
      params.append('code_challenge_method', 'S256');

      const parRes = await axios.post(`${HOST}/oauth/par`, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      const request_uri = parRes.data.request_uri;

      // 2. Perform the GET /oauth/authorize with the request_uri
      const authRes = await axios.get(`${HOST}/oauth/authorize`, {
        params: {
          client_id,
          request_uri
        }
      });

      expect(authRes.status).toBe(200);
      expect(authRes.data).toContain('Example Client');
      expect(authRes.data).toContain(client_id);
      expect(authRes.data).toContain('value="stream-place-state"');
      // Nuance: Verify that the extensive scope is correctly passed through and handled in the form
      expect(authRes.data).toContain('value="' + fullScope + '"');
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

      // Nuance: Verify token claims
      const decoded = jwt.decode(accessToken);
      expect(decoded.iss).toBe(HOST);
      expect(decoded.aud).toContain(`did:web:${HOST.replace(/^https?:\/\//, '')}`);
      expect(decoded.aud).toContain(client_id);
      expect(decoded.sub).toBe(userDid);

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

    test('ID Token contains correct audience (client_id)', async () => {
      const my_client_id = 'http://localhost/client-metadata.json';
      const my_redirect_uri = 'http://localhost/callback';
      
      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

      // 1. Authorize with openid scope
      const authRes = await axios.post(`${HOST}/oauth/authorize`, new URLSearchParams({
        client_id: my_client_id,
        redirect_uri: my_redirect_uri,
        scope: 'atproto openid',
        state: 'test-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        password: password
      }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        maxRedirects: 0,
        validateStatus: s => s === 302
      });

      const code = new URL(authRes.headers.location).searchParams.get('code');

      // 2. Exchange for tokens
      const { generateKeyPairSync } = await import('crypto');
      const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      const dpopJwk = publicKey.export({ format: 'jwk' });
      const dpopHeader = jwt.sign({ htu: `${HOST}/oauth/token`, htm: 'POST', iat: Math.floor(Date.now()/1000), jti: '1' }, privateKey, { algorithm: 'ES256', header: { typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk } });

      const tokenRes = await axios.post(`${HOST}/oauth/token`, new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: my_redirect_uri,
        client_id: my_client_id,
        code_verifier: codeVerifier
      }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'DPoP': dpopHeader }
      });

      expect(tokenRes.data.id_token).toBeDefined();
      const decodedId = jwt.decode(tokenRes.data.id_token);
      
      // Nuance: ID Token audience MUST be the client_id
      expect(decodedId.aud).toBe(my_client_id);
      expect(decodedId.iss).toBe(HOST);
    });

    test('Scope Enforcement: Token with "openid" scope should be denied "atproto" operations', async () => {
      const my_client_id = 'http://localhost/client-metadata.json';
      const my_redirect_uri = 'http://localhost/callback';
      
      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

      // 1. Authorize with ONLY openid scope
      const authRes = await axios.post(`${HOST}/oauth/authorize`, new URLSearchParams({
        client_id: my_client_id,
        redirect_uri: my_redirect_uri,
        scope: 'openid',
        state: 'test-state',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        password: password
      }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        maxRedirects: 0,
        validateStatus: s => s === 302
      });

      const code = new URL(authRes.headers.location).searchParams.get('code');

      // 2. Exchange for tokens
      const { generateKeyPairSync } = await import('crypto');
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const dpopJwk = publicKey.export({ format: 'jwk' });
      const dpopHeader = jwt.sign({ htu: `${HOST}/oauth/token`, htm: 'POST', iat: Math.floor(Date.now()/1000), jti: '1' }, privateKey, { algorithm: 'ES256', header: { typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk } });

      const tokenRes = await axios.post(`${HOST}/oauth/token`, new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: my_redirect_uri,
        client_id: my_client_id,
        code_verifier: codeVerifier
      }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'DPoP': dpopHeader }
      });

      const accessToken = tokenRes.data.access_token;

      // 3. Attempt to access atproto protected route
      const protectedDpop = jwt.sign({ htu: `${HOST}/xrpc/com.atproto.server.getSession`, htm: 'GET', iat: Math.floor(Date.now()/1000), jti: '2' }, privateKey, { algorithm: 'ES256', header: { typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk } });
      
      const sessionRes = await axios.get(`${HOST}/xrpc/com.atproto.server.getSession`, {
        headers: {
            'Authorization': `DPoP ${accessToken}`,
            'DPoP': protectedDpop
        },
        validateStatus: s => true
      });

      expect(sessionRes.status).toBe(403);
      expect(sessionRes.data.error).toBe('InsufficientScope');
    });

    test('Scope Enforcement: Token with "atproto" scope should be granted access', async () => {
        const my_client_id = 'http://localhost/client-metadata.json';
        const my_redirect_uri = 'http://localhost/callback';
        
        const codeVerifier = randomBytes(32).toString('base64url');
        const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  
        // 1. Authorize with atproto scope
        const authRes = await axios.post(`${HOST}/oauth/authorize`, new URLSearchParams({
          client_id: my_client_id,
          redirect_uri: my_redirect_uri,
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
  
        const code = new URL(authRes.headers.location).searchParams.get('code');
  
        // 2. Exchange for tokens
        const { generateKeyPairSync } = await import('crypto');
        const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const dpopJwk = publicKey.export({ format: 'jwk' });
        const dpopHeader = jwt.sign({ htu: `${HOST}/oauth/token`, htm: 'POST', iat: Math.floor(Date.now()/1000), jti: '1' }, privateKey, { algorithm: 'ES256', header: { typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk } });
  
        const tokenRes = await axios.post(`${HOST}/oauth/token`, new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: my_redirect_uri,
          client_id: my_client_id,
          code_verifier: codeVerifier
        }).toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'DPoP': dpopHeader }
        });
  
        const accessToken = tokenRes.data.access_token;
  
        // 3. Attempt to access atproto protected route
        const protectedDpop = jwt.sign({ htu: `${HOST}/xrpc/com.atproto.server.getSession`, htm: 'GET', iat: Math.floor(Date.now()/1000), jti: '2' }, privateKey, { algorithm: 'ES256', header: { typ: 'dpop+jwt', alg: 'ES256', jwk: dpopJwk } });
        
        const sessionRes = await axios.get(`${HOST}/xrpc/com.atproto.server.getSession`, {
          headers: {
              'Authorization': `DPoP ${accessToken}`,
              'DPoP': protectedDpop
          }
        });
  
        expect(sessionRes.status).toBe(200);
        expect(sessionRes.data.did).toBe(userDid);
      });

    test('checkAccountStatus returns valid JSON and correct status', async () => {
      // This is a public endpoint used by many clients during login flow
      const res = await axios.get(`${HOST}/xrpc/com.atproto.server.checkAccountStatus`);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('application/json');
      expect(res.data.activated).toBe(true);
      expect(res.data.repoCommit).toBeDefined();
    });

    test('auth failure returns JSON error (not HTML)', async () => {
      // Attempt to access a protected route without a token
      const res = await axios.get(`${HOST}/xrpc/com.atproto.server.getSession`, {
        validateStatus: s => s === 401
      });
      
      expect(res.status).toBe(401);
      // Nuance: Verify the response is JSON, which avoids "invalid character '<'" errors in clients
      expect(res.headers['content-type']).toContain('application/json');
      expect(res.data.error).toBe('AuthenticationRequired');
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

  describe('Advanced OAuth Features (JARM & private_key_jwt)', () => {
    test('JARM: should return a signed JWT response when requested by client', async () => {
      const client_id = 'https://jarm-client.com/meta.json';
      const redirect_uri = 'https://jarm-client.com/callback';
      
      nock('https://jarm-client.com')
        .persist()
        .get('/meta.json')
        .reply(200, {
          client_id,
          redirect_uris: [redirect_uri],
          authorization_signed_response_alg: 'RS256'
        });

      const res = await axios.post(`${HOST}/oauth/authorize`, new URLSearchParams({
        client_id,
        redirect_uri,
        password,
        state: 'jarm-test',
        code_challenge: 'any',
        code_challenge_method: 'S256'
      }).toString(), { maxRedirects: 0, validateStatus: s => s === 302 });

      const redirectUrl = new URL(res.headers.location);
      // It might be in fragment if response_mode was fragment, but here it's default (query)
      const responseJwt = redirectUrl.searchParams.get('response') || new URLSearchParams(redirectUrl.hash.slice(1)).get('response');
      expect(responseJwt).not.toBeNull();

      const decoded = jwt.decode(responseJwt);
      expect(decoded.iss).toBe(HOST);
      expect(decoded.aud).toBe(client_id);
      expect(decoded.state).toBe('jarm-test');
      expect(decoded.code).toBeDefined();
    });

    test('private_key_jwt: should authenticate client using signed assertion', async () => {
      const { generateKeyPairSync } = await import('crypto');
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      
      const client_id = 'https://secure-client.com/metadata.json';
      const jwks_uri = 'https://secure-client.com/jwks.json';
      const kid = 'test-key-id';

      const jwks = {
        keys: [{
          ...publicKey.export({ format: 'jwk' }),
          kid,
          alg: 'ES256',
          use: 'sig'
        }]
      };

      nock('https://secure-client.com')
        .persist()
        .get('/metadata.json').reply(200, {
          client_id,
          redirect_uris: ['https://secure-client.com/callback'],
          token_endpoint_auth_method: 'private_key_jwt',
          jwks_uri
        })
        .get('/jwks.json').reply(200, jwks);

      // 1. Create a fake code in DB
      const code = 'secure-code';
      await db.execute({
        sql: 'INSERT INTO oauth_codes (code, client_id, redirect_uri, scope, did, dpop_jwk, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        args: [code, client_id, 'https://secure-client.com/callback', 'atproto', 'did:plc:fake', '', Math.floor(Date.now()/1000) + 600]
      });

      // 2. Create client_assertion
      const assertion = jwt.sign({
        iss: client_id,
        sub: client_id,
        aud: HOST, // Match what the PDS now expects
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 600,
        jti: 'assertion-id'
      }, privateKey, { algorithm: 'ES256', header: { kid, alg: 'ES256' } });

      // 3. Request token
      const res = await axios.post(`${HOST}/oauth/token`, new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://secure-client.com/callback',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion
      }).toString(), {
          validateStatus: s => true
      });

      expect(res.status).toBe(200);
      expect(res.data.access_token).toBeDefined();
    });
  });
});
