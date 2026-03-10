import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { db, create, setUpForTesting } from '../src/db.js';
import { setUpRepo } from '../src/repo.js';
import { sequencer } from '../src/sequencer.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3011;
const HOST = `http://localhost:${PORT}`;

describe('FedCM identity provider support', () => {
  let server;
  let dbPath;

  beforeAll(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    process.env.PASSWORD = 'fedcm-pass';
    process.env.HANDLE = 'localhost.test';

    const dbName = `fedcm-${Date.now()}.db`;
    dbPath = path.join(__dirname, dbName);

    await setUpForTesting(`file:${dbPath}`);
    await create();
    await setUpRepo();

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

    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('publishes FedCM discovery and config documents', async () => {
    const wellKnown = await axios.get(`${HOST}/.well-known/web-identity`);
    expect(wellKnown.status).toBe(200);
    expect(wellKnown.data.provider_urls).toEqual([`${HOST}/config.json`]);

    const config = await axios.get(`${HOST}/config.json`);
    expect(config.status).toBe(200);
    expect(config.data.login_url).toBe(`${HOST}/login`);
    expect(config.data.id_assertion_endpoint).toBe(`${HOST}/assertion`);
    expect(config.data.types).toEqual(['indieauth']);

    const profile = await axios.get(`${HOST}/profile`);
    expect(profile.status).toBe(200);
    expect(profile.headers.link).toContain(`${HOST}/.well-known/oauth-authorization-server`);
    expect(profile.data).toContain('rel="indieauth-metadata"');
  });

  test('login page creates a PDS browser session and emits login status hooks', async () => {
    const response = await axios.post(
      `${HOST}/login`,
      new URLSearchParams({ password: process.env.PASSWORD, return_to: '/dashboard' }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    expect(response.status).toBe(200);
    expect(response.headers['set-cookie'][0]).toContain('pds_session=');
    expect(response.headers['set-cookie'][0]).toContain('SameSite=None');
    expect(response.headers['set-cookie'][0]).toContain('Secure');
    expect(response.headers['set-login']).toBe('logged-in');
    expect(response.data).toContain("navigator.login.setStatus('logged-in'");
    expect(response.data).toContain('window.__fedcmLoginStatusResult');
    expect(response.data).not.toContain('Register PDS');
  });

  test('accounts endpoint requires a browser session and returns pushed account metadata', async () => {
    const login = await axios.post(
      `${HOST}/login`,
      new URLSearchParams({ password: process.env.PASSWORD }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );
    const cookie = login.headers['set-cookie'][0].split(';')[0];

    const unauthorized = await axios.get(`${HOST}/accounts`, {
      headers: { 'Sec-Fetch-Dest': 'webidentity' },
      validateStatus: () => true,
    });
    expect(unauthorized.status).toBe(401);

    const accounts = await axios.get(`${HOST}/accounts`, {
      headers: {
        Cookie: cookie,
        'Sec-Fetch-Dest': 'webidentity',
      },
    });

    expect(accounts.status).toBe(200);
    expect(accounts.data.accounts).toHaveLength(1);
    expect(accounts.data.accounts[0].id).toBe(`${HOST}/profile`);
    expect(accounts.data.accounts[0].name).toBe('@localhost.test');
    expect(accounts.data.accounts[0].email).toBe('@localhost.test');
    expect(accounts.data.accounts[0]).not.toHaveProperty('username');
    expect(accounts.data.accounts[0].approved_clients).toEqual([]);
  });

  test('assertion endpoint returns an OAuth authorization code and records approved clients', async () => {
    const login = await axios.post(
      `${HOST}/login`,
      new URLSearchParams({ password: process.env.PASSWORD }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );
    const cookie = login.headers['set-cookie'][0].split(';')[0];
    const clientId = 'https://rp.example/client-metadata.json';
    const codeVerifier = 'fedcm-code-verifier';
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

    const assertion = await axios.post(
      `${HOST}/assertion`,
      new URLSearchParams({
        client_id: clientId,
        account_id: `${HOST}/profile`,
        params: JSON.stringify({
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          scope: 'profile email',
        }),
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: cookie,
          Origin: 'https://rp.example',
          'Sec-Fetch-Dest': 'webidentity',
        },
      }
    );

    expect(assertion.status).toBe(200);
    const tokenPayload = JSON.parse(assertion.data.token);
    expect(tokenPayload.code).toMatch(/^[a-f0-9]{32}$/);
    expect(tokenPayload.metadata_endpoint).toBe(`${HOST}/.well-known/oauth-authorization-server`);
    expect(assertion.headers['access-control-allow-origin']).toBe('https://rp.example');

    const tokenResponse = await axios.post(
      `${HOST}/oauth/token`,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: tokenPayload.code,
        client_id: clientId,
        code_verifier: codeVerifier,
      }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.data.me).toBe(`${HOST}/profile`);
    expect(tokenResponse.data.profile).toHaveProperty('url', `${HOST}/profile`);
    expect(tokenResponse.data).toHaveProperty('access_token');
    expect(tokenResponse.data).not.toHaveProperty('id_token');

    const accounts = await axios.get(`${HOST}/accounts`, {
      headers: {
        Cookie: cookie,
        'Sec-Fetch-Dest': 'webidentity',
      },
    });
    expect(accounts.data.accounts[0].approved_clients).toContain(clientId);

    const disconnect = await axios.post(
      `${HOST}/disconnect`,
      new URLSearchParams({ client_id: clientId }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: cookie,
          Origin: 'https://rp.example',
          'Sec-Fetch-Dest': 'webidentity',
        },
      }
    );
    expect(disconnect.status).toBe(200);

    const accountsAfterDisconnect = await axios.get(`${HOST}/accounts`, {
      headers: {
        Cookie: cookie,
        'Sec-Fetch-Dest': 'webidentity',
      },
    });
    expect(accountsAfterDisconnect.data.accounts[0].approved_clients).toEqual([]);
  });
});
