import '../env.js';
import { test, chromium } from '@playwright/test';
import http from 'http';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import axios from 'axios';
import { createHash } from 'crypto';
import app, { wss } from '../../src/server.js';
import { create, db, setUpForTesting } from '../../src/db.js';
import { setUpRepo } from '../../src/repo.js';
import { sequencer } from '../../src/sequencer.js';

const IDP_PORT = 3210;
const RP_PORT = 3211;
const IDP_ORIGIN = `http://localhost:${IDP_PORT}`;
const RP_ORIGIN = `http://localhost:${RP_PORT}`;
const ME_URL = `${IDP_ORIGIN}/profile`;
const IDP_CONFIG_URL = `${IDP_ORIGIN}/config.json`;
const RP_CODE_VERIFIER = 'playwright-fedcm-code-verifier';
const RP_CODE_CHALLENGE = createHash('sha256').update(RP_CODE_VERIFIER).digest('base64url');

async function attachFedCmCdp(context, page, pageLogs, label) {
  const cdp = await context.newCDPSession(page);
  await cdp.send('FedCm.enable', { disableRejectionDelay: true });
  await cdp.send('FedCm.resetCooldown');
  cdp.on('FedCm.dialogShown', (event) => pageLogs.push(`[${label}:dialogShown] ${JSON.stringify(event)}`));
  cdp.on('FedCm.dialogClosed', (event) => pageLogs.push(`[${label}:dialogClosed] ${JSON.stringify(event)}`));
  cdp.on('FedCm.accountsDisplayed', (event) => pageLogs.push(`[${label}:accountsDisplayed] ${JSON.stringify(event)}`));
  cdp.on('FedCm.accountSelected', (event) => pageLogs.push(`[${label}:accountSelected] ${JSON.stringify(event)}`));
  cdp.on('FedCm.dialogShown', async (event) => {
    if (event.dialogType === 'ConfirmIdpLogin') {
      try {
        await cdp.send('FedCm.clickDialogButton', {
          dialogId: event.dialogId,
          dialogButton: 'ConfirmIdpLoginContinue',
        });
      } catch (err) {
        pageLogs.push(`[${label}:clickDialogButton:error] ${err.message}`);
      }
      return;
    }

    if (event.accounts?.length) {
      try {
        await cdp.send('FedCm.selectAccount', {
          dialogId: event.dialogId,
          accountIndex: 0,
        });
      } catch (err) {
        pageLogs.push(`[${label}:selectAccount:error] ${err.message}`);
      }
    }
  });
  return cdp;
}

function createRpServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, RP_ORIGIN);

    if (req.method === 'GET' && url.pathname === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FedCM RP</title>
</head>
<body>
  <button id="login">Sign in with FedCM</button>
  <pre id="result">idle</pre>
  <script>
    const result = document.getElementById('result');
    document.getElementById('login').addEventListener('click', async () => {
      result.textContent = 'requesting';
      try {
        const credential = await navigator.credentials.get({
          identity: {
            context: 'signin',
            mode: 'passive',
            providers: [{
              configURL: ${JSON.stringify(IDP_CONFIG_URL)},
              type: 'indieauth',
              clientId: ${JSON.stringify(RP_ORIGIN)},
              nonce: 'playwright-fedcm-nonce',
              params: {
                scope: 'profile email',
                code_challenge: ${JSON.stringify(RP_CODE_CHALLENGE)},
                code_challenge_method: 'S256'
              }
            }]
          }
        });

        if (!credential || !credential.token) {
          result.textContent = 'NO_CREDENTIAL';
          return;
        }

        let assertion;
        try {
          assertion = JSON.parse(credential.token);
        } catch (err) {
          result.textContent = 'ERROR:bad_assertion_payload';
          return;
        }

        const exchange = await fetch('/exchange', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code: assertion.code,
            metadata_endpoint: assertion.metadata_endpoint
          })
        });

        const data = await exchange.json();
        result.textContent = exchange.ok ? 'SIGNED_IN:' + data.me : 'ERROR:' + (data.message || data.error);
      } catch (err) {
        result.textContent = 'ERROR:' + err.name + ':' + err.message;
      }
    });
  </script>
</body>
</html>`);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/exchange') {
      const body = await new Promise((resolve) => {
        let data = '';
        req.on('data', (chunk) => {
          data += chunk.toString();
        });
        req.on('end', () => resolve(data));
      });

      const params = new URLSearchParams(body);
      try {
        const metadataEndpoint = params.get('metadata_endpoint') || '';
        const metadataResponse = await axios.get(metadataEndpoint);
        const tokenEndpoint = metadataResponse.data.token_endpoint;
        const tokenResponse = await axios.post(
          tokenEndpoint,
          new URLSearchParams({
            grant_type: 'authorization_code',
            code: params.get('code') || '',
            client_id: RP_ORIGIN,
            code_verifier: RP_CODE_VERIFIER,
          }).toString(),
          {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          }
        );
        const meResponse = await axios.get(tokenResponse.data.me);
        const linkHeader = meResponse.headers.link || '';
        const html = String(meResponse.data);
        const hasMetadataPointer = linkHeader.includes(metadataEndpoint) || html.includes(metadataEndpoint);

        if (!hasMetadataPointer) {
          throw new Error('me URL does not advertise the IndieAuth metadata endpoint');
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          me: tokenResponse.data.me,
          access_token: tokenResponse.data.access_token,
          profile: tokenResponse.data.profile,
        }));
      } catch (err) {
        res.statusCode = err.response?.status || 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(err.response?.data || { error: 'exchange_failed', message: err.message }));
      }
      return;
    }

    res.statusCode = 404;
    res.end('Not found');
  });
}

test.describe('FedCM browser flow', () => {
  let idpServer;
  let rpServer;
  let userDataDir;
  let serverLogs;

  test.beforeAll(async () => {
    serverLogs = [];
    process.env.PASSWORD = 'playwright-fedcm-pass';
    process.env.HANDLE = 'localhost';

    await setUpForTesting(`file:${path.join(os.tmpdir(), `playwright-fedcm-${Date.now()}.db`)}`);
    await create();
    await setUpRepo();

    idpServer = http.createServer((req, res) => {
      const url = new URL(req.url, IDP_ORIGIN);
      if (['/login', '/logout', '/accounts', '/assertion', '/disconnect', '/config.json', '/profile', '/.well-known/web-identity'].includes(url.pathname)) {
        serverLogs.push(`[IDP] ${req.method} ${url.pathname} origin=${req.headers.origin || ''} sec-fetch-dest=${req.headers['sec-fetch-dest'] || ''}`);
      }
      app(req, res);
    });
    idpServer.on('upgrade', (request, socket, head) => {
      const url = new URL(request.url, `http://${request.headers.host}`);
      if (url.pathname.startsWith('/xrpc/com.atproto.sync.subscribeRepos')) {
        wss.handleUpgrade(request, socket, head, (ws) => {
          wss.emit('connection', ws, request);
        });
      } else {
        socket.destroy();
      }
    });
    await new Promise((resolve) => idpServer.listen(IDP_PORT, resolve));

    rpServer = createRpServer();
    await new Promise((resolve) => rpServer.listen(RP_PORT, resolve));
  });

  test.afterAll(async () => {
    for (const client of wss.clients) {
      client.terminate();
    }
    wss.close();
    sequencer.close();
    await db.close();
    await new Promise((resolve) => idpServer.close(resolve));
    await new Promise((resolve) => rpServer.close(resolve));
    if (userDataDir) {
      await fs.rm(userDataDir, { recursive: true, force: true });
    }
  });

  test('signs into an RP with FedCM using an explicit configURL', async () => {
    test.slow();
    userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'playwright-fedcm-profile-'));
    const pageLogs = [];

    const context = await chromium.launchPersistentContext(userDataDir, {
      headless: true,
      args: [
        '--enable-features=FedCmIdPRegistration,FedCmLightweightMode,FedCmWithoutWellKnownEnforcement',
      ],
    });

    try {
      const idpPage = await context.newPage();
      idpPage.on('console', (msg) => pageLogs.push(`[IDP:${msg.type()}] ${msg.text()}`));
      idpPage.on('pageerror', (err) => pageLogs.push(`[IDP:pageerror] ${err.message}`));
      await idpPage.goto(`${IDP_ORIGIN}/login`);
      await idpPage.getByLabel('PDS password').fill(process.env.PASSWORD);
      await idpPage.getByRole('button', { name: 'Sign in' }).click();
      await idpPage.waitForFunction(() => window.__fedcmLoginStatusResult !== null, undefined, { timeout: 30000 });
      const loginStatusResult = await idpPage.evaluate(() => window.__fedcmLoginStatusResult);
      const loginStatusText = await idpPage.locator('#fedcm-status').textContent();
      if (loginStatusResult !== true) {
        throw new Error([
          `navigator.login.setStatus("logged-in", ...) did not succeed before the explicit configURL test.`,
          `Login status result: ${loginStatusResult}`,
          `Status text: ${loginStatusText}`,
          `Browser logs:`,
          ...pageLogs,
          `Server logs:`,
          ...serverLogs,
        ].join('\n'));
      }

      const rpPage = await context.newPage();
      rpPage.on('console', (msg) => pageLogs.push(`[RP:${msg.type()}] ${msg.text()}`));
      rpPage.on('pageerror', (err) => pageLogs.push(`[RP:pageerror] ${err.message}`));
      await attachFedCmCdp(context, rpPage, pageLogs, 'RP:CDP');

      await rpPage.goto(RP_ORIGIN);
      await rpPage.getByRole('button', { name: 'Sign in with FedCM' }).click();

      const deadline = Date.now() + 30000;
      let resultText = await rpPage.locator('#result').textContent();
      while (Date.now() < deadline && resultText !== `SIGNED_IN:${ME_URL}`) {
        await rpPage.waitForTimeout(250);
        resultText = await rpPage.locator('#result').textContent();
        if (resultText && resultText !== 'idle' && resultText !== 'requesting' && resultText.startsWith('ERROR:')) {
          break;
        }
      }

      if (resultText !== `SIGNED_IN:${ME_URL}`) {
        throw new Error([
          `Expected explicit-configURL FedCM login to succeed.`,
          `Received: ${resultText}`,
          `Browser logs:`,
          ...pageLogs,
          `Server logs:`,
          ...serverLogs,
        ].join('\n'));
      }
    } finally {
      await context.close();
    }
  });
});
