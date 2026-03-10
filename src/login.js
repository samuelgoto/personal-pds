import express from 'express';
import { escapeHtml, verifyPassword } from './util.js';
import { buildAccountPushPayload, getConfigUrl } from './fedcm.js';
import {
  clearSessionCookieHeader,
  createSession,
  destroySession,
  SESSION_TTL_SECONDS,
  setSessionCookie,
} from './session.js';

const router = express.Router();

const setLoginHeaders = (res, status) => {
  res.setHeader('Set-Login', status);
  res.setHeader('Login-Status', status);
};

function normalizeReturnTo(req, candidate) {
  if (typeof candidate !== 'string' || !candidate) return '/';
  if (candidate.startsWith('/')) return candidate;

  try {
    const url = new URL(candidate);
    if (url.origin === req.user.issuer) {
      return `${url.pathname}${url.search}${url.hash}`;
    }
  } catch {}

  return '/';
}

function renderLoggedOutPage({ returnTo = '/' } = {}) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Signed out</title>
</head>
<body>
  <script>
    const returnTo = ${JSON.stringify(returnTo)};
    (async () => {
      if (navigator.login && typeof navigator.login.setStatus === 'function') {
        try {
          await navigator.login.setStatus('logged-out');
        } catch {}
      }
      window.location.replace(returnTo);
    })();
  </script>
  <p>Signed out. Returning to <a href="${escapeHtml(returnTo)}">${escapeHtml(returnTo)}</a>.</p>
</body>
</html>
  `;
}

function renderLoginForm(req, { error = '', returnTo = '/', autoReturn = false } = {}) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PDS Login</title>
  <style>
    :root {
      --bg: #f3f5f7;
      --card: #ffffff;
      --ink: #111827;
      --muted: #4b5563;
      --line: #d1d5db;
      --accent: #0f172a;
      --danger: #b91c1c;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #dbeafe 0%, #f8fafc 45%, #eef2ff 100%);
      color: var(--ink);
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    main {
      width: min(420px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
    }
    h1 {
      margin: 0 0 10px;
      font-size: 1.7rem;
    }
    p {
      margin: 0 0 18px;
      color: var(--muted);
      line-height: 1.5;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
    }
    input {
      width: 100%;
      box-sizing: border-box;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px 14px;
      font: inherit;
      margin-bottom: 14px;
    }
    button {
      width: 100%;
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      font: inherit;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
    }
    .error {
      color: var(--danger);
      margin-bottom: 14px;
    }
    .meta {
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <main>
    <h1>Sign in to ${escapeHtml(req.user.handle)}</h1>
    <p>Creates a browser session for your PDS. If the browser supports it, this page also pushes IndieAuth account metadata with the Login Status API and prepares IdP registration for FedCM.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    <form method="POST" action="/login">
      <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
      <input type="hidden" name="auto_return" value="${autoReturn ? '1' : '0'}">
      <label for="password">PDS password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Sign in</button>
    </form>
    <p class="meta">Identity provider config URL: <code>${escapeHtml(getConfigUrl(req))}</code></p>
  </main>
</body>
</html>
  `;
}

function renderLoggedInPage(req, { title, message, returnTo, autoReturn, accountPushPayload }) {
  const configUrl = getConfigUrl(req);
  const escapedReturnTo = escapeHtml(returnTo || '/');
  const account = accountPushPayload.accounts[0];
  const displayName = escapeHtml(account?.name || req.user.handle);
  const handle = escapeHtml(req.user.handle);
  const picture = account?.picture ? `<img class="avatar" src="${escapeHtml(account.picture)}" alt="${displayName}">` : '<div class="avatar fallback" aria-hidden="true"></div>';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3f5f7;
      --card: #ffffff;
      --ink: #111827;
      --muted: #4b5563;
      --line: #d1d5db;
      --accent: #0f172a;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top, #dbeafe, #f8fafc 45%);
      color: var(--ink);
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    main {
      width: min(560px, 100%);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
    }
    h1 {
      margin: 0 0 12px;
      font-size: 1.6rem;
    }
    .hero {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 16px;
    }
    .avatar {
      width: 72px;
      height: 72px;
      border-radius: 999px;
      object-fit: cover;
      border: 1px solid var(--line);
      background: #dbeafe;
      flex: 0 0 auto;
    }
    .avatar.fallback {
      background: linear-gradient(135deg, #0f172a, #2563eb);
    }
    .eyebrow {
      margin: 0;
      color: var(--muted);
      font-size: 0.95rem;
    }
    p {
      margin: 0 0 16px;
      color: var(--muted);
      line-height: 1.5;
    }
    code {
      font-size: 0.9rem;
      word-break: break-all;
    }
    .actions {
      display: flex;
      gap: 12px;
      margin-top: 20px;
      flex-wrap: wrap;
    }
    a, button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 10px 16px;
      font: inherit;
      text-decoration: none;
      cursor: pointer;
    }
    .primary {
      background: var(--accent);
      color: #fff;
    }
    .secondary {
      background: #e5e7eb;
      color: var(--ink);
    }
    pre {
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      overflow: auto;
      font-size: 0.85rem;
      margin-top: 18px;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <main>
    <div class="hero">
      ${picture}
      <div>
        <p class="eyebrow">Welcome to your PDS</p>
        <h1>${displayName}</h1>
        <p>@${handle}</p>
      </div>
    </div>
    <p>${escapeHtml(message)}</p>
    <p>This page refreshes the browser sign-in state for <code>${escapeHtml(req.user.issuer)}</code> and, when supported, lets you register this PDS as an IndieAuth identity provider for FedCM.</p>
    <div class="actions">
      <button class="primary" id="register-fedcm" type="button" disabled>Register PDS</button>
      <a class="secondary" href="${escapedReturnTo}">Continue</a>
      <form method="POST" action="/logout">
        <input type="hidden" name="return_to" value="${escapedReturnTo}">
        <button class="secondary" type="submit">Log out</button>
      </form>
    </div>
    <pre id="fedcm-status">Refreshing browser sign-in state...</pre>
  </main>
  <script>
    const returnTo = ${JSON.stringify(returnTo || '/')};
    const configUrl = ${JSON.stringify(configUrl)};
    const shouldAutoReturn = ${autoReturn ? 'true' : 'false'};
    const statusNode = document.getElementById('fedcm-status');
    const registerButton = document.getElementById('register-fedcm');
    const accountPushPayload = ${JSON.stringify(accountPushPayload)};
    const statusMessages = [];
    window.__fedcmLoginStatusResult = null;
    window.__fedcmRegistrationResult = null;

    function renderStatus() {
      statusNode.textContent = statusMessages.join('\\n');
    }

    async function pushLoginStatus() {
      if (navigator.login && typeof navigator.login.setStatus === 'function') {
        try {
          await navigator.login.setStatus('logged-in', accountPushPayload);
          window.__fedcmLoginStatusResult = true;
          statusMessages.push('navigator.login.setStatus("logged-in", ...) succeeded.');
          registerButton.disabled = false;
          if (shouldAutoReturn) {
            statusMessages.push('Returning to ' + returnTo + '...');
            renderStatus();
            window.location.replace(returnTo);
            return;
          }
        } catch (err) {
          window.__fedcmLoginStatusResult = false;
          statusMessages.push('navigator.login.setStatus failed: ' + err.message);
        }
      } else {
        window.__fedcmLoginStatusResult = false;
        statusMessages.push('navigator.login.setStatus is unavailable in this browser.');
      }
      renderStatus();
    }

    registerButton.addEventListener('click', async () => {
      registerButton.disabled = true;
      if (window.IdentityProvider && typeof IdentityProvider.register === 'function') {
        try {
          const registrationResult = await IdentityProvider.register(configUrl);
          window.__fedcmRegistrationResult = registrationResult;
          statusMessages.push('IdentityProvider.register(configUrl) returned: ' + registrationResult);
          if (registrationResult !== true) {
            registerButton.disabled = false;
          }
        } catch (err) {
          window.__fedcmRegistrationResult = false;
          statusMessages.push('IdentityProvider.register failed: ' + err.message);
          registerButton.disabled = false;
        }
      } else {
        window.__fedcmRegistrationResult = false;
        statusMessages.push('IdentityProvider.register is unavailable in this browser.');
        registerButton.disabled = false;
      }
      renderStatus();
    });

    void pushLoginStatus();
  </script>
</body>
</html>
  `;
}

async function renderSessionPage(req, res, { title, message, returnTo, autoReturn }) {
  const accountPushPayload = await buildAccountPushPayload(req);
  setLoginHeaders(res, 'logged-in');
  res.send(renderLoggedInPage(req, {
    title,
    message,
    returnTo,
    autoReturn,
    accountPushPayload,
  }));
}

router.get('/login', async (req, res) => {
  const returnTo = normalizeReturnTo(req, req.query.return_to);
  const autoReturn = req.query.auto_return === '1';

  if (req.session) {
    return renderSessionPage(req, res, {
      title: 'Already signed in',
      message: 'Your PDS session is active.',
      returnTo,
      autoReturn,
    });
  }

  res.send(renderLoginForm(req, { returnTo, autoReturn }));
});

router.post('/login', async (req, res) => {
  const returnTo = normalizeReturnTo(req, req.body.return_to);
  const autoReturn = req.body.auto_return === '1';

  if (!verifyPassword(req.body.password, req.user.password)) {
    return res.status(401).send(renderLoginForm(req, {
      error: 'Invalid password.',
      returnTo,
      autoReturn,
    }));
  }

  const { sessionId } = await createSession(req.user);
  setSessionCookie(res, sessionId, SESSION_TTL_SECONDS);
  return renderSessionPage(req, res, {
    title: 'Signed in',
    message: 'Browser session created. Your PDS is ready to refresh browser sign-in state and, if you want, register as a FedCM identity provider.',
    returnTo,
    autoReturn,
  });
});

async function handleLogout(req, res) {
  const returnTo = normalizeReturnTo(req, req.method === 'GET' ? req.query.return_to : req.body.return_to);
  await destroySession(req);
  clearSessionCookieHeader(res);
  setLoginHeaders(res, 'logged-out');
  res.send(renderLoggedOutPage({ returnTo }));
}

router.get('/logout', handleLogout);
router.post('/logout', handleLogout);

export default router;
