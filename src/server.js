import express from 'express';
import { db } from './db.js';
import { createToken, verifyToken, createAccessToken, createIdToken, validateDpop, getJkt } from './auth.js';
import { TursoStorage, getRootCid, maybeInitRepo } from './repo.js';
import { Repo, WriteOpAction, blocksToCarFile } from '@atproto/repo';
import * as crypto from '@atproto/crypto';
import { createHash, randomBytes, createPublicKey, createECDH } from 'crypto';
import { CID } from 'multiformats';
import { sequencer } from './sequencer.js';
import { WebSocketServer } from 'ws';
import axios from 'axios';
import { cborEncode, cborDecode, formatDid, createTid, createBlobCid, fixCids } from './util.js';

const app = express();
export const wss = new WebSocketServer({ noServer: true });

// Unify WebSocket handling via Sequencer
wss.on('connection', (ws, req) => {
  console.log('New firehose subscriber connected (via sequencer)');
  const url = new URL(req.url, `http://${req.headers.host}`);
  const cursor = url.searchParams.get('cursor');
  sequencer.addClient(ws, cursor ? parseInt(cursor, 10) : undefined);
});

// Remove broadcastRepoUpdate as it's handled by sequencer.sequenceEvent

// 1. CORS middleware (Absolute top)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP, atproto-accept-labelers, atproto-proxy-type, atproto-proxy, atproto-proxy-exp, atproto-content-type, x-bsky-topics, x-bsky-active-labelers');
  res.setHeader('Access-Control-Expose-Headers', 'atproto-content-type, atproto-proxy, atproto-proxy-exp, x-bsky-topics, x-bsky-active-labelers');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// 2. Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// 3. JSON parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/xrpc/com.atproto.server.describeServer', async (req, res) => {
  const pdsDid = (process.env.PDS_DID || '').trim();
  console.log(`[${new Date().toISOString()}] describeServer request from ${req.headers['user-agent'] || 'unknown'}. Returning did=${pdsDid}`);
  res.json({ availableUserDomains: [], did: pdsDid });
});

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
    // For single-user PDS, we might want to be lenient or strictly follow the spec
    // Let's assume the user knows what they are doing if it's their own server, 
    // but a real PDS must validate this.
    return null;
  }
};

app.post('/oauth/par', async (req, res) => {
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

app.get('/oauth/authorize', async (req, res) => {
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
  
  // Validate client metadata if possible
  if (client_id.startsWith('http')) {
    await validateClient(client_id, redirect_uri);
  }

  // Simple HTML for authorization
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

app.post('/oauth/authorize', async (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, response_mode, password } = req.body;
  const user = await getSingleUser(req);

  if (password !== user.password) {
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
  
  const host = getHost(req);
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production') ? 'https' : 'http';
  params.set('iss', `${protocol}://${host}`);

  if (response_mode === 'fragment') {
    url.hash = params.toString();
  } else {
    params.forEach((v, k) => url.searchParams.set(k, v));
  }
  
  res.redirect(url.toString());
});

app.post('/oauth/token', async (req, res) => {
  try {
    const { grant_type, code, redirect_uri, client_id, refresh_token, code_verifier } = req.body;
    const user = await getSingleUser(req);
    const host = getHost(req);
    const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production') ? 'https' : 'http';
    const issuer = `${protocol}://${host}`;

    // Validate DPoP
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

      // PKCE Validation
      if (row.dpop_jwk) { // We stored code_challenge in dpop_jwk column temporarily
        if (!code_verifier) return res.status(400).json({ error: 'invalid_request', message: 'Missing code_verifier' });
        const hash = createHash('sha256').update(code_verifier).digest('base64url');
        if (hash !== row.dpop_jwk) {
            return res.status(400).json({ error: 'invalid_grant', message: 'PKCE verification failed' });
        }
      }

      console.log(`Generating tokens for client_id: ${client_id}, issuer: ${issuer}`);
      const access_token = createAccessToken(row.did, user.handle, jkt, issuer, client_id);
      const new_refresh_token = randomBytes(32).toString('hex');

      await db.execute({
        sql: 'INSERT INTO oauth_refresh_tokens (token, client_id, did, scope, dpop_jwk, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        args: [new_refresh_token, client_id, row.did, row.scope, jkt, Math.floor(Date.now() / 1000) + 30 * 24 * 3600]
      });

      // Cleanup code
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

      console.log(`Generating tokens for client_id: ${client_id}, issuer: ${issuer}`);
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
  } catch (err) {
    console.error('OAuth token error:', err.message);
    res.status(400).json({ error: 'invalid_request', message: err.message });
  }
});

app.get('/xrpc/com.atproto.server.getServiceContext', async (req, res) => {
  res.json({
    did: (process.env.PDS_DID || '').trim(),
    endpoint: `https://${getHost(req)}`
  });
});

// 4. Favicon handler
app.get('/favicon.ico', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
  res.status(204).end();
});

// Helper to get system state
const getSystemMeta = async (key) => {
  try {
    const res = await db.execute({
      sql: 'SELECT value FROM system_state WHERE key = ?',
      args: [key]
    });
    return res.rows.length > 0 ? res.rows[0].value : null;
  } catch (e) {
    return null;
  }
};

// Helper to get the current host safely
export const getHost = (req) => {
  if (process.env.HANDLE && process.env.HANDLE !== 'localhost') return process.env.HANDLE;
  const host = req.get('host') || 'localhost';
  console.log(`DEBUG: getHost derived host="${host}" from req.get("host")`);
  return host;
};

const getBlobUrl = (req, blob) => {
  if (!blob || !blob.ref || !blob.ref.$link) return undefined;
  const host = getHost(req);
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production' || !host.includes('localhost')) ? 'https' : 'http';
  return `${protocol}://${host}/xrpc/com.atproto.sync.getBlob?cid=${blob.ref.$link}`;
};

// Helper to get the single allowed user from Env
const getSingleUser = async (req = null) => {
  const handle = process.env.HANDLE || 'localhost.test';
  
  const did = (process.env.PDS_DID || formatDid(handle.split(':')[0])).trim();

  const privKeyHex = process.env.PRIVATE_KEY;
  const password = process.env.PASSWORD;
  
  if (!password) {
    throw new Error('PASSWORD environment variable is not set');
  }
  
  let root_cid = await getRootCid();
  if (!root_cid) {
    console.log('No repository found. Auto-initializing...');
    await maybeInitRepo();
    root_cid = await getRootCid();
  }
  
  if (!root_cid) return null;

  return {
    handle,
    password,
    did,
    signing_key: Buffer.from(privKeyHex, 'hex'),
    root_cid: root_cid.toString() // Ensure it is a string
  };
};

const auth = async (req, res, next) => {
  res.setHeader('Content-Type', 'application/json');
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    console.log(`Auth failed: No Authorization header for ${req.url}`);
    return res.status(401).json({ error: 'AuthenticationRequired' });
  }
  const [type, token] = authHeader.split(' ');
  
  if (type === 'DPoP') {
    try {
      const { jkt } = await validateDpop(req, token);
      const payload = verifyToken(token);
      if (!payload || payload.cnf?.jkt !== jkt) {
        return res.status(401).json({ error: 'InvalidToken', message: 'DPoP binding mismatch' });
      }
      req.user = payload;
      return next();
    } catch (err) {
      console.log(`Auth failed: DPoP error for ${req.url}: ${err.message}`);
      return res.status(401).json({ error: 'InvalidToken', message: err.message });
    }
  }

  const payload = verifyToken(token);
  if (!payload) {
    console.log(`Auth failed: Invalid token for ${req.url}`);
    return res.status(401).json({ error: 'InvalidToken' });
  }
  req.user = payload;
  next();
};

// --- Endpoints ---
app.get('/.well-known/atproto-did', async (req, res) => {
  const pdsDid = (process.env.PDS_DID || '').trim();
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Cache-Control', 'no-cache');
  // Use res.write and res.end to ensure absolutely no extra formatting
  res.write(pdsDid);
  res.end();
});

app.get('/.well-known/oauth-authorization-server', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const host = getHost(req);
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production') ? 'https' : 'http';
  const issuer = `${protocol}://${host}`;
  
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
    require_pushed_authorization_requests: true,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    scopes_supported: ['atproto'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
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

app.get('/.well-known/oauth-protected-resource', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const host = getHost(req);
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production') ? 'https' : 'http';
  const issuer = `${protocol}://${host}`;

  res.json({
    resource: issuer,
    authorization_servers: [issuer],
    scopes_supported: ['atproto'],
    bearer_methods_supported: ['header'],
    resource_documentation: 'https://atproto.com/specs/oauth'
  });
});

app.get('/.well-known/openid-configuration', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const host = getHost(req);
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production') ? 'https' : 'http';
  const issuer = `${protocol}://${host}`;

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

app.get('/.well-known/jwks.json', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  const privKeyHex = process.env.PRIVATE_KEY;
  if (!privKeyHex) return res.status(500).json({ error: 'NoPrivateKey' });
  
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(privKeyHex, 'hex'));
  const uncompressed = ecdh.getPublicKey();
  const x = uncompressed.slice(1, 33).toString('base64url');
  const y = uncompressed.slice(33, 65).toString('base64url');

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
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

app.get('/xrpc/com.atproto.identity.getRecommendedDidCredentials', async (req, res) => {
  res.json({
    rotationKeys: [],
    alsoKnownAs: [],
    verificationMethods: {},
    services: {}
  });
});

// --- Dashboard ---
app.get('/', async (req, res) => {
  const user = await getSingleUser(req);
  const blockCountRes = await db.execute('SELECT count(*) as count FROM repo_blocks');
  const eventCountRes = await db.execute('SELECT count(*) as count FROM sequencer');
  const lastPing = await getSystemMeta('last_relay_ping');
  const repoCreatedAt = await getSystemMeta('repo_created_at');

  // Get last 10 events
  const lastEventsRes = await db.execute("SELECT * FROM sequencer ORDER BY seq DESC LIMIT 10");
  const events = lastEventsRes.rows.map(row => {
    try {
      const evt = cborDecode(new Uint8Array(row.event));
      return {
        seq: row.seq,
        time: row.time,
        ops: evt.ops || []
      };
    } catch (e) {
      return { seq: row.seq, time: row.time, ops: [] };
    }
  });

  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Minimal PDS Status</title>
    <style>
        body { font-family: -apple-system, sans-serif; line-height: 1.6; max-width: 900px; margin: 40px auto; padding: 20px; background: #f4f4f9; color: #333; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h1 { color: #007bff; display: flex; align-items: center; gap: 10px; }
        .stat { display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 10px 0; }
        .stat:last-child { border-bottom: none; }
        .label { font-weight: bold; }
        .value { font-family: monospace; color: #666; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warn { color: #dc3545; font-weight: bold; }
        .danger-zone { border: 2px solid #dc3545; padding: 20px; border-radius: 8px; margin-top: 40px; background: #fff5f5; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #0056b3; }
        button.danger { background: #dc3545; }
        button.secondary { background: #6c757d; }
        .activity-item { padding: 8px; border-bottom: 1px solid #eee; font-size: 0.9em; }
        .activity-item:last-child { border-bottom: none; }
        .op-tag { padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }
        .op-create { background: #e3fcef; color: #28a745; }
        .op-update { background: #fff3cd; color: #856404; }
        .op-delete { background: #f8d7da; color: #721c24; }
        .actions { display: flex; gap: 10px; margin-top: 10px; }
        #action-result { margin-top: 10px; padding: 10px; border-radius: 4px; display: none; }
    </style>
</head>
<body>
    <h1><span>🌐</span> Personal PDS Dashboard</h1>
    
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div class="card">
            <h2>Identity</h2>
            <div class="stat"><span class="label">Handle</span><span class="value">${user?.handle || 'Not Initialized'}</span></div>
            <div class="stat"><span class="label">DID</span><span class="value">${user?.did || 'N/A'}</span></div>
            <div class="stat"><span class="label">PDS Domain</span><span class="value">${process.env.HANDLE || req.get('host')}</span></div>
            <div class="stat"><span class="label">Created At</span><span class="value">${repoCreatedAt || 'N/A'}</span></div>
        </div>

        <div class="card">
            <h2>Network & Status</h2>
            <div class="stat">
                <span class="label">Relay Crawler</span>
                <span class="value ${lastPing ? 'status-ok' : 'status-warn'}">
                    ${lastPing ? 'Connected' : 'Pending'}
                </span>
            </div>
            <div class="stat"><span class="label">Last Relay Ping</span><span class="value">${lastPing ? new Date(lastPing).toLocaleString() : 'Never'}</span></div>
            <div class="actions">
                <button class="secondary" onclick="runAction('/debug/ping-relay')">Ping Relay</button>
                <button class="secondary" onclick="runAction('/xrpc/com.atproto.server.describeServer')">Self-Check</button>
            </div>
            <div id="action-result"></div>
        </div>
    </div>

    <div class="card">
        <h2>Recent Activity</h2>
        <div id="activity-feed">
            ${events.length === 0 ? '<p>No activity yet.</p>' : events.map(e => `
                <div class="activity-item">
                    <strong>Seq ${e.seq}</strong> <span style="color: #999;">${new Date(e.time).toLocaleTimeString()}</span><br/>
                    ${e.ops.map(op => `
                        <span class="op-tag op-${op.action}">${op.action}</span> 
                        <span class="value">${op.path}</span>
                    `).join('<br/>')}
                </div>
            `).join('')}
        </div>
    </div>

    <div class="card">
        <h2>System & Storage</h2>
        <div class="stat"><span class="label">Total Repo Blocks</span><span class="value">${blockCountRes.rows[0].count}</span></div>
        <div class="stat"><span class="label">Event Log Size</span><span class="value">${eventCountRes.rows[0].count}</span></div>
        <div class="stat"><span class="label">Node.js</span><span class="value">${process.version}</span></div>
        <div class="stat"><span class="label">Database</span><span class="value">Turso (libSQL)</span></div>
    </div>

    <div class="danger-zone">
        <h2>Danger Zone</h2>
        <p>Wiping the PDS will delete all posts, follows, likes, and profile data. This cannot be undone.</p>
        <form action="/debug/reset" method="POST" onsubmit="return confirm('PERMANENTLY DELETE ALL DATA? This is your last warning.')">
            <input type="password" name="password" placeholder="PDS Password" required style="padding: 10px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px;">
            <button type="submit" class="danger">Wipe PDS Data</button>
        </form>
    </div>

    <script>
        async function runAction(url) {
            const resDiv = document.getElementById('action-result');
            resDiv.style.display = 'block';
            resDiv.style.background = '#eee';
            resDiv.innerText = 'Running...';
            try {
                const res = await fetch(url);
                const data = await res.json();
                resDiv.style.background = res.ok ? '#e3fcef' : '#f8d7da';
                resDiv.innerText = JSON.stringify(data, null, 2);
            } catch (e) {
                resDiv.style.background = '#f8d7da';
                resDiv.innerText = 'Error: ' + e.message;
            }
        }
    </script>
</body>
</html>
  `;
  res.send(html);
});

app.post('/debug/reset', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password !== process.env.PASSWORD) {
        return res.status(403).send('<h1>Forbidden</h1><p>Incorrect password.</p><a href="/">Back to Dashboard</a>');
    }

    console.log('Wiping ALL PDS data via Web UI...');
    await db.execute('DELETE FROM repo_blocks');
    await db.execute('DELETE FROM sequencer');
    await db.execute('DELETE FROM blobs');
    await db.execute('DELETE FROM sessions');
    await db.execute("DELETE FROM system_state WHERE key = 'repo_created_at'");
    
    res.send('<h1>Success</h1><p>PDS has been wiped clean.</p><a href="/">Back to Dashboard</a>');
  } catch (err) {
    res.status(500).send(`<h1>Error</h1><p>${err.message}</p>`);
  }
});

const RELAY_URL = process.env.RELAY_URL || 'https://bsky.network';

export async function pingRelay(hostname) {
  if (!hostname || hostname.includes('localhost') || hostname.includes('127.0.0.1')) {
    const msg = 'Skipping relay ping: PDS is running on localhost or hostname not provided.';
    console.log(msg);
    return { success: false, message: msg };
  }

  try {
    console.log(`Pinging relay ${RELAY_URL} to crawl ${hostname}...`);
    const res = await axios.post(`${RELAY_URL}/xrpc/com.atproto.sync.requestCrawl`, {
      hostname: hostname
    });
    await db.execute({
      sql: "INSERT OR REPLACE INTO system_state (key, value) VALUES ('last_relay_ping', ?)",
      args: [new Date().toISOString()]
    });
    console.log('Relay notified successfully.');
    return { success: true, data: res.data };
  } catch (err) {
    const errorMsg = err.response?.data || err.message;
    console.error('Failed to notify relay:', errorMsg);
    return { success: false, error: errorMsg };
  }
}

app.get('/debug/ping-relay', async (req, res) => {
  try {
    const host = getHost(req);
    const result = await pingRelay(host);
    res.json({
        host,
        result
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper to generate the DID document
const getDidDoc = async (req, host) => {
  const pdsDid = (process.env.PDS_DID || formatDid(host)).trim();
  const privKeyHex = process.env.PRIVATE_KEY;
  if (!privKeyHex) return null;

  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(Buffer.from(privKeyHex, 'hex')));
  const protocol = (req.protocol === 'https' || process.env.NODE_ENV === 'production' || !host.includes('localhost')) ? 'https' : 'http';
  const serviceEndpoint = `${protocol}://${host}`;

  return {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multiconf/v1",
        "https://w3id.org/security/suites/secp256k1-2019/v1"
    ],
    "id": pdsDid,
    "alsoKnownAs": [`at://${host}`],
    "verificationMethod": [
      {
        "id": `${pdsDid}#atproto`,
        "type": "Multikey",
        "controller": pdsDid,
        "publicKeyMultibase": keypair.did().split(':').pop()
      }
    ],
    "authentication": [`${pdsDid}#atproto`],
    "assertionMethod": [`${pdsDid}#atproto`],
    "capabilityInvocation": [`${pdsDid}#atproto`],
    "capabilityDelegation": [`${pdsDid}#atproto`],
    "service": [{
      "id": "#atproto_pds",
      "type": "AtprotoPersonalDataServer",
      "serviceEndpoint": serviceEndpoint
    }]
  };
};

app.get('/xrpc/com.atproto.identity.resolveDid', async (req, res) => {
  try {
    const { did } = req.query;
    if (!did) return res.status(400).json({ error: 'InvalidRequest', message: 'Missing did' });

    const pdsDid = (process.env.PDS_DID || '').trim();
    if (did.toLowerCase() === pdsDid.toLowerCase()) {
      const host = getHost(req);
      const doc = await getDidDoc(req, host);
      if (!doc) return res.status(404).json({ error: 'DidNotFound' });
      return res.json(doc);
    }

    // Proxy other DIDs to plc.directory if they are did:plc
    if (did.startsWith('did:plc:')) {
      try {
        console.log(`Proxying resolveDid for ${did} to plc.directory...`);
        const plcRes = await axios.get(`https://plc.directory/${did}`, { timeout: 5000 });
        return res.json(plcRes.data);
      } catch (err) {
        console.error(`plc.directory error for ${did}: ${err.message}`);
        return res.status(404).json({ error: 'DidNotFound', message: `Proxy failed: ${err.message}` });
      }
    }

    res.status(404).json({ error: 'DidNotFound' });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.identity.resolveHandle', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const { handle } = req.query;
  const user = await getSingleUser(req);
  if (!user) return res.status(500).json({ error: 'ServerNotInitialized' });

  // Only resolve locally if the handle EXACTLY matches our domain or is empty/self
  if (!handle || handle === user.handle || handle === 'self') {
    console.log(`[RESOLVE] Local handle resolved: ${handle || 'default'} -> ${user.did}`);
    return res.json({ did: user.did.trim() });
  }

  // 2. Otherwise, proxy the request to a public AppView to resolve other handles
  try {
    console.log(`[RESOLVE] Proxying handle resolution to bsky.social for: ${handle}`);
    const appView = 'https://bsky.social';
    const response = await axios.get(`${appView}/xrpc/com.atproto.identity.resolveHandle?handle=${handle}`, {
        timeout: 5000,
        validateStatus: (status) => status === 200 || status === 404
    });

    if (response.status === 200) {
        console.log(`[RESOLVE] External handle resolved via bsky.social: ${handle} -> ${response.data.did}`);
        return res.json(response.data);
    }
  } catch (err) {
    console.error(`[RESOLVE] Proxy resolution failed for ${handle}:`, err.message);
  }

  return res.status(404).json({ error: 'HandleNotFound' });
});
app.post('/xrpc/com.atproto.server.createSession', async (req, res) => {
  const { identifier, password } = req.body;
  const user = await getSingleUser(req);
  if (!user) {
    console.log('Login failed: Server not initialized (no user)');
    return res.status(500).json({ error: 'ServerNotInitialized' });
  }

  if (identifier !== user.handle && identifier !== user.did) {
    console.log(`Login failed: Invalid identifier. Received: ${identifier}, Expected: ${user.handle} or ${user.did}`);
    return res.status(401).json({ error: 'InvalidIdentifier' });
  }

  if (password !== user.password) {
    console.log(`Login failed: Password mismatch for ${identifier}`);
    return res.status(401).json({ error: 'InvalidPassword' });
  }

  const accessJwt = createToken(user.did, user.handle);  res.json({ accessJwt, refreshJwt: accessJwt, handle: user.handle, did: user.did });
});

app.post('/xrpc/com.atproto.server.refreshSession', auth, async (req, res) => {
  const user = await getSingleUser(req);
  if (!user) return res.status(500).json({ error: 'ServerNotInitialized' });
  
  const accessJwt = createToken(user.did, user.handle);
  res.json({ accessJwt, refreshJwt: accessJwt, handle: user.handle, did: user.did });
});

app.get('/xrpc/com.atproto.server.getAccount', auth, async (req, res) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.status(404).json({ error: 'UserNotFound' });
    
    const birthDate = await getSystemMeta(`birthDate:${user.did}`) || process.env.BIRTHDATE || '1990-01-01';
    const email = process.env.EMAIL || `pds@${user.handle}`;

    res.json({
      handle: user.handle,
      did: user.did,
      email: email,
      emailConfirmed: true,
      birthDate: birthDate,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.server.checkAccountStatus', async (req, res) => {
  try {
    const user = await getSingleUser(req);
    if (!user) {
      return res.status(404).json({ error: 'UserNotFound', message: 'User or Repository not initialized' });
    }
    res.json({
      activated: true,
      validEmail: true,
      repoCommit: await getRootCid(),
      repoRev: '0',
      repoBlocks: 1,
      indexedIncremental: true,
      expectedBlobs: 0,
      importedBlobs: 0
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.server.getSession', auth, async (req, res) => {
  res.json({ handle: req.user.handle, did: req.user.sub });
});

app.post('/xrpc/com.atproto.repo.createRecord', auth, async (req, res) => {
  try {
    const { repo, collection, record, rkey } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    // ATProto nuance: records from clients often have CID strings. 
    // They MUST be CID objects for proper Tag 42 storage.
    const fixedRecord = fixCids(record);

    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const finalRkey = rkey || createTid();
    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Create, collection, rkey: finalRkey, record: fixedRecord }], keypair);
    
    const recordCid = await updatedRepo.data.get(collection + '/' + finalRkey);
    if (!recordCid) {
        console.error(`Failed to find CID in MST for path: ${collection}/${finalRkey}`);
    }

    // Nuance: Firehose events should ideally only contain the NEW blocks (the diff)
    const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

    // Ensure we have a proper CID object for the ops
    const opCid = typeof recordCid === 'string' ? CID.parse(recordCid) : recordCid;
    console.log(`DEBUG: opCid for firehose:`, {
        type: typeof opCid,
        isCid: !!(opCid?.asCID === opCid || opCid?._Symbol_for_multiformats_cid),
        val: opCid?.toString()
    });

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'create', path: `${collection}/${finalRkey}`, cid: opCid }],
        blobs: [], // Placeholder
        time: new Date().toISOString(),
        rebase: false,
        tooBig: false,
      }
    });
    
    res.json({ 
        uri: `at://${user.did}/${collection}/${finalRkey}`, 
        cid: recordCid?.toString() || updatedRepo.cid.toString(),
        commit: {
            cid: updatedRepo.cid.toString(),
            rev: updatedRepo.commit.rev
        }
    });
  } catch (err) {
    console.error('Error in createRecord:', err);
    res.status(500).json({ error: 'InternalServerError', message: err.message });
  }
});

app.post('/xrpc/com.atproto.repo.putRecord', auth, async (req, res) => {
  try {
    const { repo, collection, rkey, record } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });

    const fixedRecord = fixCids(record);

    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));

    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Update, collection, rkey, record: fixedRecord }], keypair);
    const recordCid = await updatedRepo.data.get(collection + '/' + rkey);
    if (!recordCid) {
        console.error(`Failed to find CID in MST for path: ${collection}/${rkey}`);
    }

    const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

    // Ensure we have a proper CID object
    const opCid = typeof recordCid === 'string' ? CID.parse(recordCid) : recordCid;

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'update', path: `${collection}/${rkey}`, cid: opCid }],
        blobs: [],
        time: new Date().toISOString(),
        rebase: false,
        tooBig: false,
      }
    });
    
    res.json({ 
        uri: `at://${user.did}/${collection}/${rkey}`, 
        cid: recordCid?.toString() || updatedRepo.cid.toString(),
        commit: {
            cid: updatedRepo.cid.toString(),
            rev: updatedRepo.commit.rev
        }
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.post('/xrpc/com.atproto.repo.deleteRecord', auth, async (req, res) => {
  try {
    const { repo, collection, rkey } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const updatedRepo = await repoObj.applyWrites([{ action: WriteOpAction.Delete, collection, rkey }], keypair);

    const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'delete', path: `${collection}/${rkey}`, cid: null }],
        blobs: [],
        time: new Date().toISOString(),
        rebase: false,
        tooBig: false,
      }
    });
    
    res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.post('/xrpc/com.atproto.repo.applyWrites', auth, async (req, res) => {
  try {
    const { repo, writes, swapCommit } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });

    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));

    const repoWrites = writes.map(w => {
        if (w.$type === 'com.atproto.repo.applyWrites#create') {
            return { action: WriteOpAction.Create, collection: w.collection, rkey: w.rkey || createTid(), record: fixCids(w.value) };
        } else if (w.$type === 'com.atproto.repo.applyWrites#update') {
            return { action: WriteOpAction.Update, collection: w.collection, rkey: w.rkey, record: fixCids(w.value) };
        } else if (w.$type === 'com.atproto.repo.applyWrites#delete') {
            return { action: WriteOpAction.Delete, collection: w.collection, rkey: w.rkey };
        }
        throw new Error(`Unknown write action: ${w.$type}`);
    });

    const updatedRepo = await repoObj.applyWrites(repoWrites, keypair);

    // Prepare ops for the sequencer event
    const ops = [];
    for (const w of repoWrites) {
        let cid = null;
        if (w.action !== WriteOpAction.Delete) {
            const rawCid = await updatedRepo.data.get(w.collection + '/' + w.rkey);
            cid = typeof rawCid === 'string' ? CID.parse(rawCid) : rawCid;
        }
        ops.push({
            action: w.action.toLowerCase(),
            path: `${w.collection}/${w.rkey}`,
            cid: cid
        });
    }
    const blocks = await blocksToCarFile(updatedRepo.cid, storage.newBlocks);

    await sequencer.sequenceEvent({
      did: user.did,
      type: 'commit',
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: ops,
        time: new Date().toISOString(),
        rebase: false,
        tooBig: false,
        blobs: [],
      }
    });

    res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
  } catch (err) {
    console.error('Error in applyWrites:', err);
    res.status(500).json({ error: 'InternalServerError', message: err.message });
  }
});

app.get('/xrpc/app.bsky.actor.getProfile', async (req, res) => {
  try {
    const { actor } = req.query;
    const user = await getSingleUser(req);
    if (!user || (actor !== user.did && actor !== user.handle)) {
        return res.status(404).json({ error: 'ProfileNotFound' });
    }

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
    if (!profile) {
        return res.status(404).json({ error: 'ProfileNotFound' });
    }
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();
    
    res.json({
        did: user.did,
        handle: user.handle,
        displayName: profile.displayName || user.handle,
        description: profile.description || '',
        avatar: getBlobUrl(req, profile.avatar),
        banner: getBlobUrl(req, profile.banner),
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        viewer: {
            muted: false,
            blockedBy: false,
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Error in getProfile:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.actor.getProfiles', async (req, res) => {
  try {
    const actors = Array.isArray(req.query.actors) ? req.query.actors : [req.query.actors];
    const user = await getSingleUser(req);
    const profiles = [];

    if (user) {
        const storage = new TursoStorage();
        const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
        const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
        
        if (profile) {
            const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();

            const localProfile = {
                did: user.did,
                handle: user.handle,
                displayName: profile.displayName || user.handle,
                description: profile.description || '',
                avatar: getBlobUrl(req, profile.avatar),
                banner: getBlobUrl(req, profile.banner),
                associated: {
                    activitySubscription: { allowSubscriptions: 'followers' }
                },
                viewer: {
                    muted: false,
                    blockedBy: false,
                },
                labels: [],
                createdAt: repoCreatedAt,
                indexedAt: new Date().toISOString(),
            };

            for (const actor of actors) {
                if (actor === user.did || actor === user.handle) {
                    profiles.push(localProfile);
                }
            }
        }
    }

    res.json({ profiles });
  } catch (err) {
    console.error('Error in getProfiles:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.actor.getPreferences', auth, async (req, res) => {
  try {
    const prefsJson = await getSystemMeta(`prefs:${req.user.sub}`);
    let preferences = prefsJson ? JSON.parse(prefsJson) : [];
    
    // Ensure there is at least an adultContentPref if missing
    if (!preferences.find(p => p.$type === 'app.bsky.actor.defs#adultContentPref')) {
        preferences.push({
            $type: 'app.bsky.actor.defs#adultContentPref',
            enabled: true
        });
    }

    res.json({ preferences });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.post('/xrpc/app.bsky.actor.putPreferences', auth, async (req, res) => {
  try {
    const { preferences } = req.body;
    
    // Extract and store birthDate if provided in personalDetailsPref
    const personalDetailsPref = preferences.find(p => p.$type === 'app.bsky.actor.defs#personalDetailsPref');
    if (personalDetailsPref?.birthDate) {
        await db.execute({
            sql: "INSERT OR REPLACE INTO system_state (key, value) VALUES (?, ?)",
            args: [`birthDate:${req.user.sub}`, personalDetailsPref.birthDate]
        });
    }

    await db.execute({
      sql: "INSERT OR REPLACE INTO system_state (key, value) VALUES (?, ?)",
      args: [`prefs:${req.user.sub}`, JSON.stringify(preferences)]
    });
    res.json({});
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

const fetchExternalPost = async (req, uri) => {
  try {
    const appView = 'https://bsky.social';
    console.log(`[EXTERNAL] Fetching external post: ${uri}`);
    const response = await axios.get(`${appView}/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(uri)}&depth=0`, {
        timeout: 5000
    });
    // AppView returns a thread object which could be a threadViewPost or notFoundPost
    if (response.data.thread?.post) {
        return response.data.thread.post;
    }
    return response.data.thread;
  } catch (err) {
    console.error(`[EXTERNAL] Failed to fetch external post ${uri}: ${err.message}`);
    return {
        uri,
        $type: 'app.bsky.feed.defs#notFoundPost',
        notFound: true
    };
  }
};

const getAuthorFeed = async (req, res, actor, limit) => {
  try {
    const user = await getSingleUser(req);
    if (!user || (actor !== user.did && actor !== user.handle)) {
        return res.json({ feed: [] });
    }

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();
    
    const author = {
        did: user.did,
        handle: user.handle,
        displayName: profile?.displayName || user.handle,
        avatar: getBlobUrl(req, profile?.avatar),
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        viewer: {
            muted: false,
            blockedBy: false,
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    };

    const feed = [];
    for await (const rec of repoObj.walkRecords()) {
      if (rec.collection === 'app.bsky.feed.post') {
        feed.push({
            post: {
                uri: `at://${user.did}/${rec.collection}/${rec.rkey}`,
                cid: rec.cid.toString(),
                author,
                record: rec.record,
                replyCount: 0,
                repostCount: 0,
                likeCount: 0,
                indexedAt: rec.record.createdAt || new Date().toISOString(),
                viewer: {},
                labels: [],
            }
        });
      }
    }
    
    feed.sort((a, b) => new Date(b.post.record.createdAt).getTime() - new Date(a.post.record.createdAt).getTime());

    res.json({ 
        feed: feed.slice(0, parseInt(limit || '50', 10)),
    });
  } catch (err) {
    console.error('Error in getAuthorFeed:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
};

app.get('/xrpc/app.bsky.feed.getAuthorFeed', async (req, res) => {
  return getAuthorFeed(req, res, req.query.actor, req.query.limit);
});

app.get('/xrpc/app.bsky.feed.getTimeline', auth, async (req, res) => {
  const host = getHost(req);
  const userDid = formatDid(host);
  return getAuthorFeed(req, res, userDid, req.query.limit);
});

app.get('/xrpc/app.bsky.feed.getFeed', auth, async (req, res) => {
  res.json({ feed: [] });
});

app.post('/xrpc/com.atproto.repo.uploadBlob', auth, express.raw({ type: '*/*', limit: '5mb' }), async (req, res) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.status(403).json({ error: 'InvalidRepo' });

    const content = req.body;
    const mimeType = req.headers['content-type'] || 'application/octet-stream';
    
    // Generate valid CIDv1
    const cid = await createBlobCid(content);

    await db.execute({
      sql: "INSERT OR REPLACE INTO blobs (cid, did, mime_type, content, created_at) VALUES (?, ?, ?, ?, ?)",
      args: [cid, user.did, mimeType, content, new Date().toISOString()]
    });

    res.json({
      blob: {
        $type: 'blob',
        ref: { $link: cid },
        mimeType: mimeType,
        size: content.length,
      }
    });
  } catch (err) {
    console.error('Error in uploadBlob:', err);
    res.status(500).json({ error: 'InternalServerError', message: err.message });
  }
});

app.get('/xrpc/com.atproto.sync.getBlob', async (req, res) => {
  try {
    const { cid } = req.query;
    
    const result = await db.execute({
      sql: "SELECT mime_type, content FROM blobs WHERE cid = ?",
      args: [cid]
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'BlobNotFound' });
    }

    const { mime_type, content } = result.rows[0];
    res.setHeader('Content-Type', mime_type);
    res.send(Buffer.from(content));
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

const getPostThread = async (req, res, uri, isV2 = false) => {
  try {
    const user = await getSingleUser(req);
    if (!user) return res.status(404).json({ error: 'PostNotFound' });

    // Canonicalize the URI to use the DID instead of the handle
    const canonicalUri = uri.replace(`at://${user.handle}`, `at://${user.did}`);
    const isLocalDid = canonicalUri.startsWith(`at://${user.did}`);

    if (!isLocalDid) {
        return res.status(404).json({ error: 'PostNotFound' });
    }

    const parts = canonicalUri.replace('at://', '').split('/');
    const collection = parts[1];
    const rkey = parts[2];

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const recordCid = await repoObj.data.get(`${collection}/${rkey}`);
    const record = await repoObj.getRecord(collection, rkey);

    if (!record) {
        return res.status(404).json({ error: 'PostNotFound' });
    }

    const profile = await repoObj.getRecord('app.bsky.actor.profile', 'self');
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();

    const author = {
        did: user.did,
        handle: user.handle,
        displayName: profile?.displayName || user.handle,
        avatar: getBlobUrl(req, profile?.avatar),
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    };

    // Find replies in the repository
    const allPostEntries = await repoObj.data.list('app.bsky.feed.post/');
    const directReplies = [];
    console.log(`[THREAD] Searching for replies to: ${canonicalUri} (from original: ${uri})`);
    
    for (const entry of allPostEntries) {
        if (!entry.k) continue; // Safety check
        const postRkey = entry.k.split('/').pop();
        if (postRkey === rkey) continue; // Skip the anchor post itself
        
        const postRecord = await repoObj.getRecord('app.bsky.feed.post', postRkey);
        const parentUri = postRecord?.reply?.parent?.uri;
        
        if (parentUri) {
            // Canonicalize the parent URI from the record for comparison
            const canonicalParentUri = parentUri.replace(`at://${user.handle}`, `at://${user.did}`);
            if (canonicalParentUri === canonicalUri) {
                console.log(`[THREAD] Found direct reply: ${postRkey}`);
                directReplies.push({
                    uri: `at://${user.did}/app.bsky.feed.post/${postRkey}`,
                    cid: entry.v.toString(),
                    record: postRecord
                });
            }
        }
    }

    if (isV2) {
        const thread = [
            {
              uri: canonicalUri,
              depth: 0,
              value: {
                $type: "app.bsky.unspecced.defs#threadItemPost",
                post: {
                  uri: canonicalUri,
                  cid: recordCid.toString(),
                  author,
                  record,
                  replyCount: directReplies.length,
                  repostCount: 0,
                  likeCount: 0,
                  quoteCount: 0,
                  bookmarkCount: 0,
                  indexedAt: record.createdAt || new Date().toISOString(),
                  labels: []
                },
                moreParents: false,
                moreReplies: 0,
                opThread: true,
                hiddenByThreadgate: false,
                mutedByViewer: false
              }
            }
        ];

        // Add direct replies at depth 1
        for (const reply of directReplies) {
            thread.push({
                uri: reply.uri,
                depth: 1,
                value: {
                    $type: "app.bsky.unspecced.defs#threadItemPost",
                    post: {
                        uri: reply.uri,
                        cid: reply.cid,
                        author, // In single user PDS, author is the same
                        record: reply.record,
                        replyCount: 0,
                        repostCount: 0,
                        likeCount: 0,
                        quoteCount: 0,
                        bookmarkCount: 0,
                        indexedAt: reply.record.createdAt || new Date().toISOString(),
                        labels: []
                    },
                    moreParents: false,
                    moreReplies: 0,
                    opThread: false,
                    hiddenByThreadgate: false,
                    mutedByViewer: false
                }
            });
        }

        return res.json({ thread, hasOtherReplies: false });
    }

    // Legacy/Standard V1 structure
    res.json({
        thread: {
            $type: 'app.bsky.feed.defs#threadViewPost',
            post: {
                uri: canonicalUri,
                cid: recordCid.toString(),
                author,
                record,
                replyCount: directReplies.length,
                repostCount: 0,
                likeCount: 0,
                quoteCount: 0,
                bookmarkCount: 0,
                indexedAt: record.createdAt || new Date().toISOString(),
                viewer: {},
                labels: [],
            },
            replies: directReplies.map(reply => ({
                $type: 'app.bsky.feed.defs#threadViewPost',
                post: {
                    uri: reply.uri,
                    cid: reply.cid,
                    author,
                    record: reply.record,
                    replyCount: 0,
                    repostCount: 0,
                    likeCount: 0,
                    quoteCount: 0,
                    bookmarkCount: 0,
                    indexedAt: reply.record.createdAt || new Date().toISOString(),
                    viewer: {},
                    labels: [],
                },
                replies: []
            })),
            threadContext: {},
        }
    });
  } catch (err) {
    console.error('Error in getPostThread:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
};

app.get('/xrpc/app.bsky.feed.getPostThread', async (req, res) => {
  return getPostThread(req, res, req.query.uri, false);
});

app.get('/xrpc/app.bsky.unspecced.getPostThreadV2', async (req, res) => {
  return getPostThread(req, res, req.query.anchor, true);
});

app.get('/xrpc/app.bsky.graph.getFollows', async (req, res) => {
  try {
    const { actor } = req.query;
    const user = await getSingleUser(req);
    
    let profile = undefined;
    if (user && (actor === user.did || actor === user.handle)) {
        profile = {
            did: user.did,
            handle: user.handle,
            indexedAt: new Date().toISOString(),
        };
    }

    res.json({
        follows: [],
        subject: profile,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.graph.getFollowers', async (req, res) => {
  res.json({ followers: [] });
});

app.get('/xrpc/app.bsky.graph.getSuggestedFollowsByActor', async (req, res) => {
  res.json({ suggestions: [] });
});

app.get('/xrpc/app.bsky.graph.getMutes', auth, async (req, res) => {
  res.json({ mutes: [] });
});

app.get('/xrpc/app.bsky.graph.getBlocks', auth, async (req, res) => {
  res.json({ blocks: [] });
});

app.get('/xrpc/app.bsky.actor.getSuggestions', auth, async (req, res) => {
  res.json({ actors: [] });
});

app.get('/xrpc/app.bsky.notification.getUnreadCount', auth, async (req, res) => {
  res.json({ count: 0 });
});


app.get('/xrpc/app.bsky.unspecced.getConfig', async (req, res) => {
  res.json({});
});

app.get('/xrpc/app.bsky.labeler.getServices', async (req, res) => {
  res.json({ views: [] });
});

app.get('/xrpc/app.bsky.ageassurance.getState', async (req, res) => {
  res.json({ status: 'verified' });
});

app.get('/xrpc/chat.bsky.convo.getLog', auth, async (req, res) => {
  res.json({ logs: [] });
});

app.get('/xrpc/chat.bsky.convo.listConvos', auth, async (req, res) => {
  res.json({ convos: [] });
});

app.get('/xrpc/app.bsky.notification.listNotifications', auth, async (req, res) => {
  res.json({ 
    notifications: [], 
    cursor: undefined,
    seenAt: new Date().toISOString()
  });
});

app.post('/xrpc/app.bsky.notification.updateSeen', auth, async (req, res) => {
  res.json({});
});

app.get('/xrpc/app.bsky.draft.getDrafts', auth, async (req, res) => {
  res.json({ drafts: [] });
});

app.get('/xrpc/com.atproto.repo.listRecords', async (req, res) => {
  try {
    const { repo, collection, limit } = req.query;
    const user = await getSingleUser(req);
    if (!user || (repo !== user.did && repo !== user.handle)) return res.status(404).json({ error: 'RepoNotFound' });

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const records = [];
    for await (const rec of repoObj.walkRecords()) {
      if (rec.collection === collection) {
        records.push({ uri: `at://${user.did}/${rec.collection}/${rec.rkey}`, cid: rec.cid.toString(), value: rec.record });
      }
    }
    res.json({ records: records.slice(0, parseInt(limit || '50', 10)) });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

// Helper to get a single record from the local repo
const getRecordHelper = async (repo, collection, rkey) => {
  const user = await getSingleUser(); 
  if (!user) {
    console.log('[HELPER] No user found');
    return null;
  }
  
  const isMatch = repo.toLowerCase() === user.did.toLowerCase() || repo.toLowerCase() === user.handle.toLowerCase();
  if (!isMatch) {
    console.log(`[HELPER] Repo mismatch: ${repo} !== ${user.did} or ${user.handle}`);
    return null;
  }

  try {
    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const value = await repoObj.getRecord(collection, rkey);
    
    if (!value) {
        console.log(`[HELPER] Record not found: ${collection}/${rkey}`);
        return null;
    }
    
    const cid = await repoObj.data.get(`${collection}/${rkey}`);
    return { value, cid: cid.toString() };
  } catch (err) {
    console.error(`[HELPER] Error fetching ${collection}/${rkey}:`, err.message);
    return null;
  }
};

app.get('/xrpc/com.atproto.repo.listRecords', async (req, res) => {
  try {
    const { repo, collection, limit, cursor } = req.query;
    const user = await getSingleUser();
    if (!user || (repo.toLowerCase() !== user.did.toLowerCase() && repo.toLowerCase() !== user.handle.toLowerCase())) {
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    const entries = await repoObj.data.list(collection + '/');
    
    const records = [];
    for (const entry of entries) {
        const rkey = entry.k.split('/').pop();
        const value = await repoObj.getRecord(collection, rkey);
        if (value) {
            records.push({
                uri: `at://${user.did}/${collection}/${rkey}`,
                cid: entry.v.toString(),
                value
            });
        }
    }

    res.json({ records });
  } catch (err) {
    console.error('Error in listRecords:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/app.bsky.feed.getPosts', async (req, res) => {
  try {
    const { uris } = req.query;
    const requestedUris = Array.isArray(uris) ? uris : [uris];
    const user = await getSingleUser(req);
    if (!user) return res.status(500).json({ error: 'ServerNotInitialized' });

    const profileRes = await getRecordHelper(user.did, 'app.bsky.actor.profile', 'self');
    const profile = profileRes?.value;
    const repoCreatedAt = await getSystemMeta('repo_created_at') || new Date().toISOString();

    const author = {
        did: user.did,
        handle: user.handle,
        displayName: profile?.displayName || user.handle,
        avatar: profile?.avatar,
        associated: {
            activitySubscription: { allowSubscriptions: 'followers' }
        },
        labels: [],
        createdAt: repoCreatedAt,
        indexedAt: new Date().toISOString(),
    };

    const posts = [];
    for (const uri of requestedUris) {
        if (!uri) continue;
        // at://did:plc:123/app.bsky.feed.post/456
        const parts = uri.replace('at://', '').split('/');
        const repo = parts[0];
        const collection = parts[1];
        const rkey = parts[2];

        if (collection !== 'app.bsky.feed.post') continue;

        const recordRes = await getRecordHelper(repo, collection, rkey);
        if (recordRes) {
            posts.push({
                uri,
                cid: recordRes.cid,
                author,
                record: recordRes.value,
                replyCount: 0, // Placeholder
                repostCount: 0,
                likeCount: 0,
                quoteCount: 0,
                bookmarkCount: 0,
                indexedAt: recordRes.value.createdAt || new Date().toISOString(),
                labels: [],
            });
        }
    }

    res.json({ posts });
  } catch (err) {
    console.error('Error in getPosts:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.repo.getRecord', async (req, res) => {
  const { repo, collection, rkey } = req.query;
  const record = await getRecordHelper(repo, collection, rkey);
  
  if (!record) return res.status(404).json({ error: 'RecordNotFound' });
  
  const user = await getSingleUser(req);
  res.json({ uri: `at://${user.did}/${collection}/${rkey}`, value: record.value, cid: record.cid });
});

app.get('/xrpc/com.atproto.repo.describeRepo', async (req, res) => {
  try {
    const { repo } = req.query;
    const user = await getSingleUser(req);
    if (!user || (repo !== user.did && repo !== user.handle)) {
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    const host = getHost(req);
    const didDoc = await getDidDoc(req, host);

    res.json({
        handle: user.handle,
        did: user.did,
        didDoc: didDoc,
        collections: [
            'app.bsky.actor.profile',
            'app.bsky.feed.post',
            'app.bsky.feed.like',
            'app.bsky.feed.repost',
            'app.bsky.graph.follow'
        ],
        handleIsCorrect: true,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.getRecord', async (req, res) => {
  try {
    const { did, collection, rkey } = req.query;
    const pdsDid = (process.env.PDS_DID || '').trim();
    if (did && pdsDid && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });

    const storage = new TursoStorage();
    const rootCid = await getRootCid();
    const repoObj = await Repo.load(storage, CID.parse(rootCid));
    const record = await repoObj.getRecord(collection, rkey);

    if (!record) return res.status(404).json({ error: 'RecordNotFound' });

    // Note: getRecord in sync usually returns proof (blocks), but we'll provide the data
    res.json({
        uri: `at://${did}/${collection}/${rkey}`,
        cid: (await repoObj.data.get(`${collection}/${rkey}`)).toString(),
        value: record
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.head('/xrpc/com.atproto.sync.getHead', (req, res) => res.status(200).end());
app.get('/xrpc/com.atproto.sync.getHead', async (req, res) => {
  try {
    const { did } = req.query;
    const pdsDid = (process.env.PDS_DID || '').trim();
    console.log(`[SYNC] getHead: requested=${did}, authoritative=${pdsDid}`);
    if (did && pdsDid && did.toLowerCase() !== pdsDid.toLowerCase()) {
        console.log(`[SYNC] getHead: DID mismatch: ${did} !== ${pdsDid}`);
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    const rootCid = await getRootCid();
    if (!rootCid) {
        console.log(`[SYNC] getHead: Root CID not found`);
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    res.setHeader('Content-Type', 'application/json');
    res.json({ root: rootCid });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.head('/xrpc/com.atproto.sync.getLatestCommit', (req, res) => res.status(200).end());
app.get('/xrpc/com.atproto.sync.getLatestCommit', async (req, res) => {
  try {
    const { did } = req.query;
    const pdsDid = (process.env.PDS_DID || '').trim();
    console.log(`TAP getLatestCommit: did=${did}, pdsDid=${pdsDid}`);
    if (did && pdsDid && did !== pdsDid) {
        console.log(`TAP getLatestCommit: DID mismatch: ${did} !== ${pdsDid}`);
        return res.status(404).json({ error: 'RepoNotFound' });
    }

    const rootCid = await getRootCid();
    const result = await db.execute({
      sql: 'SELECT event FROM sequencer WHERE type = "commit" ORDER BY seq DESC LIMIT 1',
    });

    if (result.rows.length === 0 || !rootCid) {
        console.log(`TAP getLatestCommit: No sequencer event or Root CID found`);
        return res.status(404).json({ error: 'RepoNotFound' });
    }
    const event = cborDecode(new Uint8Array(result.rows[0].event));

    res.setHeader('Content-Type', 'application/json');
    res.json({
        cid: rootCid,
        rev: event.rev,
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/_health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

app.get('/xrpc/com.atproto.sync.getRepoStatus', async (req, res) => {
  try {
    const { did } = req.query;
    const pdsDid = (process.env.PDS_DID || '').trim();
    if (did && pdsDid && did.toLowerCase() !== pdsDid.toLowerCase()) {
      return res.status(404).json({ error: 'RepoNotFound' });
    }

    const result = await db.execute({
      sql: 'SELECT event FROM sequencer WHERE type = "commit" ORDER BY seq DESC LIMIT 1',
    });

    let rev = '';
    if (result.rows.length > 0) {
      const event = cborDecode(new Uint8Array(result.rows[0].event));
      rev = event.rev || '';
    }

    res.json({
      did: pdsDid,
      active: true,
      status: 'active',
      rev: rev
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.listRepos', async (req, res) => {
  try {
    const pdsDid = (process.env.PDS_DID || '').trim();
    const rootCid = await getRootCid();
    if (!pdsDid || !rootCid) {
        console.log(`TAP listRepos: PDS_DID or Root CID not found`);
        return res.json({ repos: [] });
    }

    res.json({
        repos: [{
            did: pdsDid,
            head: rootCid,
        }]
    });
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

// WebSocket Firehose for subscribeRepos
app.get('/xrpc/com.atproto.sync.subscribeRepos', async (req, res) => {
  // If this is a regular HTTP request, provide a helpful message
  if (req.headers.upgrade !== 'websocket') {
    return res.status(200).send('WebSocket firehose endpoint. Use a WebSocket client to subscribe.');
  }
  // WebSocket upgrades are handled at the server level (see api/index.js)
});

app.get('/xrpc/com.atproto.sync.getBlocks', async (req, res) => {
  try {
    const { did, cids } = req.query;
    const pdsDid = (process.env.PDS_DID || '').trim();
    if (did && pdsDid && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });

    const storage = new TursoStorage();
    const blocks = [];
    const requestedCids = Array.isArray(cids) ? cids : [cids];
    
    for (const cidStr of requestedCids) {
      if (!cidStr) continue;
      const block = await storage.get(CID.parse(cidStr));
      if (block) blocks.push(block);
    }

    const car = await blocksToCarFile(CID.parse(requestedCids[0]), blocks);
    res.setHeader('Content-Type', 'application/vnd.ipld.car');
    res.send(Buffer.from(car));
  } catch (err) {
    res.status(500).json({ error: 'InternalServerError' });
  }
});

app.get('/xrpc/com.atproto.sync.getRepo', async (req, res) => {
  const { did, since } = req.query;
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (did && pdsDid && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });
  
  const rootCid = await getRootCid();
  if (!rootCid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(rootCid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

app.get('/xrpc/com.atproto.sync.getCheckout', async (req, res) => {
  const { did } = req.query;
  const pdsDid = (process.env.PDS_DID || '').trim();
  if (did && pdsDid && did !== pdsDid) return res.status(404).json({ error: 'RepoNotFound' });
  
  const rootCid = await getRootCid();
  if (!rootCid) return res.status(404).json({ error: 'RepoNotFound' });

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(rootCid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

export default app;
