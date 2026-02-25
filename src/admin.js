import express from 'express';
import { db } from './db.js';
import { cborDecode } from './util.js';
import { getHost, getSystemMeta } from './server.js';

const router = express.Router();

router.get('/', async (req, res) => {
  const user = req.user;
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

router.post('/debug/reset', async (req, res) => {
  try {
    const { password } = req.body;
    const user = req.user;
    if (!password || !user || password !== user.password) {
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


export default router;
