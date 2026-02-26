import express from 'express';
import { db } from './db.js';
import * as cbor from '@ipld/dag-cbor';
import { sequencer } from './sequencer.js';

const router = express.Router();

router.get('/', async (req, res) => {
  const user = req.user;
  const blockCountRes = await db.execute('SELECT count(*) as count FROM repo_blocks');
  const eventCountRes = await db.execute('SELECT count(*) as count FROM sequencer');
  const subscriberCount = sequencer.getSubscriberCount();

  // Get last 10 blocks
  const lastBlocksRes = await db.execute("SELECT * FROM repo_blocks LIMIT 10");
  const blocks = lastBlocksRes.rows.map(row => {
    try {
      const data = cbor.decode(new Uint8Array(row.block));
      return { cid: row.cid, data };
    } catch (e) {
      return { cid: row.cid, data: { error: 'Failed to decode CBOR' } };
    }
  });

  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Personal PDS Dashboard</title>
    <style>
        body { font-family: -apple-system, sans-serif; line-height: 1.6; max-width: 1100px; margin: 40px auto; padding: 20px; background: #f4f4f9; color: #333; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h1 { color: #007bff; display: flex; align-items: center; gap: 10px; }
        h2 { border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 15px; }
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
        .block-item { background: #f8f9fa; border-radius: 4px; padding: 10px; margin-bottom: 10px; border: 1px solid #eee; }
        .block-item pre { margin: 10px 0 0 0; font-size: 0.8rem; overflow-x: auto; background: #fff; padding: 10px; border-radius: 4px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1><span>🌐</span> Personal PDS Dashboard</h1>
    
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div class="card">
            <h2>Identity</h2>
            <div class="stat"><span class="label">Handle</span><span class="value">${user.handle}</span></div>
            <div class="stat"><span class="label">DID</span><span class="value">${user.did}</span></div>
            <div class="stat"><span class="label">PDS Domain</span><span class="value">${user.host}</span></div>
        </div>

        <div class="card">
            <h2>Network & Status</h2>
            <div class="stat"><span class="label">PDS Status</span><span class="value status-ok">Online</span></div>
            <div class="stat"><span class="label">Relay Connections</span><span class="value ${subscriberCount > 0 ? 'status-ok' : 'status-warn'}">${subscriberCount}</span></div>
            <div class="actions">
                <button class="secondary" onclick="runAction('/xrpc/com.atproto.server.describeServer')">Self-Check</button>
            </div>
            <div id="action-result"></div>
        </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1.5fr; gap: 20px;">
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
            <h2>Recent Blocks (Storage)</h2>
            <div id="blocks-feed">
                ${blocks.length === 0 ? '<p>No blocks stored.</p>' : blocks.map(b => `
                    <div class="block-item">
                        <div style="font-size: 0.8rem; color: #657786; font-family: monospace; word-break: break-all;">${b.cid}</div>
                        <pre>${JSON.stringify(b.data, (key, value) => {
                            if (value instanceof Uint8Array) return `[Buffer ${value.length}]`;
                            if (value && typeof value === 'object' && value.asCID === value) return value.toString();
                            return value;
                        }, 2)}</pre>
                    </div>
                `).join('')}
            </div>
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
    
    res.send('<h1>Success</h1><p>PDS has been wiped clean.</p><a href="/">Back to Dashboard</a>');
});

export default router;
