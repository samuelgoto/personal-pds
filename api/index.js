import http from 'http';
import axios from 'axios';
import { initDb, db } from '../src/db.js';
import * as server from '../src/server.js';
import { maybeInitRepo } from '../src/repo.js';

const app = server.default;
const getHost = server.getHost;

const PORT = process.env.PORT || 3000;
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

// Initialization promise to ensure it only runs once
let initialized = false;
async function initialize() {
  if (initialized) return;
  console.log('Initializing PDS...');
  if (!process.env.PASSWORD) {
    throw new Error('PASSWORD environment variable is not set');
  }
  const dbUrl = process.env.TURSO_DATABASE_URL || process.env.DATABASE_URL;
  if (!dbUrl) {
    throw new Error('TURSO_DATABASE_URL or DATABASE_URL environment variable is not set');
  }
  await initDb(db);
  await maybeInitRepo();
  initialized = true;
  console.log('Initialization complete.');
}

// Global error handlers for better Heroku debugging
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Start the server
console.log('Starting server sequence...');
initialize().then(() => {
  const serverInst = http.createServer(app);

  // Handle WebSocket upgrades for the firehose
  serverInst.on('upgrade', (request, socket, head) => {
    if (request.url.startsWith('/xrpc/com.atproto.sync.subscribeRepos')) {
      console.log('Handling firehose upgrade request');
      server.wss.handleUpgrade(request, socket, head, (ws) => {
        server.wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  serverInst.listen(PORT, () => {
    console.log(`Minimal PDS listening on port ${PORT}`);
    const domain = process.env.DOMAIN || 'pds.sgo.to';
    console.log(`Authoritative Domain: ${domain}`);
    
// Proactively ping relay on startup to trigger crawl
    setTimeout(async () => {
        let attempts = 0;
        const maxAttempts = 3;
        while (attempts < maxAttempts) {
            try {
                console.log(`Attempt ${attempts + 1}: Pinging relay for ${domain}...`);
                const result = await pingRelay(domain);
                if (result.success) break;
                console.log(`Ping failed, retrying in 10s...`);
            } catch (e) {
                console.log(`Ping error, retrying in 10s...`);
            }
            attempts++;
            await new Promise(r => setTimeout(r, 10000));
        }
    }, 5000); // 5s initial delay for Heroku routing to stabilize
  });
}).catch(err => {
  console.error('CRITICAL STARTUP ERROR:', err);
  process.exit(1);
});

// Export the app for Vercel
export default app;
