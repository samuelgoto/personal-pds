import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import { initDb, db } from './db.js';
import app, { wss } from './server.js';
import { setLastRelayPing } from './admin.js';
import { maybeInitRepo } from './repo.js';

const PORT = process.env.PORT || 3000;

const RELAY_URL = process.env.RELAY_URL || 'https://bsky.network';

async function pingRelay(hostname) {
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
    setLastRelayPing(new Date().toISOString());
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
  console.log('Checking environment variables...');
  
  const required = ['HANDLE', 'PDS_DID', 'PRIVATE_KEY', 'PASSWORD', 'TURSO_DATABASE_URL'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  console.log('Initializing PDS...');
  await initDb(db);
  await maybeInitRepo();
  initialized = true;
  console.log('Initialization complete.');
}

// Global error handlers
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

// Start the server
initialize().then(() => {
  const serverInst = http.createServer(app);

  // Handle WebSocket upgrades for the firehose
  serverInst.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname.startsWith('/xrpc/com.atproto.sync.subscribeRepos')) {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  serverInst.listen(PORT, () => {
    console.log(`Minimal PDS listening on port ${PORT}`);
    const domain = process.env.HANDLE || 'pds.sgo.to';
    
    // Proactively ping relay on startup
    setTimeout(async () => {
        console.log(`Attempting to ping relay for ${domain}...`);
        await pingRelay(domain);
    }, 20000); 
  });
}).catch(err => {
  console.error('CRITICAL STARTUP ERROR:', err);
  process.exit(1);
});
