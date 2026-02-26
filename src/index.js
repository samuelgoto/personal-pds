import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import { connect, db } from './db.js';
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

// Validation & Initialization
if (!process.env.HANDLE) throw new Error('Missing HANDLE environment variable');
if (!process.env.PDS_DID) throw new Error('Missing PDS_DID environment variable');
if (!process.env.PRIVATE_KEY) throw new Error('Missing PRIVATE_KEY environment variable');
if (!process.env.PASSWORD) throw new Error('Missing PASSWORD environment variable');
if (!process.env.TURSO_DATABASE_URL) throw new Error('Missing TURSO_DATABASE_URL environment variable');

console.log('Initializing PDS...');
await connect();
await maybeInitRepo();
console.log('Initialization complete.');

const server = http.createServer(app);

// Handle WebSocket upgrades for the firehose
server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (url.pathname.startsWith('/xrpc/com.atproto.sync.subscribeRepos')) {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`Minimal PDS listening on port ${PORT}`);
  const domain = process.env.HANDLE;
  
  // Proactively ping relay on startup
  setTimeout(async () => {
      console.log(`Attempting to ping relay for ${domain}...`);
      await pingRelay(domain);
  }, 20000); 
});
