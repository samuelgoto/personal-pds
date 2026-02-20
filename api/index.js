import 'dotenv/config';
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
  if (!process.env.PASSWORD) {
    throw new Error('PASSWORD environment variable is not set');
  }
  await initDb(db);
  await maybeInitRepo();
  initialized = true;
}

// Global ping status to ensure we only ping once per session
let pinged = false;

// Middleware to ensure initialization on serverless platforms
app.use(async (req, res, next) => {
  try {
    await initialize();
    const host = getHost(req);
    if (!pinged && host) {
        pinged = true;
        pingRelay(host).catch(console.error);
    }
    next();
  } catch (err) {
    res.status(500).send(`Server Initialization Error: ${err.message}`);
  }
});

// For local development
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  initialize().then(() => {
    const serverInst = http.createServer(app);

    serverInst.listen(PORT, () => {
      console.log(`Minimal PDS listening on port ${PORT}`);
    });
  }).catch(console.error);
}

// Export the app for Vercel
export default app;
