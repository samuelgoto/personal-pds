import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import { initDb, db } from './src/db.js';
import app, { wss } from './src/server.js';
import { maybeInitRepo } from './src/repo.js';

const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN;
const RELAY_URL = process.env.RELAY_URL || 'https://bsky.network';

async function pingRelay() {
  if (!DOMAIN || DOMAIN.includes('localhost') || DOMAIN.includes('127.0.0.1')) {
    console.log('Skipping relay ping: PDS is running on localhost or DOMAIN not set.');
    return;
  }

  try {
    const hostname = new URL(`https://${DOMAIN}`).hostname;
    console.log(`Pinging relay ${RELAY_URL} to crawl ${hostname}...`);
    await axios.post(`${RELAY_URL}/xrpc/com.atproto.sync.requestCrawl`, {
      hostname: hostname
    });
    await db.execute({
      sql: "INSERT OR REPLACE INTO system_state (key, value) VALUES ('last_relay_ping', ?)",
      args: [new Date().toISOString()]
    });
    console.log('Relay notified successfully.');
  } catch (err: any) {
    console.error('Failed to notify relay:', err.response?.data || err.message);
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

// Middleware to ensure initialization on serverless platforms
app.use(async (req, res, next) => {
  try {
    await initialize();
    next();
  } catch (err: any) {
    res.status(500).send(`Server Initialization Error: ${err.message}`);
  }
});

// For local development
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  initialize().then(() => {
    const server = http.createServer(app);

    server.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });

    server.listen(PORT, () => {
      console.log(`Minimal PDS listening on port ${PORT}`);
      pingRelay().catch(console.error);
    });
  }).catch(console.error);
}

// Export the app for Vercel
export default app;
