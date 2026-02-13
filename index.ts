import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import { initDb, db } from './src/db';
import app, { wss } from './src/server';
import { maybeInitRepo } from './src/repo';

const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || 'localhost:3000';
const RELAY_URL = process.env.RELAY_URL || 'https://bsky.network';

async function pingRelay() {
  if (DOMAIN.includes('localhost') || DOMAIN.includes('127.0.0.1')) {
    console.log('Skipping relay ping: PDS is running on localhost.');
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

async function start() {
  if (!process.env.PASSWORD) {
    console.error('FATAL: PASSWORD environment variable is not set.');
    process.exit(1);
  }

  await initDb(db);
  await maybeInitRepo();
  
  const server = http.createServer(app);

  server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  });

  server.listen(PORT, () => {
    console.log(`Minimal PDS listening on port ${PORT}`);
    
    // Notify the relay that we are online
    pingRelay().catch(console.error);
  });
}

start().catch(console.error);
