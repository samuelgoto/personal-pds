import 'dotenv/config';
import http from 'http';
import axios from 'axios';
import { initDb, db } from './db.js';
import app, { wss, pingRelay } from './server.js';

const PORT = process.env.PORT || 3000;

// Initialization promise to ensure it only runs once
let initialized = false;
async function initialize() {
  if (initialized) return;
  console.log('Initializing PDS...');
  if (!process.env.PASSWORD) {
    throw new Error('PASSWORD environment variable is not set');
  }
  const dbUrl = process.env.TURSO_DATABASE_URL;
  if (!dbUrl) {
    throw new Error('TURSO_DATABASE_URL environment variable is not set');
  }
  await initDb(db);
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
    const domain = process.env.DOMAIN || 'pds.sgo.to';
    
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
