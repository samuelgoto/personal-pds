import 'dotenv/config';
import http from 'http';
import { initDb } from './src/db';
import app, { wss } from './src/server';

const PORT = process.env.PORT || 3000;

async function start() {
  await initDb();
  
  const server = http.createServer(app);

  server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  });

  server.listen(PORT, () => {
    console.log(`Minimal PDS listening on port ${PORT}`);
  });
}

start().catch(console.error);
