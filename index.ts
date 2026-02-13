import 'dotenv/config';
import { initDb } from './src/db';
import app from './src/server';

const PORT = process.env.PORT || 3000;

async function start() {
  await initDb();
  app.listen(PORT, () => {
    console.log(`Minimal PDS listening on port ${PORT}`);
  });
}

start().catch(console.error);
