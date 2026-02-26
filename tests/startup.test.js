import { spawn } from 'child_process';
import axios from 'axios';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Server Startup', () => {
  let serverProcess;
  const PORT = 3010;
  const dbName = `startup-${Date.now()}.db`;
  const dbPath = path.join(__dirname, dbName);

  afterAll(async () => {
    if (serverProcess) {
      serverProcess.kill();
    }
    // Small delay to allow process to exit and release file handles
    await new Promise(resolve => setTimeout(resolve, 500));
    
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
    const shmPath = `${dbPath}-shm`;
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
  });

  test('should start and respond to health check', async () => {
    // 1. Start the server via src/index.js in a subprocess
    serverProcess = spawn('node', ['src/index.js'], {
      env: {
        ...process.env,
        PORT: PORT.toString(),
        TURSO_DATABASE_URL: `file:${dbPath}`,
        TURSO_AUTH_TOKEN: 'test-token',
        HANDLE: 'localhost.test',
        PDS_DID: 'did:plc:test',
        PRIVATE_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', // 64-char hex
        PASSWORD: 'test-password'
      },
      stdio: 'pipe'
    });

    let stdout = '';
    serverProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    // 2. Wait for the server to be ready (up to 10 seconds)
    let isReady = false;
    for (let i = 0; i < 20; i++) {
      try {
        const res = await axios.get(`http://localhost:${PORT}/xrpc/_health`);
        if (res.status === 200) {
          isReady = true;
          break;
        }
      } catch (e) {
        // Not ready yet
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    if (!isReady) {
        console.log('Server Output:', stdout);
    }
    expect(isReady).toBe(true);
  }, 15000);
});
