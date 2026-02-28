import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

// 1. Load the actual .env file if it exists (same as npm start)
dotenv.config();

// 2. Fallback to .env.example for any missing variables
// This ensures that anyone checking out the repo has a working test environment
// that is structurally identical to the production/dev environment.
const envExamplePath = path.resolve(process.cwd(), '.env.example');
if (fs.existsSync(envExamplePath)) {
  const envExample = dotenv.parse(fs.readFileSync(envExamplePath));
  for (const key in envExample) {
    if (!process.env[key]) {
      process.env[key] = envExample[key];
    }
  }
}

// 3. Apply critical test-only overrides
// We use PORT=0 so tests can run in parallel without "Address in use" errors
process.env.PORT = '0'; 
// We use a memory database so tests are fast and don't overwrite your local dev DB
process.env.TURSO_DATABASE_URL = 'file::memory:';
process.env.NODE_ENV = 'test';
