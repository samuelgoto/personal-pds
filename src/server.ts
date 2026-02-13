import express from 'express';
import { db } from './db';
import { createToken, verifyToken } from './auth';
import { TursoStorage } from './repo';
import { Repo, WriteOpAction, blocksToCarFile } from '@atproto/repo';
import * as crypto from '@atproto/crypto';
import { CID } from 'multiformats/cid';
import { sequencer } from './sequencer';
import { WebSocketServer } from 'ws';

const app = express();
app.use(express.json());

// Setup WebSocket server for firehose
export const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url || '', `http://${req.headers.host}`);
  const cursor = url.searchParams.get('cursor');
  sequencer.addClient(ws, cursor ? parseInt(cursor, 10) : undefined);
});

// did:web support
app.get('/.well-known/did.json', async (req, res) => {
  const host = req.get('host');
  // In a single-user PDS, we might still have multiple "hosts" during tests
  // Let's find the account that matches the requested host
  const account = await db.execute({
    sql: 'SELECT did, signing_key FROM account WHERE did LIKE ?',
    args: [`%${host}`]
  });
  
  if (account.rows.length === 0) {
    // Fallback to first account if no direct match (for production)
    const fallback = await db.execute('SELECT did, signing_key FROM account LIMIT 1');
    if (fallback.rows.length === 0) return res.status(404).send('Not Found');
    const { did, signing_key } = fallback.rows[0] as any;
    return serveDidDoc(res, did, signing_key, host!);
  }
  
  const { did, signing_key } = account.rows[0] as any;
  serveDidDoc(res, did, signing_key, host!);
});

async function serveDidDoc(res: any, did: string, signing_key: any, host: string) {
  const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(signing_key));
  res.json({
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": did,
    "service": [
      {
        "id": "#atproto_pds",
        "type": "AtprotoPersonalDataServer",
        "serviceEndpoint": `https://${host}`
      }
    ],
    "verificationMethod": [
      {
        "id": `${did}#atproto`,
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyMultibase": keypair.did().split(':').pop()
      }
    ],
    "authentication": [`${did}#atproto`]
  });
}

// XRPC: resolveHandle
app.get('/xrpc/com.atproto.identity.resolveHandle', async (req, res) => {
  const { handle } = req.query as any;
  const user = await getSingleUser(req);
  if (!user || handle !== user.handle) {
    return res.status(404).json({ error: 'HandleNotFound' });
  }
  res.json({ did: user.did });
});

// Helper to get the single allowed user
const getSingleUser = async (req: express.Request) => {
  const host = req.get('host') || 'localhost';
  let handle = host.split(':')[0]; // Use hostname as handle
  if (handle === 'localhost') handle = 'localhost.test'; // Lexicon validation requires a dot
  const password = process.env.PASSWORD || 'admin';
  
  const account = await db.execute({
    sql: 'SELECT did, signing_key, root_cid FROM account LIMIT 1'
  });
  
  if (account.rows.length === 0) return null;
  
  return {
    handle,
    password,
    did: account.rows[0].did as string,
    signing_key: account.rows[0].signing_key as any,
    root_cid: account.rows[0].root_cid as string
  };
};

// XRPC: createSession
app.post('/xrpc/com.atproto.server.createSession', async (req, res) => {
  const { identifier, password } = req.body;
  const user = await getSingleUser(req);
  
  if (!user) return res.status(500).json({ error: 'ServerNotInitialized' });
  
  console.log(`createSession debug: identifier=${identifier}, user.handle=${user.handle}, user.did=${user.did}`);

  // Accept either the handle or the DID as identifier
  if (identifier !== user.handle && identifier !== user.did) {
    return res.status(401).json({ error: 'InvalidIdentifier' });
  }
  
  if (password !== user.password) {
    return res.status(401).json({ error: 'InvalidPassword' });
  }
  
  const accessJwt = createToken(user.did, user.handle);
  
  res.json({
    accessJwt,
    refreshJwt: accessJwt,
    handle: user.handle,
    did: user.did
  });
});

const auth = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'AuthenticationRequired' });
  const token = authHeader.split(' ')[1];
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'InvalidToken' });
  req.user = payload;
  next();
};

app.get('/xrpc/com.atproto.server.getSession', auth, async (req: any, res) => {
  res.json({
    handle: req.user.handle,
    did: req.user.sub
  });
});

// XRPC: createRecord
app.post('/xrpc/com.atproto.repo.createRecord', auth, async (req: any, res) => {
  try {
    const { repo, collection, record, rkey } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    // Create a record key if not provided
    const finalRkey = rkey || Date.now().toString(32);
    
    const updatedRepo = await repoObj.applyWrites([
      {
        action: WriteOpAction.Create,
        collection,
        rkey: finalRkey,
        record
      }
    ], keypair);
    
    await db.execute({
      sql: 'UPDATE account SET root_cid = ? WHERE did = ?',
      args: [updatedRepo.cid.toString(), user.did]
    });

    // Sequence the commit for the firehose
    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'create', path: `${collection}/${finalRkey}`, cid: updatedRepo.cid }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({
      uri: `at://${user.did}/${collection}/${finalRkey}`,
      cid: updatedRepo.cid.toString()
    });
  } catch (err) {
    console.error('Error in createRecord:', err);
    res.status(500).json({ error: 'InternalServerError', message: err instanceof Error ? err.message : String(err) });
  }
});

// XRPC: putRecord (Update or Create)
app.post('/xrpc/com.atproto.repo.putRecord', auth, async (req: any, res) => {
  try {
    const { repo, collection, rkey, record } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const updatedRepo = await repoObj.applyWrites([
      {
        action: WriteOpAction.Update,
        collection,
        rkey,
        record
      }
    ], keypair);
    
    await db.execute({
      sql: 'UPDATE account SET root_cid = ? WHERE did = ?',
      args: [updatedRepo.cid.toString(), user.did]
    });

    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'update', path: `${collection}/${rkey}`, cid: updatedRepo.cid }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({
      uri: `at://${user.did}/${collection}/${rkey}`,
      cid: updatedRepo.cid.toString()
    });
  } catch (err) {
    console.error('Error in putRecord:', err);
    res.status(500).json({ error: 'InternalServerError', message: err instanceof Error ? err.message : String(err) });
  }
});

// XRPC: deleteRecord
app.post('/xrpc/com.atproto.repo.deleteRecord', auth, async (req: any, res) => {
  try {
    const { repo, collection, rkey } = req.body;
    const user = await getSingleUser(req);
    if (!user || repo !== user.did) return res.status(403).json({ error: 'InvalidRepo' });
    
    const storage = new TursoStorage();
    const keypair = await crypto.Secp256k1Keypair.import(new Uint8Array(user.signing_key));
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const updatedRepo = await repoObj.applyWrites([
      {
        action: WriteOpAction.Delete,
        collection,
        rkey
      }
    ], keypair);
    
    await db.execute({
      sql: 'UPDATE account SET root_cid = ? WHERE did = ?',
      args: [updatedRepo.cid.toString(), user.did]
    });

    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: user.did,
      event: {
        repo: user.did,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'delete', path: `${collection}/${rkey}`, cid: null }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({ commit: { cid: updatedRepo.cid.toString(), rev: updatedRepo.commit.rev } });
  } catch (err) {
    console.error('Error in deleteRecord:', err);
    res.status(500).json({ error: 'InternalServerError', message: err instanceof Error ? err.message : String(err) });
  }
});

// XRPC: describeServer
app.get('/xrpc/com.atproto.server.describeServer', async (req, res) => {
  const account = await db.execute('SELECT did FROM account LIMIT 1');
  res.json({
    availableUserDomains: [],
    did: account.rows[0]?.did || 'did:web:unknown'
  });
});

// XRPC: listRecords
app.get('/xrpc/com.atproto.repo.listRecords', async (req, res) => {
  try {
    const { repo, collection, limit, cursor } = req.query as any;
    const user = await getSingleUser(req);
    if (!user || (repo !== user.did && repo !== user.handle)) return res.status(404).json({ error: 'RepoNotFound' });

    const storage = new TursoStorage();
    const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
    
    const records: any[] = [];
    for await (const rec of repoObj.walkRecords()) {
      if (rec.collection === collection) {
        records.push({
          uri: `at://${user.did}/${rec.collection}/${rec.rkey}`,
          cid: rec.cid.toString(),
          value: rec.record
        });
      }
    }

    // Basic limit implementation
    const finalRecords = records.slice(0, parseInt(limit || '50', 10));

    res.json({
      records: finalRecords
    });
  } catch (err) {
    console.error('Error in listRecords:', err);
    res.status(500).json({ error: 'InternalServerError' });
  }
});

// XRPC: getRecord
app.get('/xrpc/com.atproto.repo.getRecord', async (req, res) => {
  const { repo, collection, rkey } = req.query as any;
  const user = await getSingleUser(req);
  if (!user || (repo !== user.did && repo !== user.handle)) return res.status(404).json({ error: 'RepoNotFound' });
  
  const storage = new TursoStorage();
  const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
  const record = await repoObj.getRecord(collection, rkey);
  
  if (!record) return res.status(404).json({ error: 'RecordNotFound' });
  
  res.json({
    uri: `at://${user.did}/${collection}/${rkey}`,
    value: record
  });
});

// XRPC: getRepo (sync)
app.get('/xrpc/com.atproto.sync.getRepo', async (req, res) => {
  const { did } = req.query as any;
  console.log(`getRepo request for did: ${did}`);
  const userResult = await db.execute({
    sql: 'SELECT root_cid FROM account WHERE did = ?',
    args: [did]
  });
  if (userResult.rows.length === 0) {
    console.log(`Repo not found for did: ${did}`);
    return res.status(404).json({ error: 'RepoNotFound' });
  }
  const user = userResult.rows[0] as any;

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(user.root_cid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

export default app;
