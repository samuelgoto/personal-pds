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
  const account = await db.execute('SELECT did, signing_key FROM account LIMIT 1');
  if (account.rows.length === 0) return res.status(404).send('Not Found');
  
  const { did, signing_key } = account.rows[0] as any;
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
});

// XRPC: createSession
app.post('/xrpc/com.atproto.server.createSession', async (req, res) => {
  const { identifier, password } = req.body;
  const result = await db.execute({
    sql: 'SELECT * FROM account WHERE handle = ? OR did = ?',
    args: [identifier, identifier]
  });
  
  if (result.rows.length === 0) return res.status(401).json({ error: 'InvalidIdentifier' });
  const user = result.rows[0] as any;
  
  if (user.password !== password) return res.status(401).json({ error: 'InvalidPassword' });
  
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
    if (repo !== req.user.sub) return res.status(403).json({ error: 'InvalidRepo' });
    
    const userResult = await db.execute({
      sql: 'SELECT signing_key, root_cid FROM account WHERE did = ?',
      args: [req.user.sub]
    });
    if (userResult.rows.length === 0) return res.status(404).json({ error: 'UserNotFound' });
    const user = userResult.rows[0] as any;
    
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
      args: [updatedRepo.cid.toString(), req.user.sub]
    });

    // Sequence the commit for the firehose
    const carBlocks = await storage.getRepoBlocks();
    const blocks = await blocksToCarFile(updatedRepo.cid, carBlocks);

    await sequencer.sequenceEvent({
      type: 'commit',
      did: req.user.sub,
      event: {
        repo: req.user.sub,
        commit: updatedRepo.cid,
        blocks: blocks,
        rev: updatedRepo.commit.rev,
        since: repoObj.commit.rev,
        ops: [{ action: 'create', path: `${collection}/${finalRkey}`, cid: updatedRepo.cid }],
        time: new Date().toISOString(),
      }
    });
    
    res.json({
      uri: `at://${req.user.sub}/${collection}/${finalRkey}`,
      cid: updatedRepo.cid.toString()
    });
  } catch (err) {
    console.error('Error in createRecord:', err);
    res.status(500).json({ error: 'InternalServerError', message: err instanceof Error ? err.message : String(err) });
  }
});

// XRPC: getRecord
app.get('/xrpc/com.atproto.repo.getRecord', async (req, res) => {
  const { repo, collection, rkey } = req.query as any;
  const userResult = await db.execute({
    sql: 'SELECT root_cid FROM account WHERE did = ? OR handle = ?',
    args: [repo, repo]
  });
  if (userResult.rows.length === 0) return res.status(404).json({ error: 'RepoNotFound' });
  const user = userResult.rows[0] as any;
  
  const storage = new TursoStorage();
  const repoObj = await Repo.load(storage, CID.parse(user.root_cid));
  const record = await repoObj.getRecord(collection, rkey);
  
  if (!record) return res.status(404).json({ error: 'RecordNotFound' });
  
  res.json({
    uri: `at://${repo}/${collection}/${rkey}`,
    value: record
  });
});

// XRPC: getRepo (sync)
app.get('/xrpc/com.atproto.sync.getRepo', async (req, res) => {
  const { did } = req.query as any;
  const userResult = await db.execute({
    sql: 'SELECT root_cid FROM account WHERE did = ?',
    args: [did]
  });
  if (userResult.rows.length === 0) return res.status(404).json({ error: 'RepoNotFound' });
  const user = userResult.rows[0] as any;

  const storage = new TursoStorage();
  const blocks = await storage.getRepoBlocks();
  const car = await blocksToCarFile(CID.parse(user.root_cid), blocks);

  res.setHeader('Content-Type', 'application/vnd.ipld.car');
  res.send(Buffer.from(car));
});

export default app;
