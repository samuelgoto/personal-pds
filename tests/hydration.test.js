import 'dotenv/config';
import { jest } from '@jest/globals';
import http from 'http';
import axios from 'axios';
import app, { wss } from '../src/server.js';
import { createDb, setDb } from '../src/db.js';
import { formatDid } from '../src/util.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { runFullSetup } from '../src/setup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3010;
const HOST = `http://localhost:${PORT}`;

describe('Hybrid Hydration Tests', () => {
  let server;
  let userDid;
  let dbPath;
  let accessToken;

  beforeAll(async () => {
    // jest.spyOn(console, 'log').mockImplementation(() => {});
    // jest.spyOn(console, 'error').mockImplementation(() => {});
    
    process.env.PASSWORD = 'hydration-pass';
    process.env.HANDLE = 'hydration.test';
    const uniqueId = Date.now();
    process.env.PDS_DID = `did:plc:test-${uniqueId}`;
    dbPath = path.join(__dirname, `test-hydration-${uniqueId}.db`);
    const testDb = createDb(`file:${dbPath}`);
    setDb(testDb);

    await runFullSetup({ db: testDb, skipPlc: true });
    userDid = formatDid('hydration.test');

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(PORT, resolve));

    // Login to get token
    const loginRes = await axios.post(`${HOST}/xrpc/com.atproto.server.createSession`, {
      identifier: 'hydration.test',
      password: 'hydration-pass'
    });
    accessToken = loginRes.data.accessJwt;
  });

  afterAll(async () => {
    server.close();
    wss.close();
  });

  test('Profile counts should reflect local data', async () => {
    // Initial profile
    const res = await axios.get(`${HOST}/xrpc/app.bsky.actor.getProfile?actor=${userDid}`);
    expect(res.data.postsCount).toBe(0);
    expect(res.data.followsCount).toBe(0);

    // 1. Create a local post
    await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: {
        text: 'Hydration post',
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.feed.post'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });

    // 2. Follow someone
    await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.graph.follow',
      record: {
        subject: 'did:plc:someone-else',
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.graph.follow'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });

    // Check profile again
    const res2 = await axios.get(`${HOST}/xrpc/app.bsky.actor.getProfile?actor=${userDid}`);
    expect(res2.data.postsCount).toBe(1);
    expect(res2.data.followsCount).toBe(1);
  });

  test('Posts should have likes, reposts, and viewer status hydrated', async () => {
    // 1. Create a post
    const postRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: {
        text: 'Likes test',
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.feed.post'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });
    const postUri = postRes.data.uri;

    // 2. Like it
    const likeRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.like',
      record: {
        subject: { uri: postUri, cid: postRes.data.cid },
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.feed.like'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });

    // 3. Repost it
    const repostRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.repost',
      record: {
        subject: { uri: postUri, cid: postRes.data.cid },
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.feed.repost'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });

    // 4. Verify Author Feed
    const feedRes = await axios.get(`${HOST}/xrpc/app.bsky.feed.getAuthorFeed?actor=${userDid}`);
    const postInFeed = feedRes.data.feed.find(item => item.post.uri === postUri).post;
    
    expect(postInFeed.likeCount).toBe(1);
    expect(postInFeed.repostCount).toBe(1);
    expect(postInFeed.viewer.like).toBe(likeRes.data.uri);
    expect(postInFeed.viewer.repost).toBe(repostRes.data.uri);

    // 5. Verify Post Thread (V2)
    const threadRes = await axios.get(`${HOST}/xrpc/app.bsky.unspecced.getPostThreadV2?anchor=${encodeURIComponent(postUri)}`);
    const postInThread = threadRes.data.thread.find(item => item.uri === postUri).value.post;
    
    expect(postInThread.likeCount).toBe(1);
    expect(postInThread.repostCount).toBe(1);
    expect(postInThread.viewer.like).toBe(likeRes.data.uri);
    expect(postInThread.viewer.repost).toBe(repostRes.data.uri);
  });

  test('Quote posts should be hydrated with the embedded record view', async () => {
    // 1. Target post
    const targetRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: {
        text: 'Target post',
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.feed.post'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });

    // 2. Quote post
    const quoteRes = await axios.post(`${HOST}/xrpc/com.atproto.repo.createRecord`, {
      repo: userDid,
      collection: 'app.bsky.feed.post',
      record: {
        text: 'I am quoting this',
        embed: {
            $type: 'app.bsky.embed.record',
            record: {
                uri: targetRes.data.uri,
                cid: targetRes.data.cid
            }
        },
        createdAt: new Date().toISOString(),
        $type: 'app.bsky.feed.post'
      }
    }, { headers: { Authorization: `Bearer ${accessToken}` } });

    // 3. Verify hydration
    console.log(`[TEST] Verifying quote post: ${quoteRes.data.uri} quoting ${targetRes.data.uri}`);
    
    // Check quoted post for count
    const targetThread = await axios.get(`${HOST}/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(targetRes.data.uri)}`);
    expect(targetThread.data.thread.post.quoteCount).toBe(1);

    // Check quoting post for embed hydration
    const quoteThread = await axios.get(`${HOST}/xrpc/app.bsky.feed.getPostThread?uri=${encodeURIComponent(quoteRes.data.uri)}`);
    const post = quoteThread.data.thread.post;
    
    expect(post.embed).toBeDefined();
    expect(post.embed.$type).toBe('app.bsky.embed.record#view');
    expect(post.embed.record.uri).toBe(targetRes.data.uri);
    expect(post.embed.record.value.text).toBe('Target post');
  });
});
