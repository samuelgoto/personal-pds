import { WebSocket } from 'ws';
import { cborDecode } from '@atproto/common';

const PDS_URL = process.argv[2] || 'wss://pds.sgo.to';
const wsUrl = `${PDS_URL}/xrpc/com.atproto.sync.subscribeRepos`;

console.log(`Connecting to firehose: ${wsUrl}...`);

const ws = new WebSocket(wsUrl);

ws.on('open', () => {
  console.log('✅ Connected to firehose!');
});

ws.on('message', (data) => {
  try {
    // ATProto frames are two CBOR objects concatenated: [header, body]
    // Since we are using @atproto/common's cborDecode, we might need to handle the concat.
    // A simple way is to use a library that handles streaming CBOR, but for debugging
    // we can try to find the boundary or use a simplified approach.
    
    console.log(`
--- Received Frame (${data.length} bytes) ---`);
    
    // Most frames start with a small header. 
    // In our implementation, we concat them.
    // Let's try to decode the whole thing or inspect the bytes.
    
    // For now, let's just log that we got data and try a basic decode
    try {
        const decoded = cborDecode(data);
        console.log('Decoded Body:', JSON.stringify(decoded, (key, value) => 
            value instanceof Uint8Array ? `[Uint8Array ${value.length}]` : value
        , 2));
    } catch (e) {
        console.log('Basic decode failed, frame might be multi-part. Hex head:', data.slice(0, 20).toString('hex'));
    }

  } catch (err) {
    console.error('Processing error:', err);
  }
});

ws.on('error', (err) => {
  console.error('WebSocket Error:', err);
});

ws.on('close', () => {
  console.log('Disconnected from firehose.');
});
