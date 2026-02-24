import axios from 'axios';

const anchor = 'at://pds.sgo.to/app.bsky.feed.post/3mfbq2qshrc2d';
const params = 'branchingFactor=1&below=10&sort=top';

const pdsUrl = `https://pds.sgo.to/xrpc/app.bsky.unspecced.getPostThreadV2?anchor=${encodeURIComponent(anchor)}&${params}`;
const bskyUrl = `https://public.api.bsky.app/xrpc/app.bsky.unspecced.getPostThreadV2?anchor=${encodeURIComponent(anchor)}&${params}`;

async function compare() {
  try {
    console.log('Fetching from PDS...');
    const pdsRes = await axios.get(pdsUrl).catch(e => ({ error: e.message, data: e.response?.data }));
    
    console.log('Fetching from Bluesky Public API...');
    const bskyRes = await axios.get(bskyUrl).catch(e => ({ error: e.message, data: e.response?.data }));

    console.log('\n--- PDS Response ---');
    console.log(JSON.stringify(pdsRes.data, null, 2));

    console.log('\n--- Bluesky Response ---');
    console.log(JSON.stringify(bskyRes.data, null, 2));

  } catch (err) {
    console.error('Comparison failed:', err);
  }
}

compare();
