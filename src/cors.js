export default (req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, DPoP, atproto-accept-labelers, atproto-proxy-type, atproto-proxy, atproto-proxy-exp, atproto-content-type, x-bsky-topics, x-bsky-active-labelers');
  res.setHeader('Access-Control-Expose-Headers', 'atproto-content-type, atproto-proxy, atproto-proxy-exp, x-bsky-topics, x-bsky-active-labelers');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
};
