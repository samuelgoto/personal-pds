# Personal PDS (AT Protocol)

A lightweight, single-user AT Protocol Personal Data Server (PDS) built with Node.js, Express, and Turso. Optimized for self-hosting your identity and data on the Bluesky network.

## Key Features

- **Stateless Single-User Design**: No complex account management. Your identity is derived directly from environment variables (`HANDLE`, `PDS_DID`, `PRIVATE_KEY`).
- **ATProto OAuth Support**: Full implementation of the modern ATProto OAuth flow, including:
  - **DPoP (Demonstrating Proof-of-Possession)** for secure token binding.
  - **PAR (Pushed Authorization Requests)** for improved security.
  - **OIDC ID Tokens** for seamless login with apps like `stream.place`.
- **Optimized Firehose**: Real-time event streaming via `com.atproto.sync.subscribeRepos` using canonical `dag-cbor` encoding and leaner CAR files (transmitting only diffs).
- **Lexicon Compliance**: Systematically verified against ATProto Lexicons for core XRPC endpoints.
- **Turso Integration**: Uses LibSQL for efficient, edge-ready data storage.

## Deployment & Setup

This project requires a **persistent hosting environment** (like Heroku, Railway, or a VPS) that supports long-lived WebSocket connections for the ATProto firehose. 

**Note**: Serverless platforms like Vercel or AWS Lambda are **not supported** because they cannot maintain the persistent WebSocket connection required for `com.atproto.sync.subscribeRepos`, which is essential for being indexed by the Bluesky network.

### 1. Prerequisites
- A **Turso** database and auth token.
- A domain name (e.g., `pds.your-domain.com`).
- A **did:plc** identity (the setup script will help you register one).

### 2. Environment Variables
Copy `.env.example` to your deployment environment and configure:
- `HANDLE`: Your PDS domain (e.g., `pds.sgo.to`).
- `PDS_DID`: Your primary account DID (e.g., `did:plc:...`).
- `PRIVATE_KEY`: Your Secp256k1 private key (hex).
- `TURSO_DATABASE_URL` & `TURSO_AUTH_TOKEN`: Your Turso credentials.
- `PASSWORD`: Your PDS login password.

### 3. Run Setup
Initialize your database and repository:
```bash
node scripts/run-setup.js
```

### 4. Run Tests
The project includes a comprehensive suite of 50+ tests covering interoperability, compliance, and OAuth flows:
```bash
npm test
```

## Implemented XRPC Endpoints

### Identity & Auth
- `GET /.well-known/atproto-did`: Handle resolution.
- `GET /.well-known/did.json`: PDS DID document.
- `GET /.well-known/jwks.json`: Public keys for OAuth.
- `GET /.well-known/oauth-authorization-server`: OAuth metadata.
- `com.atproto.identity.resolveHandle` & `resolveDid` (with proxy support).
- `com.atproto.server.createSession` & `checkAccountStatus`.

### Repository & Sync
- `com.atproto.repo.createRecord`, `putRecord`, `deleteRecord`, and `applyWrites`.
- `com.atproto.repo.uploadBlob` & `com.atproto.sync.getBlob`.
- `com.atproto.sync.getRepo` & `com.atproto.sync.subscribeRepos` (Firehose).

### App-Specific (Bsky)
- `app.bsky.actor.getProfile` & `getProfiles`.
- `app.bsky.feed.getAuthorFeed`, `getTimeline`, and `getPostThread`.

## License
ISC
