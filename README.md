# Personal PDS (AT Protocol)

A lightweight, modular, single-user AT Protocol Personal Data Server (PDS) built with Node.js, Express 5, and Turso. Optimized for self-hosting your identity and data on the Bluesky network.

## Key Features

- **Modular Architecture**: Clean separation of concerns between core server, OAuth flow, proxy logic, and repository management.
- **Single-User Design**: Identity and configuration are managed via environment variables and initialized at startup.
- **Robust OAuth 2.1**: Full implementation of ATProto OAuth, including DPoP token binding and Pushed Authorization Requests (PAR).
- **Turso Integration**: Scalable, edge-ready storage using LibSQL.
- **Real-time Firehose**: Canonical `dag-cbor` event streaming for indexing by the Bluesky network.
- **Express 5 Native**: Leverages native async error handling for cleaner, more reliable middleware and handlers.

## Architecture & Components

- **`src/server.js`**: Core route aggregator and protocol handlers.
- **`src/oauth.js`**: Complete OAuth/OIDC implementation (Metadata, PAR, Authorize, Token, JWKS).
- **`src/auth.js`**: Authentication middleware and token validation (Bearer & DPoP).
- **`src/repo.js`**: ATProto Repository management (MST, Blockstore, CAR exports).
- **`src/proxy.js`**: Intelligent XRPC proxying with Service Authentication for external AppViews.
- **`src/sequencer.js`**: Firehose event sequencing and WebSocket broadcasting.
- **`src/admin.js`**: Web-based dashboard for PDS monitoring and management.

## Implemented XRPC Handlers

### com.atproto (Core)
- `server.describeServer`: Server metadata.
- `server.getServiceContext`: Service identity resolution.
- `server.createSession` / `refreshSession`: Legacy session management.
- `server.getSession` / `getAccount`: Authenticated account details.
- `server.checkAccountStatus`: Account health and repo head.
- `identity.resolveDid` / `resolveHandle`: Local and proxied identity resolution.
- `repo.createRecord` / `putRecord` / `deleteRecord`: Data modifications.
- `repo.applyWrites`: Batch data operations.
- `repo.listRecords` / `getRecord` / `describeRepo`: Data retrieval.
- `repo.uploadBlob` / `sync.getBlob`: Blob storage and retrieval.
- `sync.getRepo` / `getCheckout` / `getBlocks`: Repository synchronization.
- `sync.getHead` / `getLatestCommit` / `getRepoStatus`: Head and sequence tracking.
- `sync.subscribeRepos`: Firehose (WebSocket).

### app.bsky (Bluesky)
- `app.bsky.actor.getPreferences` / `putPreferences`: Local preference storage.
- All other `app.bsky.*` methods are intelligently proxied to the configured AppView with Service Auth.

### OAuth / OIDC
- `POST /oauth/par`: Pushed Authorization Request.
- `GET/POST /oauth/authorize`: Authorization UI and logic.
- `POST /oauth/token`: Token exchange (Code & Refresh).
- `GET /.well-known/oauth-authorization-server`: OAuth metadata.
- `GET /.well-known/oauth-protected-resource`: Resource server metadata.
- `GET /.well-known/openid-configuration`: OIDC discovery.
- `GET /.well-known/jwks.json`: Public keys for token verification.

## Database Schema (Turso/SQLite)

The PDS uses a streamlined schema for repository data, identity, and OAuth state:

- `repo_blocks`: Content-addressed storage for repository MST nodes and records (`cid`, `block`).
- `blobs`: User-uploaded media and files (`cid`, `did`, `mime_type`, `content`, `created_at`).
- `sequencer`: Firehose event log for relay indexing (`seq`, `did`, `type`, `event`, `time`).
- `preferences`: Local user preferences and birthdate (`key`, `value`).
- `sessions`: Legacy session tracking (`id`, `handle`, `did`, `expires_at`).
- `oauth_codes`: Temporary authorization codes (`code`, `client_id`, `redirect_uri`, `scope`, `did`, `dpop_jwk`, `expires_at`).
- `oauth_refresh_tokens`: Long-lived refresh tokens (`token`, `client_id`, `did`, `scope`, `dpop_jwk`, `expires_at`).
- `oauth_par_requests`: Pending authorization requests (`request_uri`, `client_id`, `request_data`, `expires_at`).

## Setup & Deployment

### 1. Environment Configuration
Required variables: `HANDLE`, `PDS_DID`, `PRIVATE_KEY`, `PASSWORD`, `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`.

### 2. Initialization
```bash
node scripts/run-setup.js
```

### 3. Testing
```bash
npm test
```

## License
ISC
