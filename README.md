# Personal PDS (AT Protocol)

A lightweight, modular, single-user AT Protocol Personal Data Server (PDS) built with Node.js, Express 5, and Turso. Optimized for self-hosting your identity and data on the Bluesky network.

## Key Features

- **Modular Architecture**: Clean separation of concerns between core server, OAuth flow, proxy logic, and repository management.
- **Single-User Design**: Identity and configuration are managed via environment variables and initialized at startup.
- **Robust OAuth 2.1**: Full implementation of ATProto OAuth, including DPoP token binding and Pushed Authorization Requests (PAR).
- **FedCM + IndieAuth IdP**: Browser-facing IdP endpoints, Login Status accounts push, IdP Registration, and IndieAuth-style FedCM code exchange.
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

### FedCM / IndieAuth
- `GET /.well-known/web-identity`: FedCM discovery.
- `GET /config.json`: FedCM IdP config.
- `GET /profile`: Public IndieAuth profile URL with `rel="indieauth-metadata"`.
- `GET/POST /login`: Browser login page for Login Status + IdP registration.
- `POST /logout`: Browser logout page.
- `GET /accounts`: FedCM accounts endpoint.
- `POST /assertion`: FedCM assertion endpoint returning IndieAuth-style assertion payload.
- `POST /disconnect`: FedCM disconnect endpoint.

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

### 1. Generate a Private Key
Run the following command to generate a valid Secp256k1 private key for your PDS:
```bash
npm run gen-key
```

### 2. Environment Configuration
Create a `.env` file and populate it with the values generated above, along with your other details:
- `HANDLE`: Your PDS domain (e.g., `pds.your-domain.com`).
- `PDS_DID`: Your primary account DID (from `gen-key` or a registered `did:plc`).
- `PRIVATE_KEY`: Your generated private key.
- `PASSWORD`: Your PDS login password.
- `TURSO_DATABASE_URL`: Your Turso connection string.
- `TURSO_AUTH_TOKEN`: Your Turso auth token.

### 3. Initialization
Initialization happens automatically on the first run of the server.
```bash
npm start
```

### 4. Setup Profile (Optional)
To set up your initial Bluesky profile and birthdate:
```bash
npm run setup-profile "Your Name" "Your Bio" YYYY-MM-DD
```

### 3. Testing
```bash
npm test
```

### 4. Browser E2E (FedCM)
Install Chromium once:
```bash
npm run test:e2e:install
```

Run the FedCM browser test:
```bash
npm run test:e2e:fedcm
```

Run the full test suite, including the FedCM browser e2e:
```bash
npm test
```

How the e2e test works:
- It starts this PDS as the IdP and a tiny local RP in the same test process.
- The test logs into the IdP at `/login`, submits the PDS password automatically, and waits for the post-login page to push `navigator.login.setStatus(..., { accounts, apiConfig })` successfully.
- The RP then calls `navigator.credentials.get(...)` with the IdP's explicit `configURL` and `type: "indieauth"`.
- Playwright uses Chromium CDP `FedCm.*` commands to accept the browser-mediated FedCM dialog.
- The RP parses the assertion JSON, discovers the metadata endpoint, exchanges the code at the token endpoint, and verifies that the returned `me` URL points back to the same IndieAuth metadata endpoint.

Notes:
- The e2e test uses a single persistent Chromium context with multiple pages. Separate Playwright browser contexts would isolate the IdP cookies and registration state, which breaks FedCM.
- The stable automated path uses the IdP's explicit `configURL`. The registration-only `configURL: "any"` flow is intentionally not part of the default suite right now.
- If the browser flow fails, the test prints browser console logs, CDP FedCM events, and IdP route hits so it is easier to see whether the failure happened before `/accounts` or `/assertion`.

## License
Apache License 2.0
