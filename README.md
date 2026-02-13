# Simple Self-PDS (AT Protocol)

A minimal, single-user AT Protocol Personal Data Server (PDS) built with Node.js, Express, and Turso.

## Walkthrough: Key AT Protocol Concepts

### 1. Identity (DID)
In ATProto, every user is identified by a Decentralized Identifier (DID). This implementation uses `did:web`, which is the simplest form of identity for self-hosting. Your DID will look like `did:web:your-domain.com`. The PDS serves a DID document at `/.well-known/did.json` that contains your public key and the service URL.

### 2. The Repository (Repo)
Your data (posts, profile, etc.) is stored in a signed repository. This is not a traditional SQL table, but a Merkle Search Tree (MST) stored as a collection of content-addressed blocks (CIDs). Every change to your data results in a new "commit" signed by your private key.

### 3. XRPC
ATProto uses XRPC, a simple RPC protocol over HTTP.
- **Methods**: Named like `com.atproto.repo.createRecord`.
- **Lexicons**: Schemas that define the structure of records and RPC calls.

### 4. Authentication
Authentication is done via JWTs. When you log in (`createSession`), the PDS issues an `accessJwt`. This token contains your DID and is used to authorize subsequent requests.

## How to Run

1.  **Install dependencies**:
    ```bash
    npm install
    ```

2.  **Configure environment**:
    Copy `.env.example` to `.env` and fill in your details.
    ```bash
    cp .env.example .env
    ```

3.  **Run setup**:
    This will create your database, generate your signing keys, and initialize your repository.
    ```bash
    npx tsx setup.ts
    ```

4.  **Start the server**:
    ```bash
    npx tsx index.ts
    ```

## Vercel & Turso
- **Turso**: To use Turso, simply change `DATABASE_URL` in `.env` to your Turso DB URL and provide the `DATABASE_AUTH_TOKEN`.
- **Vercel**: This project is structured to work with Vercel Functions. You can deploy it by connecting your GitHub repo to Vercel and setting the environment variables.

## Implemented Endpoints
- `GET /.well-known/did.json`: DID Resolution.
- `POST /xrpc/com.atproto.server.createSession`: Login.
- `GET /xrpc/com.atproto.server.getSession`: Session check.
- `POST /xrpc/com.atproto.repo.createRecord`: Create a new record (e.g., a post).
- `GET /xrpc/com.atproto.repo.getRecord`: Retrieve a record.

## Next Steps
- **Firehose**: To be visible on the global Bluesky network, you'll need to implement `com.atproto.sync.subscribeRepos` (WebSocket) so the Relay can index your posts.
- **Blob Storage**: Implementing `com.atproto.repo.uploadBlob` for images.
