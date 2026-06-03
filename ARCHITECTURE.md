# Anonymizator — Architecture

## Overview

Anonymizator is a client-side encryption file transfer tool for academic research.
The server acts as a dumb relay — it stores encrypted blobs it cannot read.

## Design principles

### Zero-knowledge server
The server never sees plaintext data. Encryption and decryption happen entirely
in the browser using the Web Crypto API (RSA-OAEP 4096 + AES-256-GCM).
The server stores only:
- Public keys (not sensitive by nature)
- Encrypted `.enc` files (opaque without the private key)
- Metadata: emails, dates, file sizes

### No accounts
Researchers are identified by a session token (UUID) linked to their public key
fingerprint. No registration, no password, no email verification required.

### Self-hostable by design
The entire stack runs on a single server with SQLite and local file storage.
No external dependencies required (no Redis, no S3, no message queue).

## Stack

| Layer | Technology | Why |
|---|---|---|
| Backend | FastAPI (Python) | Async, simple, fast |
| Database | SQLite + aiosqlite | Zero ops, sufficient for research use |
| File storage | Local filesystem | Simple, auditable |
| Frontend | Vanilla JS + Web Crypto API | No build step, auditable |
| CLI | Typer + uvicorn | Simple, cross-platform |

## Request flow

### Creating a collection link
1. Researcher opens the web app
2. Browser generates RSA-4096 key pair (Web Crypto API)
3. Public key stored in localStorage; private key downloaded once
4. Browser calls `POST /api/sessions` → session token stored in localStorage
5. Researcher enters collector email → `POST /api/tokens`
6. Server stores token + public key, sends email with upload link

### Uploading (collector side)
1. Collector opens the one-time link
2. Browser fetches the researcher's public key from the server
3. Browser generates ephemeral AES-256-GCM key
4. File encrypted: AES-GCM(file) + RSA-OAEP(AES key)
5. Encrypted blob uploaded to server → token marked as used
6. Server notifies researcher by email

### Decrypting (researcher side)
1. Researcher clicks "Déchiffrer" next to a file
2. Browser opens `/decrypt?file_id=...`; fetches the `.enc` file via `X-Session-Token`
3. Researcher pastes private key (never sent to server)
4. Browser decrypts: RSA-OAEP(encrypted_aes_key) → AES-GCM decrypt
5. File downloaded locally; private key cleared from memory

## Binary format (.enc)

```
[encrypted_aes_key : 512 bytes]  ← RSA-4096 encrypted AES key
[iv : 12 bytes]                  ← AES-GCM nonce
[ciphertext + tag : N+16 bytes]  ← AES-GCM ciphertext with auth tag
Total: 524 + N bytes
```

## Database schema

```sql
tokens           -- one-time upload links + associated public key
uploaded_files   -- encrypted file metadata (not the file itself)
sessions         -- researcher session tokens (UUID → fingerprint mapping)
```

Indexes on `expires_at` columns accelerate hourly cleanup.
WAL mode (`PRAGMA journal_mode=WAL`) allows concurrent reads during writes.

## Known limitations

### Scalability
- SQLite: single-writer, suitable for ~50 concurrent uploads max
- Local file storage: cannot scale horizontally without shared storage (NFS, S3)
- Recommended max file size: 2 MB for public deployments

### Security
- Session tokens are stored in localStorage (XSS risk if page is compromised)
- Private key briefly exists in browser memory during decryption
- No forward secrecy: if the private key is compromised, all past files can be decrypted

### Operations
- No built-in monitoring or alerting
- Cleanup runs hourly via asyncio loop; use `scripts/cleanup.py` for cron reliability

## Migration path (if scaling is needed)

| Current | Scaled version |
|---|---|
| SQLite | PostgreSQL |
| Local uploads/ | S3 / object storage |
| Single uvicorn | Multiple workers + load balancer |
| asyncio cleanup | Celery + Redis |
| localStorage session | Proper auth (e.g. WebAuthn) |

The business logic (crypto, API routes, frontend) would not change significantly.

## Contributing

### Adding a language
See `web/locales/README.md`.

### Running tests
```bash
pytest tests/unit/python/ -v
npm test
npm run test:e2e
```

### Project structure
```
anonymizator/
├── researcher_app.py    # CLI entry point (Typer)
├── crypto_utils.py      # Python crypto (RSA + AES)
├── web/
│   ├── main.py          # FastAPI app + routes
│   ├── database.py      # SQLite helpers
│   ├── mailer.py        # SMTP email
│   ├── cleanup.py       # Expiry cleanup
│   ├── models.py        # Pydantic models
│   ├── locales/         # i18n JSON files
│   ├── static/          # JS + CSS
│   └── templates/       # Jinja2 HTML
├── scripts/
│   └── cleanup.py       # Standalone cron cleanup
├── tests/
│   ├── unit/
│   └── e2e/
├── deploy/              # Deployment configs
│   ├── nginx.conf
│   ├── anonymizator.service
│   ├── deploy.sh
│   └── update.sh
└── ARCHITECTURE.md
```
