# Anonymizator

> Secure file encryption tool for sensitive research data collection, GDPR-compliant.

## What it does

Anonymizator lets CNRS researchers securely collect sensitive data files from
participants or field workers. The researcher generates a key pair, shares a
one-time upload link with data collectors, and can decrypt any received file —
without the collector ever seeing the private key or the decrypted content of
other files.

## How it works

```text
RESEARCHER (browser — localhost:8000)
  1. Generates RSA-4096 key pair in the browser
  2. Enters the collector's email → clicks "Envoyer l'invitation"
  3. Collector receives a one-time upload link by email

COLLECTOR (any browser — no install required)
  4. Opens the link
  5. Drags & drops the data file
  6. File is encrypted in the browser before upload — the server never sees plaintext
  7. Researcher receives a notification email

RESEARCHER (browser — /decrypt)
  8. Clicks "Déchiffrer" next to the received file
  9. Pastes private key → decrypted file downloads automatically
```

## Security

- **RSA-4096 + AES-256-GCM** hybrid encryption
- **Client-side only** — encryption/decryption happen entirely in the browser via the Web Crypto API; the server only stores the already-encrypted `.enc` file
- **Private key never leaves the researcher's machine**
- **Authenticated encryption** (GCM) prevents silent data tampering
- One-time upload links — each link can only be used once
- Files are deleted automatically after 21 days (configurable)

## Installation

```bash
# Recommended: create a virtual environment first
python3 -m venv venv && source venv/bin/activate

pip install -r requirements.txt
```

Requirements: Python 3.10+.

## Usage

### Web interface (recommended)

```bash
python researcher_app.py
# Opens http://localhost:8000 automatically
```

### VPS / server deployment

```bash
cp .env.example .env
# Edit .env: set BASE_URL to your public URL, configure SMTP
uvicorn web.main:app --host 0.0.0.0 --port 8000
```

### Desktop-only apps (no server needed)

```bash
# Collector-side encryption
python encryptor_app.py

# Standalone decryption
python decryptor_app.py
```

## Web Interface

### Configuration

Copy `.env.example` to `.env` and edit as needed:

```bash
cp .env.example .env
```

Key settings:

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:8000` | Public URL for links in emails |
| `SMTP_HOST` | — | SMTP server (leave blank to disable email) |
| `TOKEN_EXPIRY_DAYS` | `7` | Collector link validity |
| `FILE_EXPIRY_DAYS` | `21` | `.enc` file retention |
| `MAX_FILE_SIZE_MB` | `500` | Upload size limit |

Email is optional — if SMTP is not configured, upload links are shown directly in the UI.

### Email configuration

**Local development — Mailpit** (catches all emails, nothing is actually sent):

```bash
# Via Docker
docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit
# Or via Homebrew
brew install mailpit && mailpit
```

`.env` for Mailpit:

```env
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=
SMTP_PASSWORD=
SMTP_STARTTLS=false
BASE_URL=http://localhost:8000
```

Emails are visible at **[http://localhost:8025](http://localhost:8025)**.

**Production — Resend** (recommended, generous free tier):

```env
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_USER=resend
SMTP_PASSWORD=re_xxxxxxxxxxxx   # your Resend API key
SMTP_STARTTLS=false
BASE_URL=https://anon.mylab.fr
```

### Distributing a pre-configured encryptor

To ship `encryptor_app.py` with a key already embedded (zero-friction for
non-technical collectors), edit the constant at the top of the file:

```python
EMBEDDED_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""
```

When `EMBEDDED_PUBLIC_KEY` is set, the key input field is hidden and the user
only needs to drop their file.

## File format

Each `.enc` file produced by Anonymizator has the following binary layout:

| Field | Size | Description |
|---|---|---|
| `encrypted_aes_key` | 512 bytes (RSA-4096) | AES-256 key encrypted with RSA-OAEP / SHA-256 |
| `nonce` | 12 bytes | AES-GCM nonce |
| `ciphertext + tag` | N + 16 bytes | AES-GCM encrypted payload (16-byte authentication tag appended) |

Total overhead before the payload: **524 bytes**.

> **Breaking changes:**
>
> - **v1 → v2:** v1 used AES-256-CFB with a 16-byte IV and RSA-2048. Not compatible.
> - **v2 old → v2 current:** older v2 builds stored `[nonce][tag][ciphertext]`; current builds store `[nonce][ciphertext+tag]` to match the Web Crypto API native output.

## GDPR compliance notes

Anonymizator supports GDPR pseudonymisation requirements (Article 4(5)) by ensuring:

- Personal data files are encrypted before leaving the collector's device
- Only the designated researcher holding the private key can decrypt them
- No plaintext data is transmitted or stored on intermediate systems
- The private key can be deleted after the study to make re-identification
  computationally infeasible
- Files are automatically purged after a configurable retention period

## License

MIT
