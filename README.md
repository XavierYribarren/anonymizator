# Anonymizator

> Secure file encryption tool for sensitive research data collection, GDPR-compliant.

## What it does

Anonymizator lets CNRS researchers securely collect sensitive data files from
participants or field workers. The researcher generates a key pair, shares the
public key with data collectors, and can decrypt any file they receive — without
the collector ever seeing the private key or the decrypted content of other files.

## How it works

```
RESEARCHER (researcher_app.py)
  1. Generates RSA-4096 key pair
  2. Shares public key with collector (Copy / Export buttons)

COLLECTOR (encryptor_app.py)
  3. Pastes public key (or uses a pre-configured build)
  4. Drags & drops data file → encrypted .enc file saved automatically

RESEARCHER (researcher_app.py)
  5. Drags & drops received .enc file → decrypted file saved locally
```

## Security

- **RSA-4096 + AES-256-GCM** hybrid encryption
- **Client-side only**: the distributor never sees plaintext data
- **Private key never leaves the researcher's machine**
- **Authenticated encryption** (GCM) prevents silent data tampering
- Private key can be password-protected at generation time

## Installation

```bash
pip install -r requirements.txt
```

Requirements: Python 3.9+, PyQt6, cryptography, paramiko.

## Usage

### For the researcher

```bash
python researcher_app.py
# Enable verbose logging if needed:
python researcher_app.py --debug
```

1. **Clés & Déchiffrement** tab → click **Générer une nouvelle paire de clés RSA-4096**
2. Choose a strong passphrase and save the private key file somewhere safe
3. Click **Copier** or **Exporter (.pem)** to share the public key with collectors
4. When you receive a `.enc` file, drag & drop it into the drop zone — the app
   decrypts it and prompts you to save the result

### For the data collector

```bash
python encryptor_app.py
```

1. Paste the public key received from the researcher
2. Drag & drop the data file onto the drop zone
3. The `.enc` file is saved automatically next to the source file
4. Send the `.enc` file to the researcher

### Standalone decryptor

```bash
python decryptor_app.py
```

Same decryption workflow as the researcher app, useful if you want to distribute
a decryption-only tool.

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

| Field              | Size                        | Description                          |
|--------------------|-----------------------------|--------------------------------------|
| `encrypted_aes_key`| `rsa_key_size / 8` bytes    | AES-256 key encrypted with RSA-OAEP  |
| `nonce`            | 12 bytes                    | AES-GCM nonce                        |
| `tag`              | 16 bytes                    | AES-GCM authentication tag           |
| `ciphertext`       | variable                    | AES-GCM encrypted payload            |

For RSA-4096 keys the header is 512 + 12 + 16 = **540 bytes** before the ciphertext.

> **Breaking change from v1:** v1 used AES-256-CFB with a 16-byte IV and RSA-2048.
> Files encrypted with v1 are not compatible with this version.

## GDPR compliance notes

Anonymizator supports GDPR pseudonymisation requirements (Article 4(5)) by ensuring:

- Personal data files are encrypted before leaving the collector's device
- Only the designated researcher holding the private key can decrypt them
- No plaintext data is transmitted or stored on intermediate systems
- The private key can be deleted after the study to make re-identification
  computationally infeasible

## License

MIT
