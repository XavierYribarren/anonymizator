"""Shared cryptographic utilities for Anonymizator.

File format for encrypted data (.enc):
  [encrypted_aes_key  (rsa_key_size // 8 bytes)]  RSA-OAEP-encrypted AES-256 key
  [nonce              (12 bytes)]                   AES-GCM nonce
  [tag                (16 bytes)]                   AES-GCM authentication tag
  [ciphertext         (variable)]                   AES-GCM-encrypted payload

Breaking change from v1: v1 used AES-256-CFB with a 16-byte IV and RSA-2048.
Files encrypted with v1 cannot be decrypted with this module.
"""
import io
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_NONCE_SIZE = 12  # AES-GCM nonce (bytes)
_TAG_SIZE = 16    # AES-GCM authentication tag (bytes)


def generate_rsa_keypair(key_size: int = 4096):
    """Generate an RSA key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def load_private_key(pem_bytes: bytes, password: bytes = None):
    """Load a PEM private key. Transparently handles OpenSSH format via paramiko."""
    if pem_bytes.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        try:
            import paramiko
            rsa_key = paramiko.RSAKey(
                file_obj=io.StringIO(pem_bytes.decode("utf-8")),
                password=password.decode("utf-8") if password else None,
            )
            buf = io.StringIO()
            rsa_key.write_private_key(buf)
            pem_bytes = buf.getvalue().encode("utf-8")
        except Exception as exc:
            raise ValueError(f"Failed to convert OpenSSH key: {exc}") from exc

    return serialization.load_pem_private_key(
        pem_bytes, password=password, backend=default_backend()
    )


def load_public_key(pem_str: str):
    """Load a PEM public key."""
    return serialization.load_pem_public_key(
        pem_str.encode("utf-8"), backend=default_backend()
    )


def encrypt_file_hybrid(data: bytes, public_key) -> bytes:
    """Encrypt *data* with RSA-OAEP + AES-256-GCM.

    Returns bytes laid out as:
      [encrypted_aes_key] [nonce (12 B)] [tag (16 B)] [ciphertext]
    """
    aes_key = os.urandom(32)  # AES-256
    nonce = os.urandom(_NONCE_SIZE)

    aesgcm = AESGCM(aes_key)
    # encrypt() appends the 16-byte GCM tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, data, None)
    ciphertext = ct_with_tag[:-_TAG_SIZE]
    tag = ct_with_tag[-_TAG_SIZE:]

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return encrypted_aes_key + nonce + tag + ciphertext


def decrypt_file_hybrid(encrypted_data: bytes, private_key) -> bytes:
    """Decrypt data produced by :func:`encrypt_file_hybrid`.

    Raises ValueError if the data is too short or authentication fails.
    """
    rsa_key_bytes = private_key.key_size // 8
    if len(encrypted_data) < rsa_key_bytes + _NONCE_SIZE + _TAG_SIZE:
        raise ValueError("Encrypted data is too short or corrupted")

    offset = 0
    encrypted_aes_key = encrypted_data[offset:offset + rsa_key_bytes]
    offset += rsa_key_bytes
    nonce = encrypted_data[offset:offset + _NONCE_SIZE]
    offset += _NONCE_SIZE
    tag = encrypted_data[offset:offset + _TAG_SIZE]
    offset += _TAG_SIZE
    ciphertext = encrypted_data[offset:]

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    # decrypt() expects ciphertext + tag concatenated
    return aesgcm.decrypt(nonce, ciphertext + tag, None)
