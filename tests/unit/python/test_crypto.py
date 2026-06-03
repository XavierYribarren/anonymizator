"""Tests for crypto_utils.py — key generation, encrypt/decrypt, fingerprint."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import (
    decrypt_file_hybrid,
    encrypt_file_hybrid,
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
)
from web.main import _public_key_fingerprint


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_key_pair(key_size=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return priv, priv.public_key(), pub_pem, priv_pem


# ── Key generation ────────────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_returns_private_and_public(self):
        priv, pub = generate_rsa_keypair(key_size=2048)
        assert priv is not None
        assert pub is not None

    def test_public_key_spki_pem(self):
        _, pub = generate_rsa_keypair(key_size=2048)
        pem = pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert "RSA PUBLIC KEY" not in pem

    def test_private_key_pkcs8_pem(self):
        priv, _ = generate_rsa_keypair(key_size=2048)
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        assert pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert "RSA PRIVATE KEY" not in pem

    def test_load_public_key_round_trip(self):
        _, pub = generate_rsa_keypair(key_size=2048)
        pem = pub.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        loaded = load_public_key(pem)
        assert loaded.key_size == 2048

    def test_load_private_key_round_trip(self):
        priv, _ = generate_rsa_keypair(key_size=2048)
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        loaded = load_private_key(pem.encode())
        assert loaded.key_size == 2048


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

class TestEncryptDecrypt:
    @pytest.fixture(autouse=True)
    def keys(self):
        self.priv, self.pub, self.pub_pem, self.priv_pem = _make_key_pair()

    def test_encrypt_returns_bytes(self):
        enc = encrypt_file_hybrid(b"hello", self.pub)
        assert isinstance(enc, bytes) and len(enc) > 0

    def test_decrypt_recovers_original(self):
        data = b"Sensitive research data 12345"
        assert decrypt_file_hybrid(encrypt_file_hybrid(data, self.pub), self.priv) == data

    def test_encrypted_differs_from_plaintext(self):
        data = b"plaintext"
        assert encrypt_file_hybrid(data, self.pub) != data

    def test_random_iv_produces_different_ciphertexts(self):
        data = b"same data"
        assert encrypt_file_hybrid(data, self.pub) != encrypt_file_hybrid(data, self.pub)

    def test_decrypt_with_wrong_key_raises(self):
        other_priv, _, _, _ = _make_key_pair()
        enc = encrypt_file_hybrid(b"secret", self.pub)
        with pytest.raises(Exception):
            decrypt_file_hybrid(enc, other_priv)

    def test_decrypt_corrupted_data_raises(self):
        enc = bytearray(encrypt_file_hybrid(b"secret", self.pub))
        enc[-1] ^= 0xFF  # flip last byte of AES-GCM tag
        with pytest.raises(Exception):
            decrypt_file_hybrid(bytes(enc), self.priv)

    def test_decrypt_too_short_raises(self):
        with pytest.raises(Exception):
            decrypt_file_hybrid(b"\x00" * 10, self.priv)

    def test_empty_file(self):
        assert decrypt_file_hybrid(encrypt_file_hybrid(b"", self.pub), self.priv) == b""

    def test_large_file(self):
        data = b"X" * (2 * 1024 * 1024)  # 2 MB
        assert decrypt_file_hybrid(encrypt_file_hybrid(data, self.pub), self.priv) == data

    def test_binary_format_structure(self):
        """Layout: [RSA key (256 B for 2048-bit)] [nonce 12 B] [ciphertext+tag]."""
        data = b"test"
        enc = encrypt_file_hybrid(data, self.pub)
        rsa_bytes = self.pub.key_size // 8  # 256
        # ciphertext + 16-byte GCM tag
        assert len(enc) == rsa_bytes + 12 + len(data) + 16


# ── Fingerprint ───────────────────────────────────────────────────────────────

class TestFingerprint:
    def test_length_is_16(self):
        _, _, pub_pem, _ = _make_key_pair()
        assert len(_public_key_fingerprint(pub_pem)) == 16

    def test_is_lowercase_hex(self):
        _, _, pub_pem, _ = _make_key_pair()
        fp = _public_key_fingerprint(pub_pem)
        int(fp, 16)  # raises ValueError if not valid hex

    def test_same_key_same_fingerprint(self):
        _, _, pub_pem, _ = _make_key_pair()
        assert _public_key_fingerprint(pub_pem) == _public_key_fingerprint(pub_pem)

    def test_different_keys_different_fingerprints(self):
        _, _, pub1, _ = _make_key_pair()
        _, _, pub2, _ = _make_key_pair()
        assert _public_key_fingerprint(pub1) != _public_key_fingerprint(pub2)

    def test_invalid_pem_raises(self):
        with pytest.raises(Exception):
            _public_key_fingerprint("not-a-pem")
