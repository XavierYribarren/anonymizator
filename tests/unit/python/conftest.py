import glob
import os
import tempfile

# ── env vars must be set before any project imports ───────────────────────────
_db_fd, _db_path = tempfile.mkstemp(suffix=".db")
os.close(_db_fd)
os.unlink(_db_path)  # let aiosqlite create it fresh

os.environ["DATABASE_PATH"] = _db_path
os.environ["UPLOAD_DIR"] = tempfile.mkdtemp()
os.environ["BASE_URL"] = "http://testserver"
os.environ["MAX_FILE_SIZE_MB"] = "10"
os.environ["TOKEN_EXPIRY_DAYS"] = "7"
os.environ["FILE_EXPIRY_DAYS"] = "21"
os.environ["SMTP_HOST"] = ""

import aiosqlite
import pytest
from httpx import ASGITransport, AsyncClient

from web import database as db
from web.main import _public_key_fingerprint, app


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
async def setup_and_teardown():
    """Init DB and reset rate limiter before each test; clean up after."""
    await db.init_db()
    _reset_rate_limiter()
    yield
    async with aiosqlite.connect(db.DATABASE_PATH) as conn:
        await conn.execute("DELETE FROM uploaded_files")
        await conn.execute("DELETE FROM tokens")
        await conn.commit()
    for f in glob.glob(os.path.join(os.environ["UPLOAD_DIR"], "*.enc")):
        try:
            os.unlink(f)
        except OSError:
            pass


def _reset_rate_limiter():
    try:
        from limits.storage import MemoryStorage
        from web.main import limiter
        limiter._storage = MemoryStorage()
    except Exception:
        pass


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        yield c


@pytest.fixture(scope="session")
def sample_key_pair():
    """2048-bit RSA key pair (smaller = faster tests, same API surface)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return {"public": pub_pem, "private": priv_pem}


@pytest.fixture
def sample_token(sample_key_pair):
    """Factory that inserts a fresh token and returns its ID."""
    async def _create(
        researcher_email="researcher@test.com",
        collector_email="collector@test.com",
    ):
        fp = _public_key_fingerprint(sample_key_pair["public"])
        token = await db.create_token(
            public_key=sample_key_pair["public"],
            public_key_fingerprint=fp,
            researcher_email=researcher_email,
            collector_email=collector_email,
        )
        return token["id"], fp

    return _create
