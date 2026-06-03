"""SQLite database helpers using aiosqlite."""
import os
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

DATABASE_PATH = os.getenv("DATABASE_PATH", "anonymizator.db")
TOKEN_EXPIRY_DAYS = int(os.getenv("TOKEN_EXPIRY_DAYS", "7"))
FILE_EXPIRY_DAYS = int(os.getenv("FILE_EXPIRY_DAYS", "21"))
SESSION_EXPIRY_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


async def init_db():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL,
                researcher_email TEXT,
                collector_email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                file_id TEXT
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_tokens_expires_at
                ON tokens(expires_at)
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_files (
                id TEXT PRIMARY KEY,
                token_id TEXT NOT NULL,
                original_filename TEXT,
                stored_filename TEXT NOT NULL,
                file_size INTEGER,
                uploaded_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                downloaded_at TEXT,
                public_key_fingerprint TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_uploaded_files_expires_at
                ON uploaded_files(expires_at)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_uploaded_files_fingerprint
                ON uploaded_files(public_key_fingerprint)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_uploaded_files_token_id
                ON uploaded_files(token_id)
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                public_key_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint
                ON sessions(public_key_fingerprint)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
                ON sessions(expires_at)
        """)
        await db.commit()


# ── Tokens ────────────────────────────────────────────────────────────────────

async def create_token(
    public_key: str,
    public_key_fingerprint: str,
    researcher_email: str | None,
    collector_email: str,
) -> dict:
    token_id = str(uuid.uuid4())
    now = _now()
    row = {
        "id": token_id,
        "public_key": public_key,
        "public_key_fingerprint": public_key_fingerprint,
        "researcher_email": researcher_email,
        "collector_email": collector_email,
        "created_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=TOKEN_EXPIRY_DAYS)),
        "used_at": None,
        "file_id": None,
    }
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """INSERT INTO tokens
               (id, public_key, public_key_fingerprint, researcher_email,
                collector_email, created_at, expires_at)
               VALUES (:id, :public_key, :public_key_fingerprint, :researcher_email,
                       :collector_email, :created_at, :expires_at)""",
            row,
        )
        await db.commit()
    return row


async def get_token(token_id: str) -> dict | None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM tokens WHERE id = ?", (token_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def mark_token_used(token_id: str, file_id: str):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE tokens SET used_at = ?, file_id = ? WHERE id = ?",
            (_iso(_now()), file_id, token_id),
        )
        await db.commit()


async def count_active_tokens(public_key_fingerprint: str) -> int:
    now = _iso(_now())
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM tokens WHERE public_key_fingerprint = ? AND expires_at > ? AND used_at IS NULL",
            (public_key_fingerprint, now),
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0


async def delete_tokens(token_ids: list[str]):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.executemany(
            "DELETE FROM tokens WHERE id = ?", [(t,) for t in token_ids]
        )
        await db.commit()


# ── Files ─────────────────────────────────────────────────────────────────────

async def create_uploaded_file(
    token_id: str,
    original_filename: str | None,
    stored_filename: str,
    file_size: int,
    public_key_fingerprint: str,
) -> str:
    file_id = str(uuid.uuid4())
    now = _now()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """INSERT INTO uploaded_files
               (id, token_id, original_filename, stored_filename,
                file_size, uploaded_at, expires_at, public_key_fingerprint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                file_id, token_id, original_filename, stored_filename,
                file_size, _iso(now),
                _iso(now + timedelta(days=FILE_EXPIRY_DAYS)),
                public_key_fingerprint,
            ),
        )
        await db.commit()
    return file_id


async def get_file(file_id: str) -> dict | None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM uploaded_files WHERE id = ?", (file_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def get_files_by_fingerprint(fingerprint: str) -> list[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT id, original_filename, uploaded_at, file_size, expires_at
               FROM uploaded_files
               WHERE public_key_fingerprint = ?
               ORDER BY uploaded_at DESC""",
            (fingerprint,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def delete_file(file_id: str):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("DELETE FROM uploaded_files WHERE id = ?", (file_id,))
        await db.commit()


async def get_expired_files() -> list[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM uploaded_files WHERE expires_at < ?", (_iso(_now()),)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_expired_tokens() -> list[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM tokens WHERE expires_at < ? AND used_at IS NULL",
            (_iso(_now()),),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


# ── Sessions ──────────────────────────────────────────────────────────────────

async def create_session(public_key_fingerprint: str) -> dict:
    token = str(uuid.uuid4())
    now = _now()
    row = {
        "token": token,
        "public_key_fingerprint": public_key_fingerprint,
        "created_at": _iso(now),
        "last_seen_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=SESSION_EXPIRY_DAYS)),
    }
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """INSERT INTO sessions
               (token, public_key_fingerprint, created_at, last_seen_at, expires_at)
               VALUES (:token, :public_key_fingerprint, :created_at, :last_seen_at, :expires_at)""",
            row,
        )
        await db.commit()
    return row


async def get_session(token: str) -> dict | None:
    now = _iso(_now())
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
            (token, now),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def update_session_last_seen(token: str):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token = ?",
            (_iso(_now()), token),
        )
        await db.commit()


async def cleanup_expired_sessions() -> int:
    now = _iso(_now())
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM sessions WHERE expires_at <= ?", (now,)
        )
        count = cursor.rowcount
        await db.commit()
    return count
