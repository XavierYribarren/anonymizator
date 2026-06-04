"""SQLite database helpers using aiosqlite."""
import os
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

DATABASE_PATH = os.getenv("DATABASE_PATH", "anonymizator.db")
TOKEN_EXPIRY_DAYS = int(os.getenv("TOKEN_EXPIRY_DAYS", "7"))
FILE_EXPIRY_DAYS = int(os.getenv("FILE_EXPIRY_DAYS", "21"))


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
                public_key TEXT,
                public_key_fingerprint TEXT NOT NULL,
                researcher_email TEXT,
                collector_email TEXT,
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
            CREATE TABLE IF NOT EXISTS public_keys (
                fingerprint      TEXT PRIMARY KEY,
                public_key       TEXT NOT NULL,
                created_at       TEXT NOT NULL,
                researcher_token TEXT UNIQUE
            )
        """)
        # Migration: add researcher_token to existing DBs that predate this column
        try:
            await db.execute("ALTER TABLE public_keys ADD COLUMN researcher_token TEXT")
        except Exception as exc:
            if "duplicate column name" not in str(exc).lower() and \
               "already exists" not in str(exc).lower():
                raise
        await db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_public_keys_researcher_token"
            " ON public_keys(researcher_token)"
        )
        await db.commit()


# ── Tokens ────────────────────────────────────────────────────────────────────

async def create_token(
    public_key: str,
    public_key_fingerprint: str,
    researcher_email: str | None,
    collector_email: str | None,
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
        # Candidate token used if this fingerprint is new or had no token yet (migration)
        candidate = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO public_keys (fingerprint, public_key, created_at, researcher_token)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(fingerprint) DO NOTHING""",
            (public_key_fingerprint, public_key, _iso(now), candidate),
        )
        # Backfill: existing row with NULL researcher_token (pre-migration)
        await db.execute(
            "UPDATE public_keys SET researcher_token = ? WHERE fingerprint = ? AND researcher_token IS NULL",
            (candidate, public_key_fingerprint),
        )
        async with db.execute(
            "SELECT researcher_token FROM public_keys WHERE fingerprint = ?",
            (public_key_fingerprint,),
        ) as cursor:
            pk_row = await cursor.fetchone()
            researcher_token = pk_row[0] if pk_row else candidate
        await db.commit()
    return {**row, "researcher_token": researcher_token}


async def get_token(token_id: str) -> dict | None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM tokens WHERE id = ?", (token_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def mark_token_used(token_id: str, file_id: str) -> bool:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "UPDATE tokens SET used_at = ?, file_id = ?, researcher_email = NULL, collector_email = NULL, public_key = NULL WHERE id = ? AND used_at IS NULL",
            (_iso(_now()), file_id, token_id),
        )
        await db.commit()
        return cursor.rowcount == 1


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


# ── Public keys ──────────────────────────────────────────────────────────────

async def rotate_researcher_token(fingerprint: str) -> str:
    """Replace the researcher_token for a given fingerprint with a fresh UUID4."""
    new_token = str(uuid.uuid4())
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE public_keys SET researcher_token = ? WHERE fingerprint = ?",
            (new_token, fingerprint),
        )
        await db.commit()
    return new_token


async def mark_file_downloaded(file_id: str) -> None:
    """Record the first download timestamp for an uploaded file."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE uploaded_files SET downloaded_at = ? WHERE id = ? AND downloaded_at IS NULL",
            (_iso(_now()), file_id),
        )
        await db.commit()


async def get_fingerprint_by_researcher_token(token: str) -> str | None:
    """Returns the public-key fingerprint associated with an opaque researcher_token."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute(
            "SELECT fingerprint FROM public_keys WHERE researcher_token = ?", (token,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


async def cleanup_orphaned_public_keys() -> int:
    """Delete public_keys entries not referenced by any active token or accessible file."""
    now = _iso(_now())
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            """DELETE FROM public_keys WHERE fingerprint NOT IN (
                   SELECT DISTINCT public_key_fingerprint FROM tokens
                   WHERE expires_at > ? AND used_at IS NULL
                   UNION
                   SELECT DISTINCT public_key_fingerprint FROM uploaded_files
                   WHERE expires_at > ?
               )""",
            (now, now),
        )
        await db.commit()
        return cursor.rowcount
