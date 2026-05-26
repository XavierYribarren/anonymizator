"""Tests for web/cleanup.py — expired file and token deletion."""
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

import pytest

from web import cleanup, database as db


async def _insert_file_with_expiry(expiry_offset_days: int, fp="cleanup_fp_123"):
    """Insert a file that expires offset_days from now (negative = already expired)."""
    from datetime import timedelta
    import aiosqlite
    import uuid

    file_id = str(uuid.uuid4())
    stored = f"{uuid.uuid4()}.enc"
    now = db._now()
    expires = now + timedelta(days=expiry_offset_days)
    async with aiosqlite.connect(db.DATABASE_PATH) as conn:
        await conn.execute(
            """INSERT INTO uploaded_files
               (id, token_id, original_filename, stored_filename,
                file_size, uploaded_at, expires_at, public_key_fingerprint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, "tok", "f.csv", stored, 100,
             db._iso(now), db._iso(expires), fp),
        )
        await conn.commit()
    return file_id, stored


async def _insert_token_with_expiry(expiry_offset_days: int, fp="cleanup_fp_tok"):
    import aiosqlite
    import uuid

    token_id = str(uuid.uuid4())
    now = db._now()
    expires = now + timedelta(days=expiry_offset_days)
    async with aiosqlite.connect(db.DATABASE_PATH) as conn:
        await conn.execute(
            """INSERT INTO tokens
               (id, public_key, public_key_fingerprint, researcher_email,
                collector_email, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (token_id, "PEM", fp, None, "c@test.com",
             db._iso(now), db._iso(expires)),
        )
        await conn.commit()
    return token_id


class TestCleanupExpired:
    async def test_deletes_expired_file_from_db(self):
        file_id, stored = await _insert_file_with_expiry(-1)
        stored_path = os.path.join(os.environ["UPLOAD_DIR"], stored)
        # File doesn't exist on disk — cleanup should handle FileNotFoundError gracefully
        await cleanup.cleanup_expired()
        assert await db.get_file(file_id) is None

    async def test_deletes_expired_file_from_disk(self):
        file_id, stored = await _insert_file_with_expiry(-1)
        stored_path = os.path.join(os.environ["UPLOAD_DIR"], stored)
        # Create actual file
        with open(stored_path, "wb") as f:
            f.write(b"\x00" * 100)
        await cleanup.cleanup_expired()
        assert not os.path.exists(stored_path)

    async def test_does_not_delete_unexpired_file(self):
        file_id, _ = await _insert_file_with_expiry(+7)
        await cleanup.cleanup_expired()
        assert await db.get_file(file_id) is not None

    async def test_handles_missing_disk_file_gracefully(self):
        """cleanup_expired must not raise if the disk file is already gone."""
        file_id, _ = await _insert_file_with_expiry(-1)
        await cleanup.cleanup_expired()  # no exception expected

    async def test_deletes_expired_unused_tokens(self):
        token_id = await _insert_token_with_expiry(-1)
        await cleanup.cleanup_expired()
        assert await db.get_token(token_id) is None

    async def test_does_not_delete_unexpired_tokens(self):
        token_id = await _insert_token_with_expiry(+7)
        await cleanup.cleanup_expired()
        assert await db.get_token(token_id) is not None

    async def test_does_not_delete_used_expired_tokens(self):
        """Used tokens are kept even if expired (they hold metadata)."""
        token_id = await _insert_token_with_expiry(-1)
        await db.mark_token_used(token_id, "some-file")
        await cleanup.cleanup_expired()
        # Used tokens are excluded from get_expired_tokens, so they stay
        assert await db.get_token(token_id) is not None


class TestCleanupLoop:
    async def test_loop_calls_cleanup_periodically(self):
        import asyncio

        call_count = 0

        async def fake_cleanup():
            nonlocal call_count
            call_count += 1

        with patch("web.cleanup.cleanup_expired", side_effect=fake_cleanup):
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                mock_sleep.side_effect = [None, asyncio.CancelledError()]
                try:
                    await cleanup.cleanup_loop()
                except asyncio.CancelledError:
                    pass
        assert call_count >= 1
