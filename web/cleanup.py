"""Background task that removes expired files, tokens, and sessions."""
import asyncio
import logging
import os

from . import database

logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.abspath(
    os.getenv("UPLOAD_DIR", os.path.join(_PROJECT_ROOT, "uploads"))
)


async def cleanup_expired():
    """Delete expired files (disk + DB), expired unused tokens, and expired sessions."""
    # Files — physical deletion must happen before DB record is removed
    expired_files = await database.get_expired_files()
    deleted_files = 0
    for record in expired_files:
        path = os.path.join(UPLOAD_DIR, record["stored_filename"])
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("Could not delete %s: %s", path, exc)
        await database.delete_file(record["id"])
        deleted_files += 1

    # Tokens
    expired_tokens = await database.get_expired_tokens()
    deleted_tokens = len(expired_tokens)
    if expired_tokens:
        await database.delete_tokens([t["id"] for t in expired_tokens])

    # Sessions
    deleted_sessions = await database.cleanup_expired_sessions()

    if deleted_files or deleted_tokens or deleted_sessions:
        logger.info(
            "Cleanup: %d files, %d tokens, %d sessions deleted",
            deleted_files, deleted_tokens, deleted_sessions,
        )


async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            await cleanup_expired()
        except Exception as exc:
            logger.warning("Cleanup error: %s", exc)
