"""Background task that removes expired files and tokens."""
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
    expired_files = await database.get_expired_files()
    for record in expired_files:
        path = os.path.join(UPLOAD_DIR, record["stored_filename"])
        try:
            os.remove(path)
            logger.info("Deleted expired file: %s", path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("Could not delete %s: %s", path, exc)
        await database.delete_file(record["id"])

    expired_tokens = await database.get_expired_tokens()
    if expired_tokens:
        await database.delete_tokens([t["id"] for t in expired_tokens])
        logger.info("Purged %d expired tokens", len(expired_tokens))


async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            await cleanup_expired()
        except Exception as exc:
            logger.warning("Cleanup error: %s", exc)
