#!/usr/bin/env python3
"""
Standalone cleanup script — can be run via cron independently of the server.

Usage: python scripts/cleanup.py
Cron example: 0 * * * * /path/to/venv/bin/python /path/to/anonymizator/scripts/cleanup.py
"""
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from web import database as db
from web.cleanup import cleanup_expired

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


async def main():
    await db.init_db()
    await cleanup_expired()


if __name__ == "__main__":
    asyncio.run(main())
