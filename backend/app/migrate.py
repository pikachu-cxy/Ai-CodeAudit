"""CLI: python -m app.migrate"""

from __future__ import annotations

import asyncio
import logging
import sys

from sqlalchemy.ext.asyncio import create_async_engine

from app.config import build_database_url, database_backend_name, settings
from app.migrations.runner import run_pending_migrations

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def main() -> int:
    backend = database_backend_name()
    url = build_database_url()
    logger.info("Running migrations for backend=%s url=%s", backend, url.split("@")[-1])

    engine = create_async_engine(url, echo=False)
    try:
        async with engine.begin() as conn:
            applied = await run_pending_migrations(conn, backend=backend)
        if applied:
            logger.info("Applied migrations: %s", ", ".join(applied))
        else:
            logger.info("No pending migrations")
        return 0
    finally:
        await engine.dispose()


if __name__ == "__main__":
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    raise SystemExit(asyncio.run(main()))
