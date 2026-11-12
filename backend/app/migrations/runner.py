"""Versioned SQL migrations with optional Python hooks."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.config import PROJECT_ROOT, database_backend_name

logger = logging.getLogger(__name__)

MIGRATIONS_ROOT = PROJECT_ROOT / "migrations"

_VERSION_RE = re.compile(r"^(\d{3})_")


def migration_backend_dir(backend: str | None = None) -> Path:
    name = (backend or database_backend_name()).strip().lower()
    if name not in ("sqlite", "mysql"):
        name = "sqlite"
    return MIGRATIONS_ROOT / name


def _split_sql_statements(sql: str) -> list[str]:
    """Split SQL file into executable statements (skip comments / empties)."""
    statements: list[str] = []
    buffer: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buffer.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(buffer).strip()
            if stmt.endswith(";"):
                stmt = stmt[:-1].strip()
            if stmt:
                statements.append(stmt)
            buffer = []
    trailing = "\n".join(buffer).strip()
    if trailing:
        statements.append(trailing)
    return statements


async def _ensure_migrations_table(conn: AsyncConnection) -> None:
    backend = database_backend_name()

    def _create(connection):
        inspector = inspect(connection)
        if "schema_migrations" in inspector.get_table_names():
            return
        if backend == "mysql":
            connection.execute(
                text(
                    """
                    CREATE TABLE schema_migrations (
                        version VARCHAR(32) NOT NULL PRIMARY KEY,
                        applied_at DATETIME NOT NULL
                    )
                    """
                )
            )
        else:
            connection.execute(
                text(
                    """
                    CREATE TABLE schema_migrations (
                        version VARCHAR(32) NOT NULL PRIMARY KEY,
                        applied_at DATETIME NOT NULL
                    )
                    """
                )
            )

    await conn.run_sync(_create)


async def _get_applied_versions(conn: AsyncConnection) -> set[str]:
    def _read(connection):
        inspector = inspect(connection)
        if "schema_migrations" not in inspector.get_table_names():
            return set()
        rows = connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
        return {str(row[0]) for row in rows}

    return await conn.run_sync(_read)


async def _record_migration(conn: AsyncConnection, version: str) -> None:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await conn.execute(
        text("INSERT INTO schema_migrations (version, applied_at) VALUES (:v, :t)"),
        {"v": version, "t": now},
    )


async def _execute_sql_file(conn: AsyncConnection, path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    statements = _split_sql_statements(sql)
    if not statements:
        return

    def _run(connection):
        for stmt in statements:
            connection.execute(text(stmt))

    await conn.run_sync(_run)


def _migration_version(path: Path) -> str:
    match = _VERSION_RE.match(path.name)
    if not match:
        raise ValueError(f"Invalid migration filename: {path.name}")
    return match.group(1)


async def _run_python_hook(version: str, conn: AsyncConnection) -> None:
    if version == "002":
        from app.migrations.hooks import backfill_normalized_source_urls

        await backfill_normalized_source_urls(conn)
    if version == "004":
        from app.migrations.hooks import apply_004_notify_emails_suppressions

        await apply_004_notify_emails_suppressions(conn)
    if version == "005":
        from app.migrations.hooks import apply_005_project_scan_languages

        await apply_005_project_scan_languages(conn)
    if version == "006":
        from app.migrations.hooks import apply_006_refresh_token_role

        await apply_006_refresh_token_role(conn)
    if version == "007":
        from app.migrations.hooks import apply_007_scan_security_score

        await apply_007_scan_security_score(conn)
    if version == "008":
        from app.migrations.hooks import apply_008_findings_scan_indexes

        await apply_008_findings_scan_indexes(conn)


async def run_pending_migrations(conn: AsyncConnection, *, backend: str | None = None) -> list[str]:
    """Apply pending SQL migrations in order. Returns applied version ids."""
    await _ensure_migrations_table(conn)
    applied = await _get_applied_versions(conn)
    migration_dir = migration_backend_dir(backend)
    if not migration_dir.is_dir():
        logger.warning("Migration directory missing: %s", migration_dir)
        return []

    applied_now: list[str] = []
    for path in sorted(migration_dir.glob("*.sql")):
        version = _migration_version(path)
        if version in applied:
            continue
        logger.info("Applying migration %s (%s)", version, path.name)
        await _execute_sql_file(conn, path)
        await _run_python_hook(version, conn)
        await _record_migration(conn, version)
        applied.add(version)
        applied_now.append(version)
    return applied_now
