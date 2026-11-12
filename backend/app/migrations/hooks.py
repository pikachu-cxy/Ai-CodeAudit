"""Python migration hooks (data backfills that are awkward in pure SQL)."""

from __future__ import annotations

import logging

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.models import Project, ScanSource, ScanTask
from app.services.url_normalize import try_normalize_gitlab_url

logger = logging.getLogger(__name__)


async def apply_004_notify_emails_suppressions(conn: AsyncConnection) -> None:
    """Idempotent scan_tasks.notify_emails_json — safe when create_all ran first."""

    def _run(connection):
        from sqlalchemy import inspect, text

        inspector = inspect(connection)
        if "scan_tasks" not in inspector.get_table_names():
            return
        cols = {c["name"] for c in inspector.get_columns("scan_tasks")}
        if "notify_emails_json" not in cols:
            connection.execute(text("ALTER TABLE scan_tasks ADD COLUMN notify_emails_json TEXT"))

    await conn.run_sync(_run)


async def apply_005_project_scan_languages(conn: AsyncConnection) -> None:
    """Idempotent projects.scan_languages_json — safe when create_all / legacy migrate ran first."""

    def _run(connection):
        from sqlalchemy import inspect, text

        inspector = inspect(connection)
        if "projects" not in inspector.get_table_names():
            return
        cols = {c["name"] for c in inspector.get_columns("projects")}
        if "scan_languages_json" not in cols:
            connection.execute(text("ALTER TABLE projects ADD COLUMN scan_languages_json TEXT"))

    await conn.run_sync(_run)


async def apply_006_refresh_token_role(conn: AsyncConnection) -> None:
    """Idempotent refresh_tokens.role — safe when create_all already added the column."""

    def _run(connection):
        from sqlalchemy import inspect, text

        inspector = inspect(connection)
        if "refresh_tokens" not in inspector.get_table_names():
            return
        cols = {c["name"] for c in inspector.get_columns("refresh_tokens")}
        if "role" in cols:
            return
        dialect = connection.dialect.name
        if dialect == "mysql":
            connection.execute(
                text(
                    "ALTER TABLE refresh_tokens "
                    "ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'user'"
                )
            )
        else:
            connection.execute(
                text(
                    "ALTER TABLE refresh_tokens "
                    "ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'user'"
                )
            )

    await conn.run_sync(_run)


async def apply_007_scan_security_score(conn: AsyncConnection) -> None:
    """Idempotent scan_tasks.security_score + score_breakdown_json."""

    def _run(connection):
        from sqlalchemy import inspect, text

        inspector = inspect(connection)
        if "scan_tasks" not in inspector.get_table_names():
            return
        cols = {c["name"] for c in inspector.get_columns("scan_tasks")}
        dialect = connection.dialect.name
        if "security_score" not in cols:
            if dialect == "mysql":
                connection.execute(text("ALTER TABLE scan_tasks ADD COLUMN security_score INT NULL"))
            else:
                connection.execute(text("ALTER TABLE scan_tasks ADD COLUMN security_score INTEGER"))
        if "score_breakdown_json" not in cols:
            connection.execute(text("ALTER TABLE scan_tasks ADD COLUMN score_breakdown_json TEXT"))

    await conn.run_sync(_run)


async def apply_008_findings_scan_indexes(conn: AsyncConnection) -> None:
    """Idempotent indexes on findings(scan_id) and common filter composites."""

    def _run(connection):
        from sqlalchemy import inspect, text

        inspector = inspect(connection)
        if "findings" not in inspector.get_table_names():
            return
        existing = {idx["name"] for idx in inspector.get_indexes("findings")}
        statements = [
            ("ix_findings_scan_id", "CREATE INDEX ix_findings_scan_id ON findings (scan_id)"),
            (
                "ix_findings_scan_severity",
                "CREATE INDEX ix_findings_scan_severity ON findings (scan_id, severity)",
            ),
            (
                "ix_findings_scan_tool",
                "CREATE INDEX ix_findings_scan_tool ON findings (scan_id, tool)",
            ),
        ]
        for name, sql in statements:
            if name in existing:
                continue
            connection.execute(text(sql))

    await conn.run_sync(_run)


async def backfill_normalized_source_urls(conn: AsyncConnection) -> None:
    """Normalize historical GitLab source_url values on projects and scan_tasks."""

    def _run(connection):
        project_rows = connection.execute(
            text(
                "SELECT id, source_url FROM projects "
                "WHERE source_type = :st AND source_url IS NOT NULL AND source_url != ''"
            ),
            {"st": ScanSource.GITLAB.value},
        ).fetchall()
        updated_projects = 0
        for row in project_rows:
            normalized = try_normalize_gitlab_url(row.source_url)
            if normalized and normalized != row.source_url:
                connection.execute(
                    text("UPDATE projects SET source_url = :url WHERE id = :id"),
                    {"url": normalized, "id": row.id},
                )
                updated_projects += 1

        scan_rows = connection.execute(
            text(
                "SELECT id, source_url FROM scan_tasks "
                "WHERE source = :st AND source_url IS NOT NULL AND source_url != ''"
            ),
            {"st": ScanSource.GITLAB.value},
        ).fetchall()
        updated_scans = 0
        for row in scan_rows:
            normalized = try_normalize_gitlab_url(row.source_url)
            if normalized and normalized != row.source_url:
                connection.execute(
                    text("UPDATE scan_tasks SET source_url = :url WHERE id = :id"),
                    {"url": normalized, "id": row.id},
                )
                updated_scans += 1

        if updated_projects or updated_scans:
            logger.info(
                "Backfilled normalized source_url: projects=%s scans=%s",
                updated_projects,
                updated_scans,
            )

    await conn.run_sync(_run)


async def backfill_normalized_source_urls_session(session) -> None:
    """Async ORM variant for tests or manual scripts."""
    result = await session.execute(
        select(Project).where(
            Project.source_type == ScanSource.GITLAB,
            Project.source_url.is_not(None),
        )
    )
    for project in result.scalars().all():
        normalized = try_normalize_gitlab_url(project.source_url)
        if normalized and normalized != project.source_url:
            project.source_url = normalized

    scan_result = await session.execute(
        select(ScanTask).where(
            ScanTask.source == ScanSource.GITLAB,
            ScanTask.source_url.is_not(None),
        )
    )
    for scan in scan_result.scalars().all():
        normalized = try_normalize_gitlab_url(scan.source_url)
        if normalized and normalized != scan.source_url:
            scan.source_url = normalized
