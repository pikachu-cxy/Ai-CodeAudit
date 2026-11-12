"""Inbound CI / Jenkins webhook helpers: URL normalize + project match."""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Project, ScanSource, ScanTask
from app.services.gitlab_service import split_project_url
from app.services.url_normalize import normalize_gitlab_url

__all__ = [
    "default_display_name",
    "find_project_by_source_url",
    "normalize_gitlab_url",
    "verify_webhook_token",
]


def verify_webhook_token(provided: str | None) -> bool:
    expected = (settings.webhook_token or "").strip()
    if not expected:
        return False
    got = (provided or "").strip()
    if not got:
        return False
    return secrets.compare_digest(got, expected)


async def find_project_by_source_url(session: AsyncSession, project_url: str) -> Project | None:
    """Find an existing GitLab project by normalized source_url (Project or prior ScanTask)."""
    key = normalize_gitlab_url(project_url)
    result = await session.execute(
        select(Project).where(Project.source_type == ScanSource.GITLAB, Project.source_url.is_not(None))
    )
    for project in result.scalars().all():
        try:
            if project.source_url and normalize_gitlab_url(project.source_url) == key:
                return project
        except ValueError:
            continue

    scan_result = await session.execute(
        select(ScanTask).where(
            ScanTask.source == ScanSource.GITLAB,
            ScanTask.source_url.is_not(None),
            ScanTask.project_id.is_not(None),
        )
    )
    for scan in scan_result.scalars().all():
        try:
            if scan.source_url and normalize_gitlab_url(scan.source_url) == key and scan.project_id:
                project = await session.get(Project, scan.project_id)
                if project:
                    return project
        except ValueError:
            continue
    return None


def default_display_name(project_url: str, name: str | None) -> str:
    if name and name.strip():
        return name.strip()
    try:
        _, path = split_project_url(project_url)
        return path.split("/")[-1] or "gitlab-project"
    except ValueError:
        return "gitlab-project"
