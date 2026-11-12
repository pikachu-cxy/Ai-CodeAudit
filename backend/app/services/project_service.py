"""Project entity helpers: list/detail/update and scan attachment."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.exceptions import DuplicateProjectNameError
from app.models import Project, ScanKind, ScanSource, ScanStatus, ScanTask, utcnow
from app.services.url_normalize import try_normalize_gitlab_url


async def find_project_by_name(
    session: AsyncSession,
    name: str,
    *,
    exclude_id: int | None = None,
) -> Project | None:
    trimmed = (name or "").strip()
    if not trimmed:
        return None
    stmt = select(Project).where(func.lower(Project.name) == trimmed.lower())
    if exclude_id is not None:
        stmt = stmt.where(Project.id != exclude_id)
    return (await session.execute(stmt)).scalars().first()


async def create_project(
    session: AsyncSession,
    *,
    name: str,
    source_type: ScanSource,
    source_url: str | None = None,
    default_branch: str | None = None,
    notes: str | None = None,
    scan_languages: list[str] | None = None,
) -> Project:
    from app.services.project_languages import pack_scan_languages_json

    stored_url = source_url
    if source_type == ScanSource.GITLAB and source_url:
        stored_url = try_normalize_gitlab_url(source_url) or source_url
    display_name = name.strip() or "未命名项目"
    existing = await find_project_by_name(session, display_name)
    if existing:
        raise DuplicateProjectNameError(existing)
    project = Project(
        name=display_name,
        notes=notes,
        source_type=source_type,
        source_url=stored_url,
        default_branch=default_branch,
        scan_languages_json=pack_scan_languages_json(scan_languages),
    )
    session.add(project)
    await session.flush()
    return project


async def ensure_project_for_new_scan(
    session: AsyncSession,
    *,
    name: str,
    source: ScanSource,
    source_url: str | None = None,
    branch: str | None = None,
    notes: str | None = None,
    project_id: int | None = None,
    scan_languages: list[str] | None = None,
) -> tuple[Project, ScanKind, str]:
    """Attach scan to existing project or create a new one. Returns (project, kind, version_label)."""
    from app.services.project_languages import pack_scan_languages_json

    if project_id is not None:
        project = await session.get(Project, project_id)
        if not project:
            raise ValueError("project not found")
        count = (
            await session.execute(
                select(func.count()).select_from(ScanTask).where(ScanTask.project_id == project.id)
            )
        ).scalar() or 0
        kind = ScanKind.AD_HOC if count > 0 else ScanKind.BASELINE
        label = f"v{count + 1}"
        # Refresh project metadata from latest source info.
        if source_url and not project.source_url:
            project.source_url = try_normalize_gitlab_url(source_url) or source_url
        elif source == ScanSource.GITLAB and source_url:
            project.source_url = try_normalize_gitlab_url(source_url) or source_url
        if branch and not project.default_branch:
            project.default_branch = branch
        project.source_type = source
        # Append mode: only update scan_languages when explicitly provided.
        if scan_languages is not None:
            project.scan_languages_json = pack_scan_languages_json(scan_languages)
        project.updated_at = utcnow()
        return project, kind, label

    project = await create_project(
        session,
        name=name,
        source_type=source,
        source_url=source_url,
        default_branch=branch,
        notes=notes,
        scan_languages=scan_languages,
    )
    return project, ScanKind.BASELINE, "v1"


async def next_version_label(session: AsyncSession, project_id: int) -> str:
    count = (
        await session.execute(
            select(func.count()).select_from(ScanTask).where(ScanTask.project_id == project_id)
        )
    ).scalar() or 0
    return f"v{count + 1}"


async def list_projects(
    session: AsyncSession,
    *,
    q: str | None = None,
    archived: str = "false",
) -> list[Project]:
    """List projects without eager-loading all scans (use project_scan_stats for extras)."""
    stmt = select(Project)
    if archived == "true":
        stmt = stmt.where(Project.archived_at.is_not(None))
    elif archived != "all":
        stmt = stmt.where(Project.archived_at.is_(None))
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Project.name.ilike(like), Project.notes.ilike(like)))
    stmt = stmt.order_by(Project.updated_at.desc())
    return list((await session.execute(stmt)).scalars().all())


async def project_scan_stats(
    session: AsyncSession,
    project_ids: list[int],
) -> tuple[dict[int, int], dict[int, ScanTask]]:
    """Return (scan_count_by_project, latest_scan_by_project) without loading all scans."""
    if not project_ids:
        return {}, {}
    count_rows = (
        await session.execute(
            select(ScanTask.project_id, func.count())
            .where(ScanTask.project_id.in_(project_ids))
            .group_by(ScanTask.project_id)
        )
    ).all()
    counts = {int(pid): int(cnt) for pid, cnt in count_rows if pid is not None}

    # Prefer highest id as latest (autoincrement); fall back is fine for list UI.
    subq = (
        select(ScanTask.project_id, func.max(ScanTask.id).label("max_id"))
        .where(ScanTask.project_id.in_(project_ids))
        .group_by(ScanTask.project_id)
        .subquery()
    )
    latest_scans = (
        await session.execute(select(ScanTask).join(subq, ScanTask.id == subq.c.max_id))
    ).scalars().all()
    latest_map = {int(s.project_id): s for s in latest_scans if s.project_id is not None}
    return counts, latest_map


async def get_project(session: AsyncSession, project_id: int) -> Project | None:
    stmt = (
        select(Project)
        .where(Project.id == project_id)
        .options(selectinload(Project.scans))
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_project_scans(session: AsyncSession, project_id: int) -> list[ScanTask]:
    stmt = (
        select(ScanTask)
        .where(ScanTask.project_id == project_id)
        .order_by(ScanTask.created_at.desc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def update_project_metadata(
    session: AsyncSession,
    project_id: int,
    *,
    name: str | None = None,
    notes: str | None = None,
    scan_languages: list[str] | None = None,
    update_scan_languages: bool = False,
) -> Project | None:
    from app.services.project_languages import pack_scan_languages_json

    project = await session.get(Project, project_id)
    if not project:
        return None
    if name is not None:
        trimmed = name.strip()
        if not trimmed or len(trimmed) > 255:
            raise ValueError("invalid name")
        existing = await find_project_by_name(session, trimmed, exclude_id=project_id)
        if existing:
            raise DuplicateProjectNameError(existing)
        project.name = trimmed
    if notes is not None:
        trimmed_notes = notes.strip() if notes else None
        if trimmed_notes and len(trimmed_notes) > 2000:
            raise ValueError("notes too long")
        project.notes = trimmed_notes or None
    if update_scan_languages:
        project.scan_languages_json = pack_scan_languages_json(scan_languages)
    project.updated_at = utcnow()
    await session.commit()
    await session.refresh(project)
    return project


async def set_project_archived(
    session: AsyncSession,
    project_id: int,
    *,
    archived: bool,
) -> Project | None:
    project = await session.get(Project, project_id)
    if not project:
        return None
    if archived:
        active = (
            await session.execute(
                select(func.count())
                .select_from(ScanTask)
                .where(
                    ScanTask.project_id == project_id,
                    ScanTask.status.in_(
                        [
                            ScanStatus.SCANNING,
                            ScanStatus.ANALYZING,
                            ScanStatus.LLM_AUDITING,
                            ScanStatus.CLONING,
                        ]
                    ),
                )
            )
        ).scalar() or 0
        if active:
            raise ValueError("cannot archive project with active scans")
        project.archived_at = datetime.now(timezone.utc)
    else:
        project.archived_at = None
    project.updated_at = utcnow()
    await session.commit()
    await session.refresh(project)
    return project


def latest_scan(project: Project) -> ScanTask | None:
    scans = list(project.scans or [])
    if not scans:
        return None
    return max(scans, key=lambda s: s.created_at or datetime.min.replace(tzinfo=timezone.utc))


_PROJECT_DELETE_BLOCK_STATUSES = {
    ScanStatus.PENDING,
    ScanStatus.CLONING,
    ScanStatus.SCANNING,
    ScanStatus.ANALYZING,
    ScanStatus.LLM_AUDITING,
}


def _safe_remove_scan_project_path(path_raw: str | None) -> None:
    if not path_raw:
        return
    project_path = Path(path_raw)
    uploads_root = settings.uploads_dir.resolve()
    repos_root = settings.repos_dir.resolve()
    try:
        resolved_project = project_path.resolve()
        if not resolved_project.exists():
            return
        for root in (resolved_project, resolved_project.parent):
            if not root.exists():
                continue
            if root == uploads_root or root == repos_root:
                continue
            if uploads_root in root.parents or repos_root in root.parents:
                shutil.rmtree(root, ignore_errors=True)
                break
    except Exception:
        # Best-effort cleanup; project row deletion should not fail due to stale files.
        return


async def delete_project(session: AsyncSession, project_id: int) -> bool:
    project = await session.get(Project, project_id)
    if not project:
        return False

    active = (
        await session.execute(
            select(func.count())
            .select_from(ScanTask)
            .where(
                ScanTask.project_id == project_id,
                ScanTask.status.in_(list(_PROJECT_DELETE_BLOCK_STATUSES)),
            )
        )
    ).scalar() or 0
    if active:
        raise ValueError("cannot delete project with active scans")

    scans = (
        await session.execute(select(ScanTask).where(ScanTask.project_id == project_id))
    ).scalars().all()
    for scan in scans:
        _safe_remove_scan_project_path(scan.project_path)

    await session.delete(project)
    await session.commit()
    return True
