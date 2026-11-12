"""Project list / history / append-scan / retest APIs."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies.auth import require_auth
from app.exceptions import DuplicateGitUrlError, DuplicateProjectNameError, WebhookValidationError, duplicate_project_http_detail
from app.models import Project, ScanKind, ScanSource, ScanTask, RetestStrategy, dt_iso
from app.schemas import (
    CheckProjectNameOut,
    CheckSourceUrlOut,
    DetectedLanguageOut,
    ProjectCreateGitLabScan,
    ProjectDetail,
    ProjectSummary,
    ProjectUpdateRequest,
    ProjectWhitelistCreate,
    ProjectWhitelistEntryOut,
    RetestRequest,
    RetestResultsSummary,
    ScanCreateGitLab,
    ScanDiffSummary,
    ScanSummary,
    ScanCoverageOut,
)
from app.services.llm_audit_coverage import batch_load_llm_audit_meta
from app.services.project_languages import (
    detected_languages_from_scanner_summary,
    parse_scan_languages_json,
)
from app.services.scan_coverage import build_scan_coverage, ensure_rule_inventory_persisted
from app.services.project_service import (
    delete_project,
    find_project_by_name,
    get_project,
    latest_scan,
    list_project_scans,
    list_projects,
    project_scan_stats,
    set_project_archived,
    update_project_metadata,
)
from app.services.scan_diff_service import compare_scans
from app.services.scan_service import (
    create_gitlab_scan,
    create_retest_scan,
    create_upload_scan,
    delete_project_suppression,
    list_project_suppressions,
    notify_emails_for_scan,
    start_scan_task,
    whitelist_finding,
)
from app.services.retest_service import (
    get_retest_results,
    run_targeted_retest_pipeline,
    start_targeted_retest_task,
)
from app.services.scan_runtime import launch_sast_pipeline, schedule_scan_pipeline
from app.services.url_normalize import normalize_gitlab_url
from app.services.webhook_service import find_project_by_source_url

router = APIRouter(prefix="/api", tags=["projects"], dependencies=[Depends(require_auth)])


def _scan_status_str(scan: ScanTask) -> str:
    st = scan.status
    return st.value if hasattr(st, "value") else str(st)


def _scan_summary(
    scan: ScanTask,
    llm_audit_meta: dict | None = None,
    *,
    compact: bool = False,
) -> ScanSummary:
    kind = scan.scan_kind or ScanKind.BASELINE
    if isinstance(kind, str):
        try:
            kind = ScanKind(kind)
        except ValueError:
            kind = ScanKind.BASELINE
    cov = build_scan_coverage(
        scan.scanner_summary,
        scan_status=_scan_status_str(scan),
        llm_audit_meta=llm_audit_meta,
        compact=compact,
    )
    detected = [
        DetectedLanguageOut(**row)
        for row in detected_languages_from_scanner_summary(scan.scanner_summary)
    ]
    return ScanSummary(
        id=scan.id,
        project_id=scan.project_id,
        parent_scan_id=scan.parent_scan_id,
        scan_kind=kind,
        version_label=scan.version_label,
        name=scan.name,
        source=scan.source,
        status=scan.status,
        source_url=scan.source_url,
        branch=scan.branch,
        notify_emails=notify_emails_for_scan(scan) or None,
        progress=scan.progress,
        progress_message=scan.progress_message,
        total_findings=scan.total_findings,
        security_score=getattr(scan, "security_score", None),
        semgrep_version=scan.semgrep_version,
        scanner_summary=None if compact else scan.scanner_summary,
        scan_coverage=ScanCoverageOut(**cov),
        detected_languages=detected,
        error_message=scan.error_message,
        notes=scan.notes,
        created_at=dt_iso(scan.created_at) or "",
        updated_at=dt_iso(scan.updated_at),
        completed_at=dt_iso(scan.completed_at),
        archived_at=dt_iso(scan.archived_at),
    )


def _project_summary(
    project: Project,
    *,
    include_latest: bool = True,
    llm_meta_map: dict[int, dict] | None = None,
) -> ProjectSummary:
    scans = list(project.scans or [])
    latest = latest_scan(project) if include_latest else None
    latest_out = None
    if latest:
        meta = (llm_meta_map or {}).get(latest.id)
        latest_out = _scan_summary(latest, llm_audit_meta=meta)
    parsed_langs = parse_scan_languages_json(getattr(project, "scan_languages_json", None))
    detected = list(latest_out.detected_languages) if latest_out else []
    return ProjectSummary(
        id=project.id,
        name=project.name,
        notes=project.notes,
        source_type=project.source_type,
        source_url=project.source_url,
        default_branch=project.default_branch,
        scan_languages=parsed_langs or None,
        detected_languages=detected,
        archived_at=dt_iso(project.archived_at),
        created_at=dt_iso(project.created_at) or "",
        updated_at=dt_iso(project.updated_at),
        scan_count=len(scans),
        latest_scan=latest_out,
    )


async def _scan_summary_with_db(db: AsyncSession, scan: ScanTask) -> ScanSummary:
    meta_map = await batch_load_llm_audit_meta(db, [scan.id])
    new_summary, changed = ensure_rule_inventory_persisted(scan.scanner_summary)
    if changed and new_summary is not None:
        scan.scanner_summary = new_summary
        await db.commit()
        await db.refresh(scan)
    return _scan_summary(scan, llm_audit_meta=meta_map.get(scan.id))


async def _scan_summaries_with_db(db: AsyncSession, scans: list[ScanTask]) -> list[ScanSummary]:
    if not scans:
        return []
    meta_map = await batch_load_llm_audit_meta(db, [s.id for s in scans])
    return [_scan_summary(s, llm_audit_meta=meta_map.get(s.id), compact=True) for s in scans]


@router.get("/projects/check-source-url", response_model=CheckSourceUrlOut)
async def api_check_source_url(
    url: str = Query(..., min_length=1),
    db: AsyncSession = Depends(get_db),
):
    try:
        normalized = normalize_gitlab_url(url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    existing = await find_project_by_source_url(db, url)
    if existing:
        # find_project_by_source_url 不做 eager load：直接拿它喂 _project_summary，
        # 会在 project.scans 上触发异步上下文里的懒加载 → MissingGreenlet → 500。
        # 与 check-name 保持一致，先用 get_project（selectinload(Project.scans)）重载。
        loaded = await get_project(db, existing.id)
        if loaded is None:
            # 两次查询之间项目被删掉：退化成「不重复」，不要 500。
            return CheckSourceUrlOut(duplicate=False, normalized_url=normalized, project=None)
        return CheckSourceUrlOut(
            duplicate=True,
            normalized_url=normalized,
            project=_project_summary(loaded),
        )
    return CheckSourceUrlOut(duplicate=False, normalized_url=normalized, project=None)


@router.get("/projects/check-name", response_model=CheckProjectNameOut)
async def api_check_project_name(
    name: str = Query(..., min_length=1),
    db: AsyncSession = Depends(get_db),
):
    existing = await find_project_by_name(db, name)
    if not existing:
        return CheckProjectNameOut(duplicate=False, project=None)
    loaded = await get_project(db, existing.id)
    return CheckProjectNameOut(
        duplicate=True,
        project=_project_summary(loaded or existing),
    )


@router.get("/projects", response_model=list[ProjectSummary])
async def api_list_projects(
    q: str | None = None,
    archived: str = Query("false", pattern="^(false|true|all)$"),
    db: AsyncSession = Depends(get_db),
):
    projects = await list_projects(db, q=q, archived=archived)
    project_ids = [p.id for p in projects]
    counts, latest_map = await project_scan_stats(db, project_ids)
    latest_ids = [s.id for s in latest_map.values()]
    meta_map = await batch_load_llm_audit_meta(db, latest_ids)
    out: list[ProjectSummary] = []
    for p in projects:
        latest = latest_map.get(p.id)
        latest_out = None
        if latest:
            latest_out = _scan_summary(
                latest,
                llm_audit_meta=meta_map.get(latest.id),
                compact=True,
            )
        parsed_langs = parse_scan_languages_json(getattr(p, "scan_languages_json", None))
        detected = list(latest_out.detected_languages) if latest_out else []
        out.append(
            ProjectSummary(
                id=p.id,
                name=p.name,
                notes=p.notes,
                source_type=p.source_type,
                source_url=p.source_url,
                default_branch=p.default_branch,
                scan_languages=parsed_langs or None,
                detected_languages=detected,
                archived_at=dt_iso(p.archived_at),
                created_at=dt_iso(p.created_at) or "",
                updated_at=dt_iso(p.updated_at),
                scan_count=counts.get(p.id, 0),
                latest_scan=latest_out,
            )
        )
    return out


@router.get("/projects/{project_id}", response_model=ProjectDetail)
async def api_get_project(project_id: int, db: AsyncSession = Depends(get_db)):
    project = await get_project(db, project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    scans = sorted(project.scans or [], key=lambda s: s.created_at or s.id, reverse=True)
    meta_map = await batch_load_llm_audit_meta(db, [s.id for s in scans])
    summary = _project_summary(project, llm_meta_map=meta_map)
    scan_summaries = [
        _scan_summary(s, llm_audit_meta=meta_map.get(s.id), compact=True) for s in scans
    ]
    return ProjectDetail(**summary.model_dump(), scans=scan_summaries)


@router.get("/projects/{project_id}/scans", response_model=list[ScanSummary])
async def api_list_project_scans(project_id: int, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    scans = await list_project_scans(db, project_id)
    return await _scan_summaries_with_db(db, scans)


@router.patch("/projects/{project_id}", response_model=ProjectSummary)
async def api_update_project(
    project_id: int,
    body: ProjectUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        project = await update_project_metadata(
            db,
            project_id,
            name=body.name,
            notes=body.notes,
            scan_languages=body.scan_languages,
            update_scan_languages="scan_languages" in body.model_fields_set,
        )
    except DuplicateProjectNameError as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not project:
        raise HTTPException(404, "项目不存在")
    project = await get_project(db, project_id)
    return _project_summary(project)  # type: ignore[arg-type]


@router.post("/projects/{project_id}/archive", response_model=ProjectSummary)
async def api_archive_project(project_id: int, db: AsyncSession = Depends(get_db)):
    try:
        project = await set_project_archived(db, project_id, archived=True)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not project:
        raise HTTPException(404, "项目不存在")
    project = await get_project(db, project_id)
    return _project_summary(project)  # type: ignore[arg-type]


@router.post("/projects/{project_id}/unarchive", response_model=ProjectSummary)
async def api_unarchive_project(project_id: int, db: AsyncSession = Depends(get_db)):
    project = await set_project_archived(db, project_id, archived=False)
    if not project:
        raise HTTPException(404, "项目不存在")
    project = await get_project(db, project_id)
    return _project_summary(project)  # type: ignore[arg-type]


@router.delete("/projects/{project_id}")
async def api_delete_project(project_id: int, db: AsyncSession = Depends(get_db)):
    try:
        ok = await delete_project(db, project_id)
    except ValueError as exc:
        raise HTTPException(400, "项目有进行中的扫描，无法删除") from exc
    if not ok:
        raise HTTPException(404, "项目不存在")
    return {"deleted": True}


@router.post("/projects/{project_id}/scans/upload", response_model=ScanSummary)
async def api_project_upload_scan(
    project_id: int,
    file: UploadFile = File(...),
    name: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = None
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", dir=settings.uploads_dir) as tmp:
        tmp_path = Path(tmp.name)
        total = 0
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(413, "上传文件超过大小限制")
            tmp.write(chunk)
    try:
        scan = await create_upload_scan(db, tmp_path, name, project_id=project_id)
    except DuplicateProjectNameError as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        tmp_path.unlink(missing_ok=True)
    return await _scan_summary_with_db(db, scan)


@router.post("/projects/{project_id}/scans/gitlab", response_model=ScanSummary)
async def api_project_gitlab_scan(
    project_id: int,
    body: ProjectCreateGitLabScan,
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    project_url = (body.project_url or project.source_url or "").strip()
    if not project_url:
        raise HTTPException(400, "缺少 GitLab 项目地址")
    if not project_url.endswith(".git"):
        project_url = f"{project_url.rstrip('/')}.git"
    token = (body.access_token or "").strip() or (settings.gitlab_access_token or "").strip()
    if not token:
        raise HTTPException(400, "缺少 GitLab access token")
    try:
        scan = await create_gitlab_scan(
            db,
            project_url=project_url,
            branch=body.branch or project.default_branch or "main",
            access_token=token,
            name=body.name,
            project_id=project_id,
            scan_kind=ScanKind.AD_HOC,
            notify_emails=body.notify_emails,
            report_severities=body.report_severities,
        )
    except (DuplicateGitUrlError, DuplicateProjectNameError) as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except WebhookValidationError as exc:
        raise HTTPException(exc.http_status, exc.message) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        # git clone / 探活过程中的「环境类」故障：进程超时（TimeoutExpired 属
        # SubprocessError）、进程起不来或磁盘写入失败（OSError）。这些不是缺陷，
        # 仍按 400 把原因回给前端。
        raise HTTPException(400, f"克隆失败: {exc}") from exc
    # 故意不再兜底 `except Exception`：AttributeError / TypeError / KeyError 这类
    # 编程错误必须冒泡成 500 并留下堆栈。曾经的 `except Exception → 400 "克隆失败"`
    # 把 `'ProjectCreateGitLabScan' object has no attribute 'report_severities'`
    # 伪装成了克隆失败，掩盖了真实缺陷（见 tests/test_gitlab_scan_error_mapping.py）。
    return await _scan_summary_with_db(db, scan)


def _suppression_out(row) -> ProjectWhitelistEntryOut:
    return ProjectWhitelistEntryOut(
        id=row.id,
        project_id=row.project_id,
        status=row.status or "",
        reason=row.reason or "",
        rule_id=row.rule_id,
        file_path=row.file_path,
        fingerprint_strict=row.fingerprint_strict,
        fingerprint_relaxed=row.fingerprint_relaxed,
        source_scan_id=row.source_scan_id,
        source_finding_id=row.source_finding_id,
        created_by=row.created_by,
        created_at=dt_iso(row.created_at),
        expires_at=dt_iso(row.expires_at),
    )


@router.get(
    "/projects/{project_id}/whitelist",
    response_model=list[ProjectWhitelistEntryOut],
)
async def api_list_project_whitelist(
    project_id: int,
    include_expired: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    rows = await list_project_suppressions(
        db, project_id, include_expired=include_expired
    )
    return [_suppression_out(r) for r in rows]


@router.post(
    "/projects/{project_id}/whitelist",
    response_model=ProjectWhitelistEntryOut,
)
async def api_add_project_whitelist(
    project_id: int,
    body: ProjectWhitelistCreate,
    user: dict = Depends(require_auth),
    db: AsyncSession = Depends(get_db),
):
    """把某条漏洞加入项目白名单；该项目后续扫描不再上报它。"""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "项目不存在")
    try:
        row = await whitelist_finding(
            db,
            project_id=project_id,
            finding_id=body.finding_id,
            reason=body.reason,
            created_by=(user or {}).get("username"),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _suppression_out(row)


@router.delete("/projects/{project_id}/whitelist/{suppression_id}")
async def api_delete_project_whitelist(
    project_id: int,
    suppression_id: int,
    db: AsyncSession = Depends(get_db),
):
    ok = await delete_project_suppression(
        db, project_id=project_id, suppression_id=suppression_id
    )
    if not ok:
        raise HTTPException(404, "白名单条目不存在")
    return {"ok": True, "id": suppression_id}


@router.post("/scans/{scan_id}/retest", response_model=ScanSummary)
async def api_retest_scan(
    scan_id: int,
    body: RetestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan = await create_retest_scan(
            db,
            scan_id,
            branch=body.branch,
            access_token=body.access_token,
            name=body.name,
            strategy=body.strategy.value,
            finding_ids=body.finding_ids,
            include_unreviewed_high=body.include_unreviewed_high,
        )
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("upload_retest_requires_new_archive"):
            raise HTTPException(
                400,
                "上传型项目无法直接复测：请在同一项目下重新上传新版本代码。",
            ) from exc
        raise HTTPException(400, msg) from exc
    except (DuplicateGitUrlError, DuplicateProjectNameError) as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except WebhookValidationError as exc:
        # 复测支持自选分支后，这里会真实命中 branch_not_found —— 必须把
        # 「远程分支不存在：xxx」原样回给前端，否则用户改错分支只会看到一句
        # 泛化的「复测创建失败」，无从判断问题。
        raise HTTPException(exc.http_status, exc.message) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(400, f"复测创建失败: {exc}") from exc
    # 同 api_project_gitlab_scan：不再用 `except Exception` 兜底，
    # 让编程错误冒泡成 500 而不是被伪装成「复测创建失败」。

    if body.auto_start and scan.status.value == "pending":
        if body.strategy == RetestStrategy.FULL:
            await start_scan_task(scan.id)
            launch_sast_pipeline(scan.id)
        else:
            await start_targeted_retest_task(scan.id)
            schedule_scan_pipeline(scan.id, run_targeted_retest_pipeline(scan.id))
    return await _scan_summary_with_db(db, scan)


@router.get("/scans/{scan_id}/retest-results", response_model=RetestResultsSummary)
async def api_retest_results(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    try:
        return await get_retest_results(db, scan_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/scans/{scan_id}/diff", response_model=ScanDiffSummary)
async def api_scan_diff(
    scan_id: int,
    baseline_scan_id: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    try:
        return await compare_scans(db, scan_id, baseline_scan_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
