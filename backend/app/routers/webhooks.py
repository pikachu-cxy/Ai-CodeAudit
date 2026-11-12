"""Public inbound webhook for Jenkins / CI scan triggers (no JWT)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.exceptions import (
    DuplicateGitUrlError,
    DuplicateProjectNameError,
    WebhookValidationError,
    duplicate_project_http_detail,
    webhook_validation_error_detail,
)
from app.models import ScanStatus, ScanTask
from app.schemas import ScanScoreOut, WebhookScanRequest, WebhookScanResponse
from app.services.scan_runtime import launch_sast_pipeline
from app.services.scan_service import create_gitlab_scan, start_scan_task
from app.services.score_service import get_or_compute_scan_score
from app.services.webhook_service import (
    default_display_name,
    find_project_by_source_url,
    verify_webhook_token,
)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


def _require_webhook_token(x_webhook_token: str | None, body_token: str | None = None) -> None:
    token = x_webhook_token or body_token
    if not (settings.webhook_token or "").strip():
        err = WebhookValidationError(
            "token_permission_insufficient",
            "Webhook 未配置：请在系统设置或 .env 中设置 WEBHOOK_TOKEN",
        )
        raise HTTPException(err.http_status, detail=webhook_validation_error_detail(err))
    if not verify_webhook_token(token):
        err = WebhookValidationError("token_permission_insufficient", "Webhook Token 无效")
        raise HTTPException(err.http_status, detail=webhook_validation_error_detail(err))


@router.get("/score", response_model=ScanScoreOut)
async def webhook_query_score(
    project_url: str = Query(..., description="GitLab 仓库地址"),
    branch: str | None = Query(None, description="可选分支；省略则取项目最近一次 completed 扫描"),
    db: AsyncSession = Depends(get_db),
    x_webhook_token: str | None = Header(default=None, alias="X-Webhook-Token"),
):
    """CI / 发版：按仓库 URL（+ 可选 branch）查询最近一次 completed 扫描的安全分。"""
    _require_webhook_token(x_webhook_token)

    project_url = (project_url or "").strip()
    if not project_url:
        err = WebhookValidationError("missing_parameter", "缺少 project_url（GitLab 仓库地址）")
        raise HTTPException(err.http_status, detail=webhook_validation_error_detail(err))

    project = await find_project_by_source_url(db, project_url)
    if not project:
        raise HTTPException(404, "未找到匹配的项目（请确认 project_url 或先触发过扫描）")

    stmt = select(ScanTask).where(
        ScanTask.project_id == project.id,
        ScanTask.status == ScanStatus.COMPLETED,
    )
    branch_val = (branch or "").strip()
    if branch_val:
        stmt = stmt.where(ScanTask.branch == branch_val)
    stmt = stmt.order_by(ScanTask.completed_at.desc().nullslast(), ScanTask.id.desc()).limit(1)
    scan = (await db.execute(stmt)).scalars().first()
    if not scan:
        detail = f"项目无已完成扫描" + (f"（branch={branch_val}）" if branch_val else "")
        raise HTTPException(404, detail)

    result = await get_or_compute_scan_score(db, scan.id, refresh=False)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return ScanScoreOut(**result)


@router.post("/scan", response_model=WebhookScanResponse, status_code=202)
async def webhook_trigger_scan(
    body: WebhookScanRequest,
    db: AsyncSession = Depends(get_db),
    x_webhook_token: str | None = Header(default=None, alias="X-Webhook-Token"),
):
    """
    Jenkins / CI: auto-create or match project by Git URL, clone, then run full SAST pipeline.

    Returns 202 when the scan is accepted and the pipeline is scheduled (not when SAST finishes).
    """
    _require_webhook_token(x_webhook_token, body.token)

    access_token = (settings.gitlab_access_token or "").strip()
    if not access_token:
        err = WebhookValidationError(
            "token_permission_insufficient", "未配置 GitLab Access Token（GITLAB_ACCESS_TOKEN）。"
        )
        raise HTTPException(err.http_status, detail=webhook_validation_error_detail(err))

    project_url = (body.project_url or "").strip()
    if not project_url:
        err = WebhookValidationError("missing_parameter", "缺少 project_url（GitLab 仓库地址）")
        raise HTTPException(err.http_status, detail=webhook_validation_error_detail(err))

    branch = (body.branch or "").strip() or (settings.gitlab_default_branch or "main")
    display_name = default_display_name(project_url, body.name)

    existing = await find_project_by_source_url(db, project_url)
    created_project = existing is None
    project_id = existing.id if existing else None

    try:
        scan = await create_gitlab_scan(
            db,
            project_url,
            branch,
            access_token,
            display_name,
            project_id=project_id,
            notify_emails=body.notify_emails,
            notify_email=body.notify_email,
            send_html_report=body.send_html_report,
            report_severities=body.report_severities,
            enforce_allowed_host=True,
        )
    except WebhookValidationError as exc:
        raise HTTPException(status_code=exc.http_status, detail=webhook_validation_error_detail(exc)) from exc
    except (DuplicateGitUrlError, DuplicateProjectNameError) as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except ValueError as exc:
        err = WebhookValidationError("missing_parameter", str(exc))
        raise HTTPException(status_code=err.http_status, detail=webhook_validation_error_detail(err)) from exc
    except RuntimeError as exc:
        # Clone failures in webhook path should be classified into the 4 webhook classes.
        msg = str(exc)
        if "登录页" in msg or "sign in" in msg.lower() or "无权限" in msg:
            err = WebhookValidationError("token_permission_insufficient", msg)
        else:
            err = WebhookValidationError("gitlab_address_invalid", msg)
        raise HTTPException(status_code=err.http_status, detail=webhook_validation_error_detail(err)) from exc

    if scan.project_id is None:
        raise HTTPException(500, "扫描创建成功但未关联项目")

    scan_id = scan.id
    try:
        await start_scan_task(scan_id, source="webhook")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    # Schedule on the event loop (more reliable than Starlette BackgroundTasks for CI triggers).
    launch_sast_pipeline(scan_id)

    db.expire_all()
    refreshed = await db.get(ScanTask, scan_id)
    if refreshed:
        scan = refreshed

    return WebhookScanResponse(
        ok=True,
        created_project=created_project,
        project_id=scan.project_id,
        scan_id=scan.id,
        branch=scan.branch or branch,
        status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
    )
