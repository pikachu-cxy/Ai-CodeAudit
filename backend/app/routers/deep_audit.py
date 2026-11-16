"""Deep Audit V1 HTTP contract.

This is an OPT-IN execution mode. It does not change the existing scan / LLM
audit / chat / review / report routes. All blackboard writes go through
``blackboard_service``; the executor only ever sees a ``ReadOnlyRepository``.

Routes::

    POST /api/scans/{scan_id}/deep-audit/plan        Planner dry-run (no writes)
    POST /api/scans/{scan_id}/deep-audit/runs        Start a run (201)
    GET  /api/scans/{scan_id}/deep-audit/runs        List runs for a scan
    GET  /api/deep-audit/runs/{run_id}               Full blackboard summary
    GET  /api/deep-audit/runs/{run_id}/facts         Shared facts + evidence
    GET  /api/deep-audit/runs/{run_id}/events        Redacted tool/LLM journal
    POST /api/deep-audit/runs/{run_id}/cancel        Cooperative cancel
    POST /api/deep-audit/runs/{run_id}/resume        Resume interrupted run
    POST /api/deep-audit/runs/{run_id}/findings/{finding_id}/confirm
                                                     Human review (evidence required)
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies.auth import require_admin, require_auth
from app.models import AuditRun, ScanEvent, ScanTask, dt_iso
from app.services import blackboard_service as bb
from app.services import deep_audit_service as svc
from app.services.deep_audit_budget import BudgetPolicy, DeepAuditBudgetSettings, save_deep_audit_budget
from app.services.deep_audit_guards import ALLOWED_TOOLS, ToolPolicyError, relative_path
from app.services.deep_audit_planner import FOCUS_KEYS, FOCUS_LABELS, AuditScope
from app.services.llm_provider import is_llm_configured

router = APIRouter(
    prefix="/api",
    tags=["deep-audit"],
    dependencies=[Depends(require_auth)],
)

DEEP_AUDIT_PHASE = "deep_audit"


class DeepAuditScopeIn(BaseModel):
    focus: list[str] = Field(default_factory=list, max_length=3)
    path_prefixes: list[str] = Field(default_factory=list, max_length=20)
    max_tasks: int | None = Field(default=None, ge=1, le=50)


class DeepAuditStartIn(DeepAuditScopeIn):
    agent_slug: str | None = Field(default=None, max_length=64)


class ConfirmIn(BaseModel):
    review_note: str = Field(default="", max_length=500)


def _loads(value: str | None, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except (json.JSONDecodeError, TypeError):
        return fallback


def _clean_scope(body: DeepAuditScopeIn) -> AuditScope:
    focus = [str(item).strip().lower() for item in body.focus if str(item).strip()]
    unknown = [item for item in focus if item not in FOCUS_KEYS]
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"不支持的审计范围：{', '.join(unknown)}；可选 {', '.join(FOCUS_KEYS)}",
        )
    prefixes = tuple(dict.fromkeys(relative_path(p) for p in body.path_prefixes))
    return AuditScope(tuple(focus), prefixes, body.max_tasks or 6)


def _run_out(row: AuditRun) -> dict:
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "status": row.status,
        "agent_slug": row.agent_slug,
        "agent_definition_id": row.agent_definition_id,
        "repository_revision": row.repository_revision,
        "config_snapshot": _loads(row.config_snapshot, {}),
        "scope": _loads(row.scope_json, {}),
        "budget_usage": _loads(row.budget_usage, {}),
        "error_message": row.error_message,
        "started_at": dt_iso(row.started_at),
        "finished_at": dt_iso(row.finished_at),
        "created_at": dt_iso(row.created_at),
        "is_active": svc.is_active(row.id),
    }


def _service_error(exc: ValueError) -> HTTPException:
    message = str(exc)
    if "不存在" in message:
        return HTTPException(status.HTTP_404_NOT_FOUND, message)
    if "执行中" in message or "仍" in message:
        return HTTPException(status.HTTP_409_CONFLICT, message)
    return HTTPException(status.HTTP_400_BAD_REQUEST, message)


@router.get("/deep-audit/settings", response_model=DeepAuditBudgetSettings, dependencies=[Depends(require_admin)])
async def get_deep_audit_settings(db: AsyncSession = Depends(get_db)) -> DeepAuditBudgetSettings:
    return (await BudgetPolicy.for_new_run(db)).configurable_limits()


@router.put("/deep-audit/settings", response_model=DeepAuditBudgetSettings, dependencies=[Depends(require_admin)])
async def update_deep_audit_settings(
    body: DeepAuditBudgetSettings, db: AsyncSession = Depends(get_db),
) -> DeepAuditBudgetSettings:
    await save_deep_audit_budget(db, body)
    return body


@router.get("/deep-audit/capabilities")
async def deep_audit_capabilities(db: AsyncSession = Depends(get_db)) -> dict:
    """Report the policy used by new runs."""
    policy = await BudgetPolicy.for_new_run(db)
    return {
        "mode": "deep_audit_v1",
        "execution_wired": True,
        "runtime_status": "deep_audit_v1_single_worker",
        "planner": "deterministic_v1 (纯数据，无 FS / Shell / HTTP / LLM)",
        "worker_count": 1,
        "blackboard": ["audit_runs", "audit_tasks", "audit_facts", "audit_evidence"],
        "allowed_tools": sorted(ALLOWED_TOOLS),
        "mcp_tools_granted": False,
        "skills_granted": False,
        "llm_configured": is_llm_configured(),
        "worker_mode": "llm" if is_llm_configured() else "deterministic_fallback",
        "focus": [
            {"key": key, "label": FOCUS_LABELS[key]} for key in FOCUS_KEYS
        ],
        "policy": policy.to_dict(),
        "legacy_llm_audit_preserved": True,
        "note": (
            "Deep Audit V1 是可选执行模式：Planner 产出结构化任务，1 个通用 Worker 仅能调用 "
            "5 个只读代码工具。无代码证据不会创建 Finding；候选 Finding 均为 UNREVIEWED/PENDING，"
            "必须人工确认。MCP / Skill 未授予执行权限。原有扫描器与 LLM 深度审计链路保持不变。"
        ),
    }


@router.post("/scans/{scan_id}/deep-audit/plan")
async def plan_preview(
    scan_id: int, body: DeepAuditScopeIn, db: AsyncSession = Depends(get_db)
) -> dict:
    """Planner-only dry run: no AuditRun/Task/Fact rows, no Worker, no LLM call."""
    try:
        return await svc.plan_preview(db, scan_id, _clean_scope(body))
    except ToolPolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ValueError as exc:
        raise _service_error(exc) from exc
    except OSError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "项目目录不可读") from exc


@router.post("/scans/{scan_id}/deep-audit/runs", status_code=status.HTTP_201_CREATED)
async def start_run(
    scan_id: int, body: DeepAuditStartIn, db: AsyncSession = Depends(get_db)
) -> dict:
    """Start one background Deep Audit run. Returns immediately with run_id."""
    try:
        scope = _clean_scope(body)
        run = await svc.start_deep_audit(
            db,
            svc.DeepAuditStartOptions(
                scan_id=scan_id,
                agent_slug=body.agent_slug,
                focus=list(scope.focus),
                path_prefixes=list(scope.path_prefixes),
                max_tasks=body.max_tasks,
            ),
        )
    except ToolPolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ValueError as exc:
        raise _service_error(exc) from exc
    except OSError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "项目目录不可读") from exc
    return {"ok": True, "run": _run_out(run)}


@router.get("/scans/{scan_id}/deep-audit/runs")
async def list_runs(
    scan_id: int,
    limit: int = Query(default=30, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if await db.get(ScanTask, scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "扫描不存在")
    rows = await bb.list_runs(db, scan_id, limit=limit)
    return {"runs": [_run_out(row) for row in rows]}


async def _require_run(db: AsyncSession, run_id: int) -> AuditRun:
    run = await bb.get_run(db, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Deep Audit 运行不存在: {run_id}")
    return run


@router.get("/deep-audit/runs/{run_id}")
async def run_summary(run_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    run = await _require_run(db, run_id)
    summary = await bb.run_summary(db, run_id)
    if summary is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "运行摘要不可用")
    summary["run"] = {**summary["run"], "is_active": svc.is_active(run_id)}
    summary["scan_id"] = run.scan_id
    return summary


@router.get("/deep-audit/runs/{run_id}/facts")
async def run_facts(
    run_id: int,
    fact_type: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cross-Worker shared facts with their code evidence."""
    await _require_run(db, run_id)
    facts = await bb.list_facts(db, run_id, fact_type=fact_type, limit=limit)
    return {"facts": facts, "count": len(facts)}


@router.get("/deep-audit/runs/{run_id}/events")
async def run_events(
    run_id: int,
    limit: int = Query(default=120, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Redacted tool/Planner/Worker journal (ScanEvent phase=deep_audit)."""
    run = await _require_run(db, run_id)
    rows = (
        await db.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == run.scan_id, ScanEvent.phase == DEEP_AUDIT_PHASE)
            .order_by(ScanEvent.id.desc())
            .limit(limit)
        )
    ).scalars().all()
    events: list[dict] = []
    for row in rows:
        payload = _loads(row.message, {"message": row.message})
        if isinstance(payload, dict):
            owner = payload.get("run_id")
            if owner is not None and str(owner) != str(run_id):
                continue
        events.append(
            {
                "id": row.id,
                "level": row.level,
                "event_type": row.tool,
                "payload": payload,
                "created_at": dt_iso(row.created_at),
            }
        )
    return {"events": events, "count": len(events)}


@router.post("/deep-audit/runs/{run_id}/cancel")
async def cancel_run(run_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    run = await _require_run(db, run_id)
    svc.request_cancel(run_id)
    return {"ok": True, "run_id": run_id, "active": svc.is_active(run_id), "status": run.status}


@router.post("/deep-audit/runs/{run_id}/resume")
async def resume_run(run_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    await _require_run(db, run_id)
    try:
        run = await svc.resume_run(run_id)
    except ValueError as exc:
        raise _service_error(exc) from exc
    if run is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "仅中断/失败的运行可恢复；已完成的运行不能恢复"
        )
    return {"ok": True, "run": _run_out(run)}


@router.post("/deep-audit/runs/{run_id}/findings/{finding_id}/confirm")
async def confirm_finding(
    run_id: int,
    finding_id: int,
    body: ConfirmIn,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Human review. Refuses when the linked fact has no code evidence."""
    run = await _require_run(db, run_id)
    finding = await bb.confirm_finding(db, run, finding_id, review_note=body.review_note)
    if finding is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "候选不存在、不属于该运行，或缺少黑板代码证据，不能确认为漏洞",
        )
    return {
        "ok": True,
        "finding_id": finding.id,
        "review_status": finding.review_status.value,
        "ai_verdict": finding.ai_verdict.value,
        "review_note": finding.review_note,
    }
