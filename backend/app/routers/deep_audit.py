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

import asyncio
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies.auth import require_admin, require_auth
from app.models import AuditRun, ScanEvent, ScanTask, dt_iso
from app.services import asset_graph_service as assets, audit_graph_service as audit_graph
from app.services import blackboard_service as bb
from app.services import deep_audit_service as svc
from app.services.deep_audit_budget import BudgetExceeded, BudgetLedger, BudgetPolicy, DeepAuditBudgetSettings, save_deep_audit_budget
from app.services.deep_audit_guards import ALLOWED_TOOLS, ToolPolicyError, relative_path
from app.services.deep_audit_lineup import public_config
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
    planner_slug: str | None = Field(default=None, min_length=2, max_length=64)
    worker_slugs: list[Annotated[str, Field(min_length=2, max_length=64)]] | None = Field(
        default=None, min_length=1, max_length=3,
    )


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
        "config_snapshot": public_config(_loads(row.config_snapshot, {})),
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
        "runtime_status": "deep_audit_v1_batched_workers",
        "planner": "agent_llm / deterministic_v1",
        "worker_count": 1,
        "max_workers": 3,
        "parallel_workers": settings.deep_audit_task_concurrency >= 2,
        "task_concurrency_limit": min(2, max(1, settings.deep_audit_task_concurrency)),
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
"Deep Audit V1 由 Planner 生成结构化任务，1–3 个 Worker 按批执行，同批最多两个不同 Worker，仅能调用 "
            "5 个只读代码工具。无代码证据不会创建 Finding；候选 Finding 均为 UNREVIEWED/PENDING，"
            "必须人工确认。MCP / Skill 未授予执行权限。原有扫描器与 LLM 深度审计链路保持不变。"
        ),
    }


@router.post("/scans/{scan_id}/deep-audit/plan")
async def plan_preview(
    scan_id: int, body: DeepAuditStartIn, db: AsyncSession = Depends(get_db)
) -> dict:
    """Preview the selected Planner without persisting a run or starting Workers."""
    try:
        return await svc.plan_preview(
            db, scan_id, _clean_scope(body), planner_slug=body.planner_slug,
            worker_slugs=body.worker_slugs, agent_slug=body.agent_slug,
        )
    except (ToolPolicyError, BudgetExceeded) as exc:
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
                planner_slug=body.planner_slug,
                worker_slugs=body.worker_slugs,
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
    if not svc.is_active(run_id):
        summary["active_tasks"] = []
        summary["current_task"] = None
    summary["scan_id"] = run.scan_id
    return summary


@router.post("/scans/{scan_id}/deep-audit/asset-graph/build")
async def build_asset_graph(scan_id: int, body: DeepAuditScopeIn, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if scan is None:
        raise HTTPException(404, "扫描不存在")
    try:
        scope = _clean_scope(body)
        ledger = BudgetLedger(await BudgetPolicy.for_new_run(db))
        repo = await svc._repository(scan, scope, ledger)
        snapshot = await assets.ensure_snapshot(db, scan, repo, scope.path_prefixes, ledger)
        return await assets.project_snapshot(db, snapshot)
    except (ValueError, OSError, BudgetExceeded, TimeoutError) as exc:
        raise HTTPException(400, "无法从当前扫描源码生成资产图") from exc


@router.get("/scans/{scan_id}/deep-audit/asset-graph")
async def get_asset_graph(
    scan_id: int, run_id: int | None = Query(default=None, ge=1),
    root_asset_id: str | None = Query(default=None, max_length=64),
    db: AsyncSession = Depends(get_db),
):
    run = await _require_run(db, run_id) if run_id else None
    snapshot_id = None
    if run:
        snapshot_id = _loads(run.config_snapshot, {}).get("asset_graph_id")
        if run.scan_id != scan_id or not snapshot_id:
            raise HTTPException(404, "该运行没有对应资产图快照")
    snapshot = await assets.read_snapshot(db, scan_id, snapshot_id)
    if not snapshot or (run and run.repository_revision != snapshot.repository_revision):
        raise HTTPException(404, "资产图快照不存在")
    if root_asset_id and not any(node["id"] == root_asset_id for node in snapshot.graph["nodes"]):
        raise HTTPException(404, "资产不存在于该快照")
    return await assets.project_snapshot(db, snapshot, run, root_asset_id, active=bool(run and svc.is_active(run.id)))


@router.get("/deep-audit/runs/{run_id}/audit-graph")
async def get_audit_graph(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await _require_run(db, run_id)
    return await audit_graph.project_run(db, run, active=svc.is_active(run_id))


@router.get("/deep-audit/runs/{run_id}/evidence/{evidence_id}/source")
async def evidence_source(run_id: int, evidence_id: int, db: AsyncSession = Depends(get_db)):
    run = await _require_run(db, run_id)
    graph = await audit_graph.project_run(db, run, active=svc.is_active(run_id))
    evidence = next((n["data"] for n in graph["nodes"] if n["id"] == f"evidence:{evidence_id}"), None)
    if not evidence or evidence["evidence_type"] != "code_slice":
        raise HTTPException(404, "此证据没有可定位的源码")
    scan = await db.get(ScanTask, run.scan_id)
    if scan is None:
        raise HTTPException(404, "扫描不存在")
    revision = run.repository_revision
    prefixes = tuple(_loads(run.scope_json, {}).get("path_prefixes", []))
    policy = BudgetPolicy(**_loads(run.config_snapshot, {}).get("policy", {}))
    await db.commit()
    try:
        ledger = BudgetLedger(policy)
        repo = await svc._repository(scan, AuditScope(path_prefixes=prefixes), ledger)
        if repo.revision != revision:
            raise ToolPolicyError("扫描源码版本已变化")
        snippet = await asyncio.wait_for(asyncio.to_thread(
            repo.read_slice,
            {"path": relative_path(evidence["file_path"]),
             "start_line": evidence["line_start"], "end_line": evidence["line_end"]},
            char_limit=policy.max_output_chars,
        ), timeout=ledger.remaining_seconds())
        if snippet.content_hash != evidence["content_hash"] or snippet.line_end != evidence["line_end"]:
            raise ToolPolicyError("证据内容校验失败")
    except (OSError, ValueError, BudgetExceeded, TimeoutError) as exc:
        raise HTTPException(409, "历史源码已删除、版本不符或不可读取，无法定位这条证据") from exc
    return {"file_path": snippet.path, "line_start": snippet.line_start,
            "line_end": snippet.line_end, "content": snippet.content}


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
