"""Deep Audit V1 scheduler: one Planner -> one general Worker -> blackboard.

This is an ADDITIONAL, opt-in execution mode. It never replaces or calls the
existing ``run_llm_audit_pipeline`` / ``run_scan_pipeline`` chains, and it does
not modify ScanTask status, so existing scanners, LLM audit, conversation,
review and reporting keep working exactly as before.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import (
    AuditRun, AuditRunStatus, AuditTask, AuditTaskStatus, AgentDefinition,
    Finding, ScanTask, ScanStatus,
)
from app.services import blackboard_service as bb
from app.services.deep_audit_budget import (
    BudgetExceeded, BudgetLedger, BudgetPolicy,
)
from app.services.deep_audit_guards import ReadOnlyRepository, ToolPolicyError, relative_path
from app.services.deep_audit_planner import AuditScope, PlannerInput, plan_tasks
from app.services.deep_audit_worker import log_event, run_worker_task
from app.services.endpoint_discovery_service import list_endpoints_summary
from app.services.llm_provider import is_llm_configured

logger = logging.getLogger(__name__)

_active_runs: dict[int, asyncio.Task] = {}
_cancel_requested: set[int] = set()
_dispatch_lock = asyncio.Lock()


class DeepAuditCancelled(Exception):
    """Cooperative cancellation; already committed facts are kept."""


@dataclass
class DeepAuditStartOptions:
    scan_id: int
    agent_slug: str | None = None
    focus: list[str] = field(default_factory=list)
    path_prefixes: list[str] = field(default_factory=list)
    max_tasks: int | None = None


def request_cancel(run_id: int) -> None:
    if is_active(run_id):
        _cancel_requested.add(run_id)


def clear_cancel(run_id: int) -> None:
    _cancel_requested.discard(run_id)


def check_cancel(run_id: int) -> None:
    if run_id in _cancel_requested:
        raise DeepAuditCancelled("用户已取消 Deep Audit 运行")


def is_active(run_id: int) -> bool:
    task = _active_runs.get(run_id)
    return task is not None and not task.done()


def _loads(value: str | None, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except (json.JSONDecodeError, TypeError):
        return fallback


async def _resolve_agent(db: AsyncSession, slug: str | None) -> AgentDefinition | None:
    stmt = select(AgentDefinition).where(AgentDefinition.enabled.is_(True))
    if slug:
        stmt = stmt.where(AgentDefinition.slug == slug.strip())
    else:
        return None
    stmt = stmt.order_by(AgentDefinition.id.asc()).limit(1)
    return (await db.execute(stmt)).scalars().first()


def _project_root(scan: ScanTask) -> Path:
    root = Path(scan.project_path).resolve()
    managed_roots = (settings.repos_dir.resolve(), settings.uploads_dir.resolve())
    if not any(parent in root.parents for parent in managed_roots) or not root.is_dir():
        raise ToolPolicyError("扫描源码必须位于平台管理的仓库或上传目录")
    if scan.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        raise ValueError("扫描尚未结束，暂不能启动 Deep Audit")
    return root


async def _repository(scan: ScanTask, scope: AuditScope, ledger: BudgetLedger, check=None) -> ReadOnlyRepository:
    def checkpoint():
        ledger.check_time()
        if check:
            check()

    return await asyncio.wait_for(
        asyncio.to_thread(
            ReadOnlyRepository, _project_root(scan), ledger.policy,
            prefixes=scope.path_prefixes, check=checkpoint,
        ),
        timeout=ledger.remaining_seconds(),
    )


async def _endpoints(repo: ReadOnlyRepository, ledger: BudgetLedger, check=None) -> list[dict]:
    def checkpoint():
        ledger.check_time()
        if check:
            check()

    return await asyncio.wait_for(
        asyncio.to_thread(
            list_endpoints_summary, repo.root, limit=40, source_files=repo.files,
            read_source=repo.read_source, cancel_check=checkpoint,
        ),
        timeout=ledger.remaining_seconds(),
    )


async def _sast_context(db: AsyncSession, scan_id: int) -> list[dict]:
    from app.models import FindingCategory

    rows = (await db.scalars(
        select(Finding)
        .where(
            Finding.scan_id == scan_id, Finding.category == FindingCategory.SAST,
            Finding.tool != "deep_audit",
        )
        .order_by(Finding.id.desc())
        .limit(60)
    )).all()
    return [
        {"file_path": row.file_path, "rule_id": row.rule_id, "severity": row.severity.value,
         "message": row.message, "tool": row.tool}
        for row in rows
    ]


async def _previous_context(db: AsyncSession, scan_id: int, current_run_id: int, revision: str) -> tuple[list[dict], set[str]]:
    from app.models import AuditFact, AuditTaskStatus

    fact_rows = (
        await db.execute(
            select(AuditFact)
            .join(AuditRun, AuditFact.run_id == AuditRun.id)
            .where(AuditRun.scan_id == scan_id, AuditRun.repository_revision == revision)
            .order_by(AuditFact.id.desc())
            .limit(120)
        )
    ).scalars().all()
    facts = [
        {"id": row.id, "summary": row.summary, "metadata": _loads(row.metadata_json, {})}
        for row in fact_rows
    ]
    task_rows = (
        await db.execute(
            select(AuditTask.fingerprint)
            .join(AuditRun, AuditTask.run_id == AuditRun.id)
            .where(
                AuditRun.scan_id == scan_id,
                AuditRun.id != current_run_id,
                AuditRun.repository_revision == revision,
                AuditTask.status == AuditTaskStatus.COMPLETED.value,
            )
        )
    ).scalars().all()
    return facts, set(str(fp) for fp in task_rows)


async def start_deep_audit(db: AsyncSession, options: DeepAuditStartOptions) -> AuditRun:
    """Validate inputs, create the run row, and schedule execution in background."""
    scan = await db.get(ScanTask, options.scan_id)
    if scan is None:
        raise ValueError(f"扫描不存在: {options.scan_id}")
    agent = await _resolve_agent(db, options.agent_slug)
    if options.agent_slug and agent is None:
        raise ValueError(f"AgentDefinition 不存在或未启用: {options.agent_slug}")

    policy = (await BudgetPolicy.for_new_run(db)).constrained_by(agent)
    use_llm = is_llm_configured()
    scope = AuditScope(
        focus=tuple(options.focus),
        path_prefixes=tuple(relative_path(path) for path in options.path_prefixes),
        max_tasks=options.max_tasks or policy.max_tasks,
    ).normalised(policy.max_tasks)
    ledger = BudgetLedger(policy)
    try:
        repo = await _repository(scan, scope, ledger)
    except (TimeoutError, BudgetExceeded) as exc:
        raise ToolPolicyError("建立只读源码清单超时") from exc
    config_snapshot = {
        "mode": "deep_audit_v1",
        "planner": "deterministic_v1",
        "worker_count": 1,
        "worker_mode": "llm" if use_llm else "deterministic_fallback",
        "llm_configured": use_llm,
        "agent_definition_id": agent.id if agent else None,
        "agent_role": agent.role if agent else "built-in",
        "policy": policy.to_dict(),
        "mcp_tools_granted": False,
        "skills_granted": False,
    }
    async with _dispatch_lock:
        active_ids = [run_id for run_id in _active_runs if is_active(run_id)]
        if active_ids and await db.scalar(
            select(AuditRun.id).where(AuditRun.id.in_(active_ids), AuditRun.scan_id == scan.id).limit(1)
        ):
            raise ValueError("该扫描已有 Deep Audit 运行正在执行中")
        run = await bb.create_run(
            db, options.scan_id,
            config_snapshot=config_snapshot,
            scope=scope.to_dict(),
            agent_slug=agent.slug if agent else "deep-audit-worker",
            agent_definition_id=agent.id if agent else None,
            revision=repo.revision,
        )
        await bb.update_run(db, run, budget_usage=ledger.snapshot())
        coro = execute_run(run.id, use_llm=use_llm, repo=repo)
        task = asyncio.create_task(coro, name=f"deep-audit-run-{run.id}")
        _active_runs[run.id] = task

        def _clear(done: asyncio.Task) -> None:
            if _active_runs.get(run.id) is done:
                _active_runs.pop(run.id, None)
                clear_cancel(run.id)

        task.add_done_callback(_clear)
    await asyncio.sleep(0)
    return run


async def execute_run(run_id: int, *, use_llm: bool = False, repo: ReadOnlyRepository | None = None) -> None:
    """Full run lifecycle; keep the run row consistent on unexpected failures."""
    try:
        await _execute_run_inner(run_id, use_llm=use_llm, repo=repo)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("Deep Audit run %s stopped: %s", run_id, type(exc).__name__)
        async with async_session() as db:
            run = await bb.get_run(db, run_id)
            if run is not None and run.status not in (
                AuditRunStatus.COMPLETED.value, AuditRunStatus.CANCELLED.value
            ):
                await bb.update_run(
                    db, run, status=(AuditRunStatus.CANCELLED.value if isinstance(exc, DeepAuditCancelled)
                                     else AuditRunStatus.FAILED.value),
                    error_message=str(exc) if isinstance(exc, (BudgetExceeded, ToolPolicyError, DeepAuditCancelled))
                    else f"运行异常：{type(exc).__name__}",
                    finished=True,
                )


async def _execute_run_inner(run_id: int, *, use_llm: bool = False, repo: ReadOnlyRepository | None = None) -> None:
    """Every committed fact survives any early exit of this function."""
    async with async_session() as db:
        run = await bb.get_run(db, run_id)
        if run is None:
            return
        scan = await db.get(ScanTask, run.scan_id)
        if scan is None:
            await bb.update_run(
                db, run, status=AuditRunStatus.FAILED.value,
                error_message="扫描记录已不存在", finished=True,
            )
            return
        agent = (
            await db.get(AgentDefinition, run.agent_definition_id)
            if run.agent_definition_id else None
        )
        if run.agent_definition_id and (agent is None or not agent.enabled):
            raise ToolPolicyError("选定的 AgentDefinition 已停用或删除")
        try:
            policy = BudgetPolicy(**(_loads(run.config_snapshot, {}).get("policy") or BudgetPolicy.from_settings().to_dict()))
        except (ToolPolicyError, TypeError, ValueError) as exc:
            await bb.update_run(
                db, run, status=AuditRunStatus.FAILED.value,
                error_message=f"只读仓库不可用: {exc}", finished=True,
            )
            return

        ledger = BudgetLedger.restore(policy, _loads(run.budget_usage, {}))
        scope_dict = _loads(run.scope_json, {})
        scope = AuditScope(
            focus=tuple(scope_dict.get("focus") or ()),
            path_prefixes=tuple(relative_path(p) for p in scope_dict.get("path_prefixes", [])),
            max_tasks=int(scope_dict.get("max_tasks") or policy.max_tasks),
        )
        check = lambda: check_cancel(run_id)
        check()
        if repo is None:
            repo = await _repository(scan, scope, ledger, check)
        if repo.revision != run.repository_revision:
            raise ToolPolicyError("扫描源码版本已变化，请启动新的 Deep Audit 运行")
        await bb.update_run(db, run, status=AuditRunStatus.PLANNING.value)
        await log_event(
            db, run.scan_id, "run_started",
            {"run_id": run_id, "revision": run.repository_revision,
             "agent": run.agent_slug, "mode": "llm" if use_llm else "deterministic"},
        )

        tasks = await bb.list_tasks(db, run_id)
        if not tasks:
            sast_findings = await _sast_context(db, run.scan_id)
            endpoints = await _endpoints(repo, ledger, check)
            previous_facts, previous_fingerprints = await _previous_context(
                db, run.scan_id, run_id, repo.revision,
            )
            planner_input = PlannerInput(
                project_info={
                    "scan_id": run.scan_id,
                    "name": scan.name,
                    "source": scan.source.value,
                    "revision": run.repository_revision,
                    "sast_finding_count": len(sast_findings),
                    "endpoint_count": len(endpoints),
                },
                sast_findings=sast_findings,
                endpoints=endpoints,
                existing_facts=previous_facts,
                previous_task_fingerprints=previous_fingerprints,
                scope=scope,
                revision=run.repository_revision,
            )
            specs = plan_tasks(planner_input, hard_max_tasks=policy.max_tasks)
            await log_event(
                db, run.scan_id, "planner_finished",
                {"run_id": run_id, "task_count": len(specs),
                 "focus": scope_dict.get("focus"), "revision": run.repository_revision},
            )
            tasks = await bb.upsert_tasks(db, run_id, specs, run.agent_slug)
        await bb.update_run(db, run, status=AuditRunStatus.RUNNING.value)

        exhausted: str | None = None
        cancelled = False
        failure: str | None = None
        for task in tasks:
            if task.status in (AuditTaskStatus.SKIPPED.value, AuditTaskStatus.COMPLETED.value):
                continue
            if exhausted or cancelled or failure:
                break
            try:
                check_cancel(run_id)
            except DeepAuditCancelled:
                cancelled = True
                break
            await bb.update_task(db, task, status=AuditTaskStatus.RUNNING.value)
            try:
                outcome = await run_worker_task(
                    db, run=run, task=task, repo=repo, policy=policy,
                    ledger=ledger, agent=agent,
                    cancel_check=lambda: check_cancel(run_id),
                    use_llm=use_llm,
                )
                await bb.update_task(
                    db, task,
                    status=AuditTaskStatus.COMPLETED.value,
                    result_summary=outcome.summary(),
                    budget_usage=ledger.snapshot(),
                )
            except BudgetExceeded as exc:
                exhausted = exc.dimension
                await bb.update_task(
                    db, task, status=AuditTaskStatus.FAILED.value,
                    result_summary=f"预算耗尽（{exc.dimension}），已完成事实已保存",
                )
                ledger.exhausted_dimension = exc.dimension
            except DeepAuditCancelled:
                cancelled = True
                await bb.update_task(
                    db, task, status=AuditTaskStatus.PENDING.value,
                    result_summary="已取消；已保存事实与证据保留，可恢复运行",
                )
            except (ToolPolicyError, OSError, ValueError) as exc:
                failure = str(exc) if isinstance(exc, ToolPolicyError) else f"任务异常：{type(exc).__name__}"
                await bb.update_task(
                    db, task, status=AuditTaskStatus.FAILED.value,
                    result_summary=failure[:500],
                )
                logger.warning("Deep Audit task failed run=%s task=%s: %s", run_id, task.id, type(exc).__name__)
            finally:
                await bb.update_run(db, run, budget_usage=ledger.snapshot())

        cancelled = cancelled or run_id in _cancel_requested
        if cancelled:
            final_status = AuditRunStatus.CANCELLED.value
            message = "用户取消；已保存事实与证据保留"
        elif exhausted:
            final_status = AuditRunStatus.FAILED.value
            message = f"预算维度 {exhausted} 耗尽，已保存事实与证据保留"
        elif failure:
            final_status = AuditRunStatus.FAILED.value
            message = failure
        else:
            final_status = AuditRunStatus.COMPLETED.value
            message = None
        await bb.update_run(
            db, run, status=final_status, budget_usage=ledger.snapshot(),
            error_message=message, finished=True,
        )
        await log_event(
            db, run.scan_id, "run_finished",
            {"run_id": run_id, "status": final_status,
             "exhausted_dimension": exhausted, "budget": ledger.snapshot()},
        )


async def resume_run(run_id: int, *, use_llm: bool | None = None) -> AuditRun | None:
    """Re-open an interrupted/cancelled run and continue with the same blackboard."""
    async with _dispatch_lock:
        if is_active(run_id):
            raise ValueError("运行仍在执行中，不能恢复")
        async with async_session() as db:
            current = await bb.get_run(db, run_id)
            if current is None:
                return None
            active_ids = [active_id for active_id in _active_runs if is_active(active_id)]
            if active_ids and await db.scalar(
                select(AuditRun.id).where(AuditRun.id.in_(active_ids), AuditRun.scan_id == current.scan_id).limit(1)
            ):
                raise ValueError("该扫描已有 Deep Audit 运行正在执行中")
            run = await bb.resume_run(db, run_id)
            if run is None:
                return None
            effective_llm = use_llm if use_llm is not None else bool(
                _loads(run.config_snapshot, {}).get("llm_configured")
            )
        task = asyncio.create_task(
            execute_run(run_id, use_llm=effective_llm), name=f"deep-audit-run-{run_id}"
        )
        _active_runs[run_id] = task

        def _clear(done: asyncio.Task) -> None:
            if _active_runs.get(run_id) is done:
                _active_runs.pop(run_id, None)
                clear_cancel(run_id)

        task.add_done_callback(_clear)
    return run


async def plan_preview(db: AsyncSession, scan_id: int, scope: AuditScope) -> dict:
    """Planner-only dry run (no execution, no writes) for the UI."""
    scan = await db.get(ScanTask, scan_id)
    if scan is None:
        raise ValueError(f"扫描不存在: {scan_id}")
    policy = await BudgetPolicy.for_new_run(db)
    sast_findings = await _sast_context(db, scan_id)
    preview_scope = scope.normalised(policy.max_tasks)
    ledger = BudgetLedger(policy)
    try:
        repo = await _repository(scan, preview_scope, ledger)
        endpoints = await _endpoints(repo, ledger)
    except (TimeoutError, BudgetExceeded) as exc:
        raise ToolPolicyError("生成审计计划超时") from exc
    previous_facts, previous_fps = await _previous_context(db, scan_id, -1, repo.revision)
    data = PlannerInput(
        project_info={"scan_id": scan_id, "name": scan.name},
        sast_findings=sast_findings,
        endpoints=endpoints,
        existing_facts=previous_facts,
        previous_task_fingerprints=previous_fps,
        scope=preview_scope,
        revision=repo.revision,
    )
    return {
        "scan_id": scan_id,
        "revision": repo.revision,
        "scope": preview_scope.to_dict(),
        "tasks": plan_tasks(data, hard_max_tasks=policy.max_tasks),
    }
