"""Dedicated database API for the Deep Audit V1 shared fact blackboard.

Nothing in the Planner / Worker / scheduler writes ORM rows directly: all
mutations go through this module. Each write commits immediately, so a cancelled
Worker, a budget abort or a process restart cannot lose facts already saved.

Compatibility: these are additive tables. Candidate conclusions are linked to
the EXISTING ``Finding`` entity via ``AuditFact.finding_id`` -- no second
finding model is introduced, and no existing table column is changed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AiVerdict, AuditEvidence, AuditFact, AuditFactType, AuditRun,
    AuditRunStatus, AuditTask, AuditTaskStatus, Finding, FindingCategory,
    ReviewStatus, ScanTask, Severity, dt_iso, utcnow,
)
from app.services.deep_audit_lineup import public_config
from app.services.tool_log_redaction import redact_text

logger = logging.getLogger(__name__)

FACT_TYPES = tuple(item.value for item in AuditFactType)
MAX_SUMMARY_CHARS = 4000


def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def compute_fact_fingerprint(
    fact_type: str,
    summary: str,
    *,
    dedupe_key: str | None = None,
    source: str | None = None,
    revision: str | None = None,
    file_path: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
) -> str:
    """Stable de-duplication key for a code fact, across tasks and runs.

    ``dedupe_key`` (e.g. ``read_file:app/api.py:1-120``) is preferred for tool
    observations, because LLM-written summaries vary between runs. The revision
    is part of the key so the same path in a different code version is a NEW
    fact rather than a stale one.
    """
    if dedupe_key:
        base = f"{_norm(fact_type)}|key:{_norm(dedupe_key)}|rev:{_norm(revision)}"
    else:
        base = "|".join(
            (
                _norm(fact_type),
                _norm(source),
                _norm(file_path),
                str(int(line_start or 0)),
                str(int(line_end or 0)),
                _norm(summary),
                _norm(revision),
            )
        )
    return _sha(base)


def compute_task_fingerprint(task_type: str, target: str, revision: str, focus: str) -> str:
    return _sha("|".join((_norm(task_type), _norm(target), _norm(revision), _norm(focus))))


def compute_evidence_fingerprint(
    revision: str, file_path: str, line_start: int, line_end: int, content_hash: str
) -> str:
    return _sha(
        "|".join(
            (
                _norm(revision), _norm(file_path), str(int(line_start)),
                str(int(line_end)), _norm(content_hash),
            )
        )
    )


def _dumps(value: Any) -> str:
    try:
        return json.dumps(value or {}, ensure_ascii=False)
    except (TypeError, ValueError):
        return "{}"


def _loads(value: str | None, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except (json.JSONDecodeError, TypeError):
        return fallback


# --------------------------------------------------------------------- runs

async def create_run(
    db: AsyncSession,
    scan_id: int,
    *,
    config_snapshot: dict,
    scope: dict,
    agent_slug: str,
    agent_definition_id: int | None,
    revision: str,
) -> AuditRun:
    scan = await db.get(ScanTask, scan_id)
    if scan is None:
        raise ValueError(f"扫描不存在: {scan_id}")
    row = AuditRun(
        scan_id=scan_id,
        status=AuditRunStatus.PENDING.value,
        config_snapshot=_dumps(config_snapshot),
        scope_json=_dumps(scope),
        repository_revision=str(revision or "")[:128],
        agent_slug=str(agent_slug or "")[:64],
        agent_definition_id=agent_definition_id,
        budget_usage=_dumps({}),
        started_at=utcnow(),
    )
    db.add(row)
    await db.commit()
    return row


async def get_run(db: AsyncSession, run_id: int) -> AuditRun | None:
    return await db.get(AuditRun, run_id)


async def list_runs(db: AsyncSession, scan_id: int | None, limit: int = 30) -> list[AuditRun]:
    stmt = select(AuditRun).order_by(AuditRun.id.desc()).limit(max(1, min(limit, 200)))
    if scan_id is not None:
        stmt = stmt.where(AuditRun.scan_id == scan_id)
    return list((await db.execute(stmt)).scalars().all())


async def update_run(
    db: AsyncSession,
    run: AuditRun,
    *,
    status: str | None = None,
    budget_usage: dict | None = None,
    error_message: str | None = None,
    finished: bool = False,
) -> AuditRun:
    if status is not None:
        run.status = status
    if budget_usage is not None:
        run.budget_usage = _dumps(budget_usage)
    if error_message is not None:
        run.error_message = redact_text(error_message)[:2000]
    if finished and run.finished_at is None:
        run.finished_at = utcnow()
    await db.commit()
    return run


async def resume_run(db: AsyncSession, run_id: int) -> AuditRun | None:
    """Re-open an interrupted run; already saved facts/tasks are never deleted."""
    run = await db.get(AuditRun, run_id)
    if run is None or run.status == AuditRunStatus.COMPLETED.value:
        return None
    run.status = AuditRunStatus.PENDING.value
    run.error_message = None
    run.finished_at = None
    tasks = (
        await db.execute(select(AuditTask).where(AuditTask.run_id == run_id))
    ).scalars().all()
    for task in tasks:
        if task.status in (AuditTaskStatus.RUNNING.value, AuditTaskStatus.FAILED.value):
            task.status = AuditTaskStatus.PENDING.value
            task.finished_at = None
    await db.commit()
    return run


# -------------------------------------------------------------------- tasks

async def upsert_tasks(
    db: AsyncSession,
    run: AuditRun,
    specs: list[dict],
    *,
    config_snapshot: dict,
) -> list[AuditTask]:
    """Commit the validated plan and its planning result in one transaction."""
    run_id = run.id
    run.config_snapshot = _dumps(config_snapshot)
    existing = {
        row.fingerprint: row
        for row in (
            await db.execute(select(AuditTask).where(AuditTask.run_id == run_id))
        ).scalars().all()
    }
    result: list[AuditTask] = []
    for spec in specs:
        fp = str(spec.get("fingerprint") or "")[:64]
        if not fp:
            continue
        if fp in existing:
            result.append(existing[fp])
            continue
        row = AuditTask(
            run_id=run_id,
            agent_id=spec["agent_id"],
            task_type=str(spec.get("task_type") or "business_logic")[:32],
            goal=redact_text(str(spec.get("goal") or ""))[:MAX_SUMMARY_CHARS],
            status=str(spec.get("status") or AuditTaskStatus.PENDING.value),
            priority=int(spec.get("priority") or 0),
            fingerprint=fp,
            scope_json=_dumps(spec.get("scope") or {}),
            result_summary=str(spec.get("result_summary") or ""),
        )
        db.add(row)
        await db.flush()
        existing[fp] = row
        result.append(row)
    await db.commit()
    return result


async def list_tasks(db: AsyncSession, run_id: int) -> list[AuditTask]:
    return list(
        (
            await db.execute(
                select(AuditTask)
                .where(AuditTask.run_id == run_id)
                .order_by(AuditTask.priority.desc(), AuditTask.id.asc())
            )
        ).scalars().all()
    )


async def update_task(
    db: AsyncSession,
    task: AuditTask,
    *,
    status: str | None = None,
    result_summary: str | None = None,
    budget_usage: dict | None = None,
) -> AuditTask:
    if status is not None:
        task.status = status
        if status == AuditTaskStatus.RUNNING.value and task.started_at is None:
            task.started_at = utcnow()
        if status in (
            AuditTaskStatus.COMPLETED.value,
            AuditTaskStatus.FAILED.value,
            AuditTaskStatus.SKIPPED.value,
        ) and task.finished_at is None:
            task.finished_at = utcnow()
    if result_summary is not None:
        task.result_summary = redact_text(str(result_summary))[:MAX_SUMMARY_CHARS]
    if budget_usage is not None:
        task.budget_usage = _dumps(budget_usage)
    await db.commit()
    return task


# -------------------------------------------------------------------- facts

async def add_fact(
    db: AsyncSession,
    run_id: int,
    *,
    fact_type: str,
    summary: str,
    source: str,
    confidence: float = 0.5,
    task_id: int | None = None,
    dedupe_key: str | None = None,
    revision: str | None = None,
    file_path: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    metadata: dict | None = None,
    cross_run_dedupe: bool = True,
) -> tuple[AuditFact, bool]:
    """Write one fact immediately; return ``(fact, created)``.

    De-duplication happens in two layers: within the run (unique constraint)
    and across previous runs of the SAME scan (query by fingerprint). Re-running
    Deep Audit on an unchanged revision therefore does not pile up duplicates.
    """
    if fact_type not in FACT_TYPES:
        raise ValueError(f"未知事实类型: {fact_type}")
    clean_summary = redact_text(str(summary or "").strip())[:MAX_SUMMARY_CHARS]
    fp = compute_fact_fingerprint(
        fact_type, clean_summary,
        dedupe_key=dedupe_key, source=source, revision=revision,
        file_path=file_path, line_start=line_start, line_end=line_end,
    )
    existing = (
        await db.execute(
            select(AuditFact).where(
                AuditFact.run_id == run_id, AuditFact.fingerprint == fp
            )
        )
    ).scalars().first()
    if existing is None and cross_run_dedupe:
        scan_id = (
            await db.execute(select(AuditRun.scan_id).where(AuditRun.id == run_id))
        ).scalar_one_or_none()
        if scan_id is not None:
            existing = (
                await db.execute(
                    select(AuditFact)
                    .join(AuditRun, AuditFact.run_id == AuditRun.id)
                    .where(AuditRun.scan_id == scan_id, AuditFact.fingerprint == fp)
                    .order_by(AuditFact.id.asc())
                    .limit(1)
                )
            ).scalars().first()
    if existing is not None:
        return existing, False

    row = AuditFact(
        run_id=run_id,
        task_id=task_id,
        fact_type=fact_type,
        summary=clean_summary,
        source=str(source or "")[:255],
        confidence=max(0.0, min(1.0, float(confidence or 0.0))),
        fingerprint=fp,
        metadata_json=_dumps(metadata or {}),
    )
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        found = (
            await db.execute(
                select(AuditFact).where(
                    AuditFact.run_id == run_id, AuditFact.fingerprint == fp
                )
            )
        ).scalars().first()
        if found is not None:
            return found, False
        raise
    return row, True


async def add_evidence(
    db: AsyncSession,
    fact_id: int,
    slices: list[Any],
    *,
    revision: str,
    evidence_type: str = "code_slice",
    summary_prefix: str = "读取到的代码范围",
) -> list[AuditEvidence]:
    """Attach verifiable code evidence (revision + line range + content hash)."""
    created: list[AuditEvidence] = []
    seen: set[str] = set()
    for item in slices:
        fp = compute_evidence_fingerprint(
            revision, item.path, item.line_start, item.line_end, item.content_hash
        )
        if fp in seen:
            continue
        seen.add(fp)
        found = (
            await db.execute(
                select(AuditEvidence).where(
                    AuditEvidence.fact_id == fact_id, AuditEvidence.fingerprint == fp
                )
            )
        ).scalars().first()
        if found is not None:
            continue
        row = AuditEvidence(
            fact_id=fact_id,
            fingerprint=fp,
            repository_revision=str(revision or "")[:128],
            file_path=str(item.path)[:1024],
            line_start=int(item.line_start),
            line_end=int(item.line_end),
            content_hash=str(item.content_hash)[:64],
            evidence_type=str(evidence_type)[:32],
            evidence_summary=f"{summary_prefix}: {item.path}:{item.line_start}-{item.line_end}",
        )
        db.add(row)
        created.append(row)
    if created:
        await db.commit()
    return created


async def evidence_for_fact(db: AsyncSession, fact_id: int) -> list[AuditEvidence]:
    return list(
        (
            await db.execute(
                select(AuditEvidence)
                .where(AuditEvidence.fact_id == fact_id)
                .order_by(AuditEvidence.id.asc())
            )
        ).scalars().all()
    )


async def list_facts(
    db: AsyncSession,
    run_id: int,
    *,
    fact_type: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Cross-Worker read of shared facts, including their evidence rows."""
    stmt = select(AuditFact).where(AuditFact.run_id == run_id)
    if fact_type:
        stmt = stmt.where(AuditFact.fact_type == fact_type)
    rows = (
        await db.execute(stmt.order_by(AuditFact.id.asc()).limit(max(1, min(limit, 500))))
    ).scalars().all()
    out: list[dict] = []
    for row in rows:
        ev = await evidence_for_fact(db, row.id)
        out.append(serialize_fact(row, ev))
    return out


def serialize_fact(row: AuditFact, evidence: list[AuditEvidence] | None = None) -> dict:
    return {
        "id": row.id,
        "run_id": row.run_id,
        "task_id": row.task_id,
        "fact_type": row.fact_type,
        "summary": row.summary,
        "source": row.source,
        "confidence": row.confidence,
        "fingerprint": row.fingerprint,
        "finding_id": row.finding_id,
        "metadata": _loads(row.metadata_json, {}),
        "created_at": dt_iso(row.created_at),
        "evidence": [serialize_evidence(item) for item in (evidence or [])],
    }


def serialize_evidence(row: AuditEvidence) -> dict:
    return {
        "id": row.id,
        "fact_id": row.fact_id,
        "repository_revision": row.repository_revision,
        "file_path": row.file_path,
        "line_start": row.line_start,
        "line_end": row.line_end,
        "content_hash": row.content_hash,
        "evidence_type": row.evidence_type,
        "evidence_summary": row.evidence_summary,
        "created_at": dt_iso(row.created_at),
    }


async def shared_facts_digest(db: AsyncSession, run_id: int, limit: int = 12) -> str:
    """Compact blackboard snapshot injected into every Worker prompt."""
    rows = (
        await db.execute(
            select(AuditFact)
            .where(AuditFact.run_id == run_id)
            .order_by(AuditFact.id.desc())
            .limit(max(1, min(limit, 50)))
        )
    ).scalars().all()
    if not rows:
        return "（黑板暂无事实）"
    lines = [
        f"- [{row.fact_type}] {row.summary[:160]} (来源 {row.source}, 置信 {row.confidence:.2f})"
        for row in reversed(rows)
    ]
    return "\n".join(lines)


# ------------------------------------------------- link to existing Finding

def _severity(value: Any) -> Severity:
    key = str(value or "").upper()
    return Severity(key) if key in Severity.__members__ else Severity.MEDIUM


def _category(value: Any, task_type: str | None) -> FindingCategory:
    key = str(value or "").lower()
    if key in [item.value for item in FindingCategory]:
        return FindingCategory(key)
    if task_type == "injection":
        return FindingCategory.SAST
    if task_type == "authz":
        return FindingCategory.AUTHORIZATION
    return FindingCategory.BUSINESS_LOGIC


async def link_candidate_finding(
    db: AsyncSession,
    run: AuditRun,
    fact: AuditFact,
    candidate: dict,
) -> Finding | None:
    """Link an evidence-backed candidate to the EXISTING Finding entity.

    Hard rule: without at least one AuditEvidence row for this fact, NOTHING is
    written to ``findings``. Even with evidence, the new Finding stays
    ``review_status=UNREVIEWED`` / ``ai_verdict=PENDING`` -- a confirmed
    vulnerability requires an explicit human review via ``confirm_finding``.
    """
    evidence = await evidence_for_fact(db, fact.id)
    if fact.fact_type != AuditFactType.CANDIDATE_FINDING.value or not evidence:
        logger.info("Skip candidate without code evidence (fact_id=%s)", fact.id)
        return None

    run_id = run.id
    scan_id = run.scan_id
    file_path = str(candidate.get("file") or evidence[0].file_path)[:1024]
    line_start = int(candidate.get("line_start") or evidence[0].line_start or 0)
    line_end = int(candidate.get("line_end") or line_start or evidence[0].line_end or 0)
    rule_id = str(candidate.get("rule_id") or f"deep-audit/{fact.fact_type}")[:512]
    if not any(
        row.repository_revision == run.repository_revision and row.file_path == file_path
        and row.evidence_type == "code_slice" and row.line_start <= line_start <= row.line_end
        for row in evidence
    ):
        return None

    matching = (
        await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.tool == "deep_audit",
                Finding.rule_id == rule_id,
                Finding.file_path == file_path,
                Finding.line_start == line_start,
            )
        )
    ).scalars().all()
    existing = next(
        (row for row in matching if _loads(row.metadata_json, {}).get("repository_revision") == run.repository_revision),
        None,
    )
    if existing is not None:
        fact.finding_id = existing.id
        await db.commit()
        return existing

    metadata = {
        "deep_audit_run_id": run_id,
        "audit_fact_id": fact.id,
        "audit_evidence_ids": [item.id for item in evidence],
        "repository_revision": run.repository_revision,
        "candidate": True,
        "source": "deep_audit_v1",
    }
    snippet = redact_text(str(candidate.get("code_snippet") or ""))[:2000] or None
    finding = Finding(
        scan_id=scan_id,
        rule_id=rule_id,
        severity=_severity(candidate.get("severity")),
        message=redact_text(str(candidate.get("message") or candidate.get("title") or fact.summary))[:4000],
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        code_snippet=snippet,
        metadata_json=_dumps(metadata),
        tool="deep_audit",
        category=_category(candidate.get("category"), candidate.get("task_type")),
        ai_verdict=AiVerdict.PENDING,
        ai_confidence=float(fact.confidence or 0.0),
        ai_reason="Deep Audit V1 候选：已有代码证据，待人工复核",
        review_status=ReviewStatus.UNREVIEWED,
    )
    db.add(finding)
    await db.flush()
    fact.finding_id = finding.id
    scan = await db.get(ScanTask, scan_id)
    if scan:
        scan.total_findings = await db.scalar(
            select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
        )
    await db.commit()
    return finding


async def has_finding_evidence(db: AsyncSession, finding: Finding, *, run_id: int | None = None) -> bool:
    revision = _loads(finding.metadata_json, {}).get("repository_revision")
    stmt = (
        select(AuditEvidence.id)
        .join(AuditFact, AuditEvidence.fact_id == AuditFact.id)
        .join(AuditRun, AuditFact.run_id == AuditRun.id)
        .where(
            AuditFact.finding_id == finding.id,
            AuditFact.fact_type == AuditFactType.CANDIDATE_FINDING.value,
            AuditRun.scan_id == finding.scan_id,
            AuditRun.repository_revision == revision,
            AuditEvidence.repository_revision == revision,
            AuditEvidence.evidence_type == "code_slice",
            AuditEvidence.file_path == finding.file_path,
            AuditEvidence.line_start <= finding.line_start,
            AuditEvidence.line_end >= finding.line_start,
        )
    )
    if run_id is not None:
        stmt = stmt.where(AuditRun.id == run_id)
    return (await db.scalar(stmt.limit(1))) is not None


async def confirm_finding(
    db: AsyncSession, run: AuditRun, finding_id: int, *, review_note: str = ""
) -> Finding | None:
    """Human review: mark a Deep Audit candidate as confirmed, evidence required."""
    finding = await db.get(Finding, finding_id)
    if finding is None or finding.scan_id != run.scan_id or finding.tool != "deep_audit":
        return None
    if not await has_finding_evidence(db, finding, run_id=run.id):
        return None
    from app.services.scan_service import update_finding_review

    return await update_finding_review(
        db, run.scan_id, finding_id, ReviewStatus.CONFIRMED,
        redact_text(review_note).strip() or "人工复核确认（Deep Audit V1）",
    )


async def run_summary(db: AsyncSession, run_id: int) -> dict | None:
    """Single aggregate payload for the minimal frontend panel."""
    run = await db.get(AuditRun, run_id)
    if run is None:
        return None
    tasks = await list_tasks(db, run_id)
    facts = await list_facts(db, run_id, limit=200)
    running = next((t for t in tasks if t.status == AuditTaskStatus.RUNNING.value), None)
    candidate_facts = [f for f in facts if f["fact_type"] == AuditFactType.CANDIDATE_FINDING.value]
    linked_ids = [f["finding_id"] for f in facts if f.get("finding_id")]
    confirmed: list[dict] = []
    if linked_ids:
        rows = (
            await db.execute(
                select(Finding).where(
                    Finding.id.in_(linked_ids),
                    Finding.review_status == ReviewStatus.CONFIRMED,
                )
            )
        ).scalars().all()
        confirmed = [
            {
                "id": row.id, "rule_id": row.rule_id, "severity": row.severity.value,
                "file_path": row.file_path, "line_start": row.line_start,
                "message": row.message,
            }
            for row in rows
        ]
    budget = _loads(run.budget_usage, {})
    config = public_config(_loads(run.config_snapshot, {}))
    planner = (config.get("lineup") or {}).get("planner")
    current_agent = running.agent_id if running else run.agent_slug or "deep-audit-worker"
    if run.status == AuditRunStatus.PLANNING.value:
        current_agent = planner["slug"] if planner else "deterministic_v1"
    return {
        "run": {
            "id": run.id, "scan_id": run.scan_id, "status": run.status,
            "repository_revision": run.repository_revision,
            "agent_slug": run.agent_slug,
            "started_at": dt_iso(run.started_at),
            "finished_at": dt_iso(run.finished_at),
            "error_message": run.error_message,
            "scope": _loads(run.scope_json, {}),
            "config_snapshot": config,
        },
        "current_agent": current_agent,
        "current_task": (
            {"id": running.id, "task_type": running.task_type, "goal": running.goal,
             "status": running.status, "priority": running.priority}
            if running else None
        ),
        "tasks": [
            {
                "id": t.id, "agent_id": t.agent_id, "task_type": t.task_type,
                "goal": t.goal, "status": t.status, "priority": t.priority,
                "result_summary": t.result_summary,
                "started_at": dt_iso(t.started_at), "finished_at": dt_iso(t.finished_at),
            }
            for t in tasks
        ],
        "budget_usage": budget,
        "fact_counts": {
            key: sum(1 for f in facts if f["fact_type"] == key) for key in FACT_TYPES
        },
        "shared_facts": facts[-30:],
        "candidates": candidate_facts[-20:],
        "confirmed_findings": confirmed,
    }


def now_utc() -> datetime:
    return utcnow()
