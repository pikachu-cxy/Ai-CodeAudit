"""Security score: configurable severity weights, deduct from 100."""

from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import (
    AiVerdict,
    Finding,
    ReviewStatus,
    ScanStatus,
    ScanTask,
    Severity,
    dt_iso,
)

MAX_SCORE = 100

DEFAULT_WEIGHTS: dict[str, int] = {
    Severity.CRITICAL.value: 25,
    Severity.HIGH.value: 10,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
    Severity.UNKNOWN.value: 0,
}


def get_score_weights() -> dict[str, int]:
    return {
        Severity.CRITICAL.value: max(0, int(getattr(settings, "score_weight_critical", 25))),
        Severity.HIGH.value: max(0, int(getattr(settings, "score_weight_high", 10))),
        Severity.MEDIUM.value: max(0, int(getattr(settings, "score_weight_medium", 3))),
        Severity.LOW.value: max(0, int(getattr(settings, "score_weight_low", 1))),
        Severity.INFO.value: max(0, int(getattr(settings, "score_weight_info", 0))),
        Severity.UNKNOWN.value: max(0, int(getattr(settings, "score_weight_unknown", 0))),
    }


def score_exclude_ai_fp() -> bool:
    return bool(getattr(settings, "score_exclude_ai_fp", True))


def _severity_key(finding: Finding) -> str:
    sev = finding.severity
    if isinstance(sev, Severity):
        return sev.value
    return str(sev or Severity.UNKNOWN.value)


def is_finding_excluded(finding: Finding, *, exclude_ai_fp: bool) -> bool:
    review = finding.review_status
    if review == ReviewStatus.FALSE_POSITIVE or (
        isinstance(review, str) and review == ReviewStatus.FALSE_POSITIVE.value
    ):
        return True
    if exclude_ai_fp:
        verdict = finding.ai_verdict
        if verdict == AiVerdict.FALSE_POSITIVE or (
            isinstance(verdict, str) and verdict == AiVerdict.FALSE_POSITIVE.value
        ):
            return True
    return False


def compute_score(
    findings: Iterable[Finding],
    weights: dict[str, int] | None = None,
    *,
    exclude_ai_fp: bool | None = None,
) -> dict[str, Any]:
    w = weights or get_score_weights()
    exclude_ai = score_exclude_ai_fp() if exclude_ai_fp is None else exclude_ai_fp

    by_severity: dict[str, int] = {k: 0 for k in DEFAULT_WEIGHTS}
    counted = 0
    excluded = 0
    deduction = 0
    deduction_detail: list[dict[str, Any]] = []

    for f in findings:
        if is_finding_excluded(f, exclude_ai_fp=exclude_ai):
            excluded += 1
            continue
        key = _severity_key(f)
        if key not in by_severity:
            by_severity[key] = 0
        by_severity[key] += 1
        counted += 1

    for sev, count in by_severity.items():
        if count <= 0:
            continue
        weight = int(w.get(sev, 0))
        part = count * weight
        deduction += part
        deduction_detail.append(
            {"severity": sev, "count": count, "weight": weight, "deduction": part}
        )

    score = max(0, MAX_SCORE - deduction)
    critical_count = int(by_severity.get(Severity.CRITICAL.value, 0))

    return {
        "score": score,
        "max_score": MAX_SCORE,
        "by_severity": by_severity,
        "counted_findings": counted,
        "excluded_findings": excluded,
        "weights": dict(w),
        "has_critical": critical_count > 0,
        "deduction": deduction,
        "deduction_detail": deduction_detail,
        "exclude_ai_fp": exclude_ai,
    }


def breakdown_to_json(result: dict[str, Any]) -> str:
    payload = {
        "by_severity": result.get("by_severity") or {},
        "counted_findings": result.get("counted_findings", 0),
        "excluded_findings": result.get("excluded_findings", 0),
        "weights": result.get("weights") or {},
        "has_critical": bool(result.get("has_critical")),
        "deduction": result.get("deduction", 0),
        "deduction_detail": result.get("deduction_detail") or [],
        "exclude_ai_fp": bool(result.get("exclude_ai_fp", True)),
        "max_score": result.get("max_score", MAX_SCORE),
    }
    return json.dumps(payload, ensure_ascii=False)


async def score_scan(session: AsyncSession, scan_id: int) -> dict[str, Any] | None:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return None
    findings = (
        await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    ).scalars().all()
    computed = compute_score(findings)
    return {
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status.value if isinstance(scan.status, ScanStatus) else str(scan.status),
        "completed_at": dt_iso(scan.completed_at),
        "branch": scan.branch,
        "source_url": scan.source_url,
        **computed,
    }


async def apply_score_fields(session: AsyncSession, scan_id: int) -> dict[str, Any] | None:
    """Compute score and set ScanTask cache fields without committing."""
    result = await score_scan(session, scan_id)
    if result is None:
        return None
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return None
    scan.security_score = int(result["score"])
    scan.score_breakdown_json = breakdown_to_json(result)
    return result


async def persist_scan_score(session: AsyncSession, scan_id: int) -> dict[str, Any] | None:
    result = await apply_score_fields(session, scan_id)
    if result is None:
        return None
    await session.commit()
    scan = await session.get(ScanTask, scan_id)
    if scan:
        await session.refresh(scan)
    return result


def _score_out_from_cache(scan: ScanTask) -> dict[str, Any] | None:
    if scan.security_score is None or not (scan.score_breakdown_json or "").strip():
        return None
    try:
        payload = json.loads(scan.score_breakdown_json or "{}")
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return {
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status.value if isinstance(scan.status, ScanStatus) else str(scan.status),
        "completed_at": dt_iso(scan.completed_at),
        "branch": scan.branch,
        "source_url": scan.source_url,
        "score": int(scan.security_score),
        "max_score": int(payload.get("max_score", MAX_SCORE)),
        "by_severity": payload.get("by_severity") or {},
        "counted_findings": int(payload.get("counted_findings", 0)),
        "excluded_findings": int(payload.get("excluded_findings", 0)),
        "weights": payload.get("weights") or get_score_weights(),
        "has_critical": bool(payload.get("has_critical")),
        "deduction": int(payload.get("deduction", 0)),
        "deduction_detail": payload.get("deduction_detail") or [],
        "exclude_ai_fp": bool(payload.get("exclude_ai_fp", True)),
    }


async def get_or_compute_scan_score(
    session: AsyncSession,
    scan_id: int,
    *,
    refresh: bool = False,
) -> dict[str, Any] | None:
    """Prefer cached ScanTask score; recompute+persist when missing or refresh=True."""
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return None
    if not refresh:
        cached = _score_out_from_cache(scan)
        if cached is not None:
            return cached
    return await persist_scan_score(session, scan_id)


async def recalculate_all_cached_scores(session: AsyncSession, *, commit: bool = True) -> int:
    """Recompute security_score for all scans using current weights (one findings query)."""
    from collections import defaultdict
    from types import SimpleNamespace

    weights = get_score_weights()
    exclude_ai = score_exclude_ai_fp()
    scans = (await session.execute(select(ScanTask))).scalars().all()
    if not scans:
        return 0

    rows = (
        await session.execute(
            select(
                Finding.scan_id,
                Finding.severity,
                Finding.review_status,
                Finding.ai_verdict,
            )
        )
    ).all()
    by_scan: dict[int, list[Any]] = defaultdict(list)
    for scan_id, severity, review_status, ai_verdict in rows:
        by_scan[int(scan_id)].append(
            SimpleNamespace(
                severity=severity,
                review_status=review_status,
                ai_verdict=ai_verdict,
            )
        )

    for scan in scans:
        computed = compute_score(by_scan.get(scan.id, []), weights, exclude_ai_fp=exclude_ai)
        scan.security_score = int(computed["score"])
        scan.score_breakdown_json = breakdown_to_json(computed)

    if commit:
        await session.commit()
    return len(scans)