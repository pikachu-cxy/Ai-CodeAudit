"""Compare findings between two scan runs using stable fingerprints."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, ScanTask
from app.schemas import FindingOut, ScanDiffFindingItem, ScanDiffSummary


_WS_RE = re.compile(r"\s+")
_NEAR_LINE_BUCKET = 20
_UPLOAD_PREFIX_RE = re.compile(
    r"(^|.*/)"
    r"(?:(?:backend/)?data/)?uploads/"
    r"[^/]+/"      # scan run id
    r"[^/]+/"      # extracted archive root dir/version dir
    r"(?P<tail>.+)$",
    re.IGNORECASE,
)
_REPOS_PREFIX_RE = re.compile(
    r"(^|.*/)"
    r"(?:(?:backend/)?data/)?repos/"
    r"[^/]+/"
    r"(?P<tail>.+)$",
    re.IGNORECASE,
)


def _normalize_path(path: str | None) -> str:
    text = (path or "").replace("\\", "/").strip().lower()
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    text = text.lstrip("/")
    m = _UPLOAD_PREFIX_RE.match(text)
    if m:
        # Keep source-relative tail stable across different upload run ids.
        return m.group("tail").lstrip("/")
    m = _REPOS_PREFIX_RE.match(text)
    if m:
        return m.group("tail").lstrip("/")
    return text


def _normalize_message(msg: str | None) -> str:
    return _WS_RE.sub(" ", (msg or "").strip().lower())[:240]


def _near_line(line: int | None) -> int:
    n = int(line or 0)
    if n <= 0:
        return 0
    return (n // _NEAR_LINE_BUCKET) * _NEAR_LINE_BUCKET


def finding_fingerprint(finding: Finding | dict) -> str:
    if isinstance(finding, dict):
        tool = finding.get("tool") or "semgrep"
        rule_id = finding.get("rule_id") or ""
        path = finding.get("file_path") or ""
        message = finding.get("message_zh") or finding.get("message") or ""
        line = finding.get("line_start") or 0
        owasp = finding.get("owasp_id") or ""
        subtype = finding.get("vuln_subtype") or ""
    else:
        tool = finding.tool or "semgrep"
        rule_id = finding.rule_id or ""
        path = finding.file_path or ""
        message = finding.message_zh or finding.message or ""
        line = finding.line_start or 0
        owasp = finding.owasp_id or ""
        subtype = finding.vuln_subtype or ""

    parts = [
        str(tool).lower().strip(),
        str(rule_id).strip().lower(),
        _normalize_path(path),
        _normalize_message(message),
        str(_near_line(line)),
        str(owasp or "").upper(),
        str(subtype or "").lower(),
    ]
    return "|".join(parts)


def _finding_out(f: Finding) -> FindingOut:
    return FindingOut.model_validate(f)


async def compare_scans(
    session: AsyncSession,
    scan_id: int,
    baseline_scan_id: int | None = None,
) -> ScanDiffSummary:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("scan not found")

    baseline_id = baseline_scan_id
    if baseline_id is None:
        baseline_id = scan.parent_scan_id
    if baseline_id is None and scan.project_id is not None:
        prev = (
            await session.execute(
                select(ScanTask)
                .where(
                    ScanTask.project_id == scan.project_id,
                    ScanTask.id != scan.id,
                    ScanTask.created_at < (scan.created_at or scan.updated_at),
                )
                .order_by(ScanTask.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if prev:
            baseline_id = prev.id

    if baseline_id is None:
        raise ValueError("baseline scan not found")

    baseline = await session.get(ScanTask, baseline_id)
    if not baseline:
        raise ValueError("baseline scan not found")
    if scan.project_id and baseline.project_id and scan.project_id != baseline.project_id:
        raise ValueError("baseline scan belongs to a different project")

    current_findings = list(
        (await session.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    )
    baseline_findings = list(
        (await session.execute(select(Finding).where(Finding.scan_id == baseline_id))).scalars().all()
    )

    return build_diff(scan_id, baseline_id, current_findings, baseline_findings)


def _severity_rank(sev) -> int:
    val = getattr(sev, "value", sev) or "UNKNOWN"
    ranks = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
    return ranks.get(str(val).upper(), 0)


def _review_worsened(base_rs: str, cur_rs: str) -> bool:
    return (base_rs, cur_rs) in {
        ("fixed", "confirmed"),
        ("false_positive", "confirmed"),
        ("false_positive", "unreviewed"),
        ("fixed", "unreviewed"),
    }


def build_diff(
    scan_id: int,
    baseline_scan_id: int,
    current_findings: Iterable[Finding],
    baseline_findings: Iterable[Finding],
) -> ScanDiffSummary:
    current_map: dict[str, Finding] = {}
    for f in current_findings:
        current_map.setdefault(finding_fingerprint(f), f)

    baseline_map: dict[str, Finding] = {}
    for f in baseline_findings:
        baseline_map.setdefault(finding_fingerprint(f), f)

    all_fps = set(current_map) | set(baseline_map)
    items: list[ScanDiffFindingItem] = []
    fixed = regressed = new = unchanged = status_changed = 0

    for fp in sorted(all_fps):
        cur = current_map.get(fp)
        base = baseline_map.get(fp)
        if cur and base:
            cur_rs = getattr(cur.review_status, "value", cur.review_status)
            base_rs = getattr(base.review_status, "value", base.review_status)
            if cur_rs != base_rs:
                status_changed += 1
            if _severity_rank(cur.severity) > _severity_rank(base.severity) or _review_worsened(
                str(base_rs), str(cur_rs)
            ):
                status = "regressed"
                regressed += 1
            else:
                status = "unchanged"
                unchanged += 1
        elif cur and not base:
            status = "new"
            new += 1
        else:
            status = "fixed"
            fixed += 1

        items.append(
            ScanDiffFindingItem(
                fingerprint=fp,
                status=status,
                current=_finding_out(cur) if cur else None,
                baseline=_finding_out(base) if base else None,
            )
        )

    return ScanDiffSummary(
        scan_id=scan_id,
        baseline_scan_id=baseline_scan_id,
        fixed_count=fixed,
        regressed_count=regressed,
        new_count=new,
        unchanged_count=unchanged,
        status_changed_count=status_changed,
        items=items,
    )
