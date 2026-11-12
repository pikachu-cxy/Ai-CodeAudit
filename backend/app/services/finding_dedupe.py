"""Two-pass finding dedupe: same-tool fingerprint, then cross-tool location merge."""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from app.models import FindingCategory, Severity
from app.services.owasp_classifier import classify_finding
from app.services.sast_flow_service import parse_finding_metadata
from app.services.scan_diff_service import (
    _near_line,
    _normalize_path,
    finding_fingerprint,
)

logger = logging.getLogger(__name__)

CROSS_TOOL_SCANNERS = frozenset({
    "semgrep",
    "codeql",
    "bandit",
    "gitleaks",
    "npm_audit",
    "pip_audit",
    "dep_exploit",
})

_TOOL_PRIORITY = {
    "codeql": 0,
    "semgrep": 1,
    "bandit": 2,
    "gitleaks": 3,
    "npm_audit": 4,
    "pip_audit": 5,
    "dep_exploit": 6,
}

_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

_HIGH_SEV = frozenset({"CRITICAL", "HIGH"})


def _severity_str(finding: dict) -> str:
    raw = finding.get("severity", "UNKNOWN")
    if isinstance(raw, Severity):
        return raw.value
    return str(raw or "UNKNOWN").upper()


def _tool_str(finding: dict) -> str:
    return str(finding.get("tool") or "semgrep").lower().strip()


def _enrich_classification(finding: dict) -> dict:
    """Copy finding and fill owasp/subtype via classifier when missing."""
    item = dict(finding)
    if item.get("owasp_id") and item.get("vuln_subtype"):
        return item
    cat = item.get("category", FindingCategory.SAST.value)
    if isinstance(cat, FindingCategory):
        cat = cat.value
    classification = classify_finding(
        rule_id=item.get("rule_id", "") or "",
        message=item.get("message", "") or "",
        metadata_json=item.get("metadata_json"),
        tool=item.get("tool", "semgrep") or "semgrep",
        category=cat,
    )
    if not item.get("owasp_id"):
        item["owasp_id"] = classification.get("owasp_id") or ""
    if not item.get("vuln_subtype"):
        item["vuln_subtype"] = classification.get("vuln_subtype") or ""
    if not item.get("owasp_name"):
        item["owasp_name"] = classification.get("owasp_name") or ""
    if not item.get("vuln_subtype_name"):
        item["vuln_subtype_name"] = classification.get("vuln_subtype_name") or ""
    return item


def cross_tool_fingerprint(finding: dict) -> str:
    """Location + classification key (no tool / rule_id)."""
    path = _normalize_path(finding.get("file_path") or "")
    line = _near_line(finding.get("line_start") or 0)
    owasp = str(finding.get("owasp_id") or "").upper()
    subtype = str(finding.get("vuln_subtype") or "").lower()
    return f"{path}|{line}|{owasp}|{subtype}"


def _canonical_rank(finding: dict) -> tuple:
    """Lower tuple = better canonical candidate."""
    sev = _severity_str(finding)
    tool = _tool_str(finding)
    return (
        _SEVERITY_RANK.get(sev, 99),
        _TOOL_PRIORITY.get(tool, 50),
    )


def _pick_canonical(group: list[dict]) -> dict:
    return min(group, key=_canonical_rank)


def _attach_merged_sources(canonical: dict, others: list[dict]) -> dict:
    """Write sources / merged_from into metadata_json on the kept finding."""
    item = dict(canonical)
    meta = parse_finding_metadata(item.get("metadata_json"))
    sources = set(meta.get("sources") or [])
    sources.add(_tool_str(item))
    merged_from = list(meta.get("merged_from") or [])
    for other in others:
        sources.add(_tool_str(other))
        merged_from.append({
            "tool": other.get("tool"),
            "rule_id": other.get("rule_id"),
            "severity": _severity_str(other),
            "message": (other.get("message") or "")[:120],
        })
    meta["sources"] = sorted(s for s in sources if s)
    meta["merged_from"] = merged_from
    item["metadata_json"] = json.dumps(meta, ensure_ascii=False)
    return item


def _dedupe_same_tool(items: list[dict]) -> tuple[list[dict], int]:
    best: dict[str, dict] = {}
    order: list[str] = []
    skipped = 0
    for item in items:
        fp = finding_fingerprint(item)
        if fp not in best:
            best[fp] = item
            order.append(fp)
            continue
        skipped += 1
        if _canonical_rank(item) < _canonical_rank(best[fp]):
            best[fp] = item
    return [best[fp] for fp in order], skipped


def _classification_is_generic(finding: dict) -> bool:
    owasp = str(finding.get("owasp_id") or "").upper()
    subtype = str(finding.get("vuln_subtype") or "").lower()
    return (not owasp and not subtype) or (owasp == "A04" and subtype in ("", "other"))


def _dedupe_cross_tool(items: list[dict]) -> tuple[list[dict], int]:
    enriched = [_enrich_classification(item) for item in items]
    buckets: dict[str, list[dict]] = defaultdict(list)
    passthrough: list[dict] = []

    for item in enriched:
        tool = _tool_str(item)
        if tool not in CROSS_TOOL_SCANNERS:
            passthrough.append(item)
            continue
        buckets[cross_tool_fingerprint(item)].append(item)

    kept: list[dict] = list(passthrough)
    skipped = 0

    for group in buckets.values():
        tools = {_tool_str(f) for f in group}
        if len(group) == 1 or len(tools) < 2:
            kept.extend(group)
            continue

        if all(_classification_is_generic(f) for f in group):
            if not any(_severity_str(f) in _HIGH_SEV for f in group):
                kept.extend(group)
                continue

        canonical = _pick_canonical(group)
        idx = group.index(canonical)
        others = group[:idx] + group[idx + 1 :]
        kept.append(_attach_merged_sources(canonical, others))
        skipped += len(others)

    return kept, skipped


def dedupe_sast_findings(
    items: list[dict],
) -> tuple[list[dict], int, int]:
    """
    Two-pass SAST dedupe.

    Returns (kept, skipped_same_tool, skipped_cross_tool).
    """
    if not items:
        return [], 0, 0

    after_same, skipped_same = _dedupe_same_tool(items)
    after_cross, skipped_cross = _dedupe_cross_tool(after_same)

    if skipped_same or skipped_cross:
        logger.info(
            "SAST findings deduped: %s -> %s (same_tool=%s, cross_tool=%s)",
            len(items),
            len(after_cross),
            skipped_same,
            skipped_cross,
        )
    return after_cross, skipped_same, skipped_cross
