"""Derive human-readable scan coverage from scanner_summary JSON."""

from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.services.llm_audit_coverage import FOCUS_TO_OWASP, build_llm_audit_coverage
from app.services.owasp_classifier import INJECTION_SUBTYPES, OWASP_TOP10, VULN_SUBTYPE_LABELS

SAST_SCANNERS = frozenset({"semgrep", "codeql"})
SECRETS_SCANNERS = frozenset({"gitleaks"})
SCA_SCANNERS = frozenset({"npm_audit", "pip_audit", "dep_exploit"})
PYTHON_SCANNERS = frozenset({"bandit"})

# Capabilities judged by Semgrep rule inventory counts (实锤)
RULE_EVIDENCE_CAPABILITIES = frozenset(
    list(INJECTION_SUBTYPES) + ["path_traversal", "ssrf", "hardcoded_secret", "deserialization"]
)

OWASP_ORDER = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]

# Tool-side OWASP fallback when no inventory (CodeQL / SCA still tool-level)
OWASP_TOOL_RULES: dict[str, frozenset[str]] = {
    "A01": SAST_SCANNERS,
    "A02": SAST_SCANNERS | SECRETS_SCANNERS,
    "A03": SAST_SCANNERS,
    "A04": frozenset(),
    "A05": SAST_SCANNERS,
    "A06": SCA_SCANNERS,
    "A07": SAST_SCANNERS,
    "A08": SAST_SCANNERS,
    "A09": SAST_SCANNERS,
    "A10": SAST_SCANNERS,
}

OWASP_PARTIAL_NOTE: dict[str, str] = {
    "A07": "SAST 规则对认证类漏洞覆盖有限",
    "A09": "SAST 规则对日志/监控类覆盖有限",
    "A04": "不安全设计主要靠 LLM 业务逻辑审计",
}

LIST_CAPABILITY_IDS = (
    "sql_injection",
    "xss",
    "command_injection",
    "secrets",
    "vulnerable_dependency",
)

SCANNER_DISPLAY_NAMES: dict[str, str] = {
    "semgrep": "Semgrep",
    "codeql": "CodeQL",
    "bandit": "Bandit",
    "gitleaks": "Gitleaks",
    "npm_audit": "npm audit",
    "pip_audit": "pip audit",
    "dep_exploit": "依赖漏洞",
}


def _parse_scanner_runs(scanner_summary: str | None) -> list[dict[str, Any]]:
    if not scanner_summary or scanner_summary.strip() in ("", "[]", "{}"):
        return []
    try:
        parsed = json.loads(scanner_summary)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, dict):
        runs = parsed.get("scanners")
        return runs if isinstance(runs, list) else []
    if isinstance(parsed, list):
        return parsed
    return []


def _scanner_status(entry: dict[str, Any]) -> str:
    # Prefer error over skipped when both are present.
    if entry.get("error"):
        return "failed"
    if entry.get("skipped"):
        return "skipped"
    return "ran"


def _slim_scanner_detail(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop heavy / duplicated fields already exposed as semgrep_rule_evidence."""
    if not detail:
        return None
    slim = {
        k: v
        for k, v in detail.items()
        if k not in ("rule_inventory", "shards")
    }
    return slim or None


def _scanner_reason(entry: dict[str, Any]) -> str | None:
    if entry.get("error"):
        return str(entry["error"])
    if entry.get("skipped") and entry.get("skip_reason"):
        return str(entry["skip_reason"])
    return None


def _ran_scanners(runs: list[dict[str, Any]]) -> set[str]:
    return {str(r.get("scanner") or "") for r in runs if _scanner_status(r) == "ran"}


def _semgrep_entry(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in runs:
        if str(entry.get("scanner") or "") == "semgrep":
            return entry
    return None


def _semgrep_configs(runs: list[dict[str, Any]]) -> list[str]:
    entry = _semgrep_entry(runs)
    if not entry:
        return []
    detail = entry.get("detail") or {}
    if isinstance(detail, dict):
        configs = detail.get("configs")
        if isinstance(configs, list) and configs:
            return [str(c) for c in configs]
    return []


def _extract_rule_inventory(
    runs: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return persisted Semgrep rule_inventory from scanner_summary detail, if any."""
    entry = _semgrep_entry(runs)
    if not entry:
        return None
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else None
    if not detail:
        return None
    inv = detail.get("rule_inventory")
    if isinstance(inv, dict) and (
        int(inv.get("total_rules") or 0) > 0 or inv.get("inventory_error") or inv.get("source")
    ):
        return inv
    return inv if isinstance(inv, dict) else None


def ensure_rule_inventory_persisted(scanner_summary: str | None) -> tuple[str | None, bool]:
    """Backfill or re-filter Semgrep rule_inventory in scanner_summary JSON.

    Used by detail endpoints so historical scans get language-filtered evidence
    without bloating list APIs.
    """
    runs = _parse_scanner_runs(scanner_summary)
    if not runs:
        return scanner_summary, False
    entry = _semgrep_entry(runs)
    if not entry or _scanner_status(entry) != "ran":
        return scanner_summary, False
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else None
    if not isinstance(detail, dict):
        return scanner_summary, False

    configs = detail.get("configs")
    if not isinstance(configs, list) or not configs:
        return scanner_summary, False

    from app.services.semgrep_rule_inventory import (
        build_rule_inventory_summary,
        languages_from_configs,
        languages_from_source_counts,
    )

    source_counts = detail.get("source_counts") if isinstance(detail.get("source_counts"), dict) else None
    project_languages = languages_from_source_counts(source_counts)
    if not project_languages:
        project_languages = languages_from_configs([str(c) for c in configs])

    inv = detail.get("rule_inventory")
    has_usable_inv = isinstance(inv, dict) and (
        int(inv.get("total_rules") or 0) > 0 or inv.get("inventory_error") or inv.get("source")
    )
    already_filtered = bool(isinstance(inv, dict) and inv.get("filtered"))
    # Skip when inventory exists and either already filtered, or we cannot derive languages.
    if has_usable_inv and (already_filtered or not project_languages):
        return scanner_summary, False

    try:
        backfilled = build_rule_inventory_summary(
            [str(c) for c in configs],
            project_languages=project_languages or None,
        )
        if not has_usable_inv:
            backfilled["source"] = f"backfill:{backfilled.get('source') or 'unknown'}"
        detail["rule_inventory"] = backfilled
        if source_counts is None and project_languages:
            # Persist inferred counts keys for later detail loads when missing.
            detail["source_counts"] = {
                cfg: 1
                for cfg in configs
                if str(cfg) in (
                    "p/python",
                    "p/javascript",
                    "p/typescript",
                    "p/golang",
                    "p/java",
                    "p/kotlin",
                    "p/php",
                    "p/ruby",
                    "p/csharp",
                    "p/rust",
                )
            }
        return json.dumps(runs, ensure_ascii=False), True
    except Exception as exc:
        detail["rule_inventory"] = {
            "source": "backfill_error",
            "configs": [str(c) for c in configs],
            "total_rules": 0,
            "by_subtype": {},
            "by_owasp": {},
            "sample_rules_by_subtype": {},
            "sample_rules_by_owasp": {},
            "inventory_error": f"历史扫描规则清单回填失败: {exc}"[:500],
            "resolved_at": None,
            "project_languages": sorted(project_languages),
            "filtered": bool(project_languages),
            "unfiltered_total_rules": 0,
        }
        return json.dumps(runs, ensure_ascii=False), True


def _evidence_from_inventory(inv: dict[str, Any] | None) -> dict[str, Any] | None:
    if not inv:
        return None
    return {
        "source": inv.get("source"),
        "configs": list(inv.get("configs") or []),
        "total_rules": int(inv.get("total_rules") or 0),
        "by_subtype": dict(inv.get("by_subtype") or {}),
        "by_owasp": dict(inv.get("by_owasp") or {}),
        "sample_rules_by_subtype": dict(inv.get("sample_rules_by_subtype") or {}),
        "sample_rules_by_owasp": dict(inv.get("sample_rules_by_owasp") or {}),
        "inventory_error": inv.get("inventory_error"),
        "resolved_at": inv.get("resolved_at"),
        "project_languages": list(inv.get("project_languages") or []),
        "filtered": bool(inv.get("filtered")),
        "unfiltered_total_rules": (
            int(inv["unfiltered_total_rules"])
            if inv.get("unfiltered_total_rules") is not None
            else None
        ),
    }


def _build_owasp_categories(
    ran: set[str],
    run_by_id: dict[str, dict[str, Any]],
    llm_audited_focus: set[str],
    by_owasp: dict[str, int],
    has_inventory: bool,
    inventory_error: str | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    semgrep_ran = "semgrep" in ran
    codeql_ran = "codeql" in ran
    partial_inventory = bool(has_inventory and inventory_error)

    for owasp_id in OWASP_ORDER:
        label = OWASP_TOP10.get(owasp_id, owasp_id)
        required = OWASP_TOOL_RULES.get(owasp_id, SAST_SCANNERS)
        tool_sources = sorted(ran & required)

        llm_sources: list[str] = []
        for focus_id, mapped_owasp in FOCUS_TO_OWASP.items():
            if mapped_owasp == owasp_id and focus_id in llm_audited_focus:
                llm_sources.append(f"llm:{focus_id}")

        rule_count = int(by_owasp.get(owasp_id) or 0)

        if owasp_id == "A04":
            if "business_logic" in llm_audited_focus:
                status = "checked"
                note = "LLM 业务逻辑审计"
                sources = llm_sources
            else:
                status = "not_checked"
                note = OWASP_PARTIAL_NOTE.get("A04")
                sources = []
        elif owasp_id == "A06":
            # SCA: still tool-level
            if tool_sources:
                status = "checked"
                note = "依赖漏洞扫描（工具级）"
                sources = tool_sources
            else:
                status = "not_checked"
                sources = []
                note = None
        elif has_inventory and semgrep_ran:
            # 实锤：规则清单 by_owasp 计数
            if rule_count > 0:
                status = "checked" if owasp_id not in ("A07", "A09") else "partial"
                if partial_inventory and status == "checked":
                    status = "partial"
                note = f"Semgrep 规则清单 {rule_count} 条"
                if partial_inventory:
                    note = f"{note} · 部分规则包未解析"
                if owasp_id in OWASP_PARTIAL_NOTE and status == "partial":
                    note = f"{note} · {OWASP_PARTIAL_NOTE[owasp_id]}"
                sources = ["semgrep"] + ([s for s in llm_sources])
                if codeql_ran:
                    sources = list(dict.fromkeys(sources + ["codeql"]))
                    note = f"{note}；CodeQL 为工具级"
            elif codeql_ran:
                status = "partial"
                note = "Semgrep 规则清单无此类规则；CodeQL 已执行（工具级，非规则清单）"
                sources = ["codeql"] + llm_sources
            elif llm_sources:
                status = "checked"
                note = "LLM 端点审计覆盖"
                sources = llm_sources
            else:
                status = "not_checked"
                note = "规则清单中无此类规则" + (f"；{inventory_error}" if inventory_error else "")
                sources = []
        elif semgrep_ran and not has_inventory:
            # No inventory: must NOT claim checked for SAST OWASP
            if codeql_ran:
                status = "partial"
                note = "Semgrep 已执行但规则清单不可用；CodeQL 工具级"
                sources = ["codeql"]
            else:
                status = "not_checked"
                note = inventory_error or "Semgrep 已执行但规则清单不可用，无法实锤覆盖"
                sources = []
            if llm_sources:
                status = "checked"
                note = "LLM 端点审计覆盖"
                sources = llm_sources
        elif codeql_ran and owasp_id in ("A01", "A03", "A05", "A07", "A08", "A09", "A10", "A02"):
            status = "partial"
            note = "CodeQL 已执行（工具级，非规则清单）"
            sources = ["codeql"] + llm_sources
        elif llm_sources:
            status = "checked"
            note = "LLM 端点审计覆盖"
            sources = llm_sources
        else:
            status = "not_checked"
            reasons = [
                _scanner_reason(run_by_id[sid])
                for sid in required
                if sid in run_by_id and _scanner_status(run_by_id[sid]) != "ran"
            ]
            note = reasons[0] if reasons else OWASP_PARTIAL_NOTE.get(owasp_id)
            sources = []

        # A02: gitleaks alone can check secrets side
        if owasp_id == "A02" and "gitleaks" in ran and status == "not_checked":
            status = "partial"
            sources = list(dict.fromkeys(["gitleaks"] + sources))
            note = (note or "") + (" · " if note else "") + "Gitleaks 密钥扫描（工具级）"

        out.append({
            "id": owasp_id,
            "label": label,
            "status": status,
            "sources": sources,
            "note": note,
            "rule_count": rule_count if has_inventory else None,
        })
    return out


def build_scan_coverage(
    scanner_summary: str | None,
    enabled_scanners: list[str] | None = None,
    *,
    scan_status: str | None = None,
    llm_audit_meta: dict[str, Any] | None = None,
    configured_llm_focus: list[str] | None = None,
    compact: bool = False,
) -> dict[str, Any]:
    """Build structured scan coverage from scanner_summary and optional LLM meta.

    When ``compact=True`` (list APIs), drop sample rule ids and heavy scanner detail.
    """
    enabled = enabled_scanners if enabled_scanners is not None else list(settings.enabled_scanners)
    enabled_set = set(enabled)
    runs = _parse_scanner_runs(scanner_summary)
    run_by_id = {str(r.get("scanner") or ""): r for r in runs}
    ran = _ran_scanners(runs)
    semgrep_configs = _semgrep_configs(runs)
    inventory = _extract_rule_inventory(runs)
    evidence = _evidence_from_inventory(inventory)
    by_subtype = dict((evidence or {}).get("by_subtype") or {})
    by_owasp = dict((evidence or {}).get("by_owasp") or {})
    has_inventory = bool(evidence and int(evidence.get("total_rules") or 0) > 0)
    inventory_error = (evidence or {}).get("inventory_error") if evidence else None
    # Semgrep ran but inventory missing/empty → treat as no evidence
    if "semgrep" in ran and not has_inventory and not evidence:
        inventory_error = inventory_error or "规则清单不可用"
    elif "semgrep" in ran and evidence and not has_inventory:
        inventory_error = inventory_error or "规则清单为空或解析失败"
    partial_inventory = bool(has_inventory and inventory_error)

    scanners_out: list[dict[str, Any]] = []
    for scanner_id in enabled:
        entry = run_by_id.get(scanner_id)
        if entry is None:
            scanners_out.append({
                "id": scanner_id,
                "name": SCANNER_DISPLAY_NAMES.get(scanner_id, scanner_id),
                "status": "not_run",
                "findings": 0,
                "reason": None,
                "version": None,
                "detail": None,
            })
            continue
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else None
        scanners_out.append({
            "id": scanner_id,
            "name": SCANNER_DISPLAY_NAMES.get(scanner_id, scanner_id),
            "status": _scanner_status(entry),
            "findings": int(entry.get("findings") or 0),
            "reason": _scanner_reason(entry),
            "version": entry.get("version"),
            "detail": None if compact else _slim_scanner_detail(detail),
        })

    for entry in runs:
        scanner_id = str(entry.get("scanner") or "")
        if scanner_id and scanner_id not in enabled_set:
            detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else None
            scanners_out.append({
                "id": scanner_id,
                "name": SCANNER_DISPLAY_NAMES.get(scanner_id, scanner_id),
                "status": _scanner_status(entry),
                "findings": int(entry.get("findings") or 0),
                "reason": _scanner_reason(entry),
                "version": entry.get("version"),
                "detail": None if compact else _slim_scanner_detail(detail),
            })

    sast_ok = bool(ran & SAST_SCANNERS)
    capabilities_out: list[dict[str, Any]] = []

    def add_tool_capability(cap_id: str, *, required: set[str], label: str | None = None) -> None:
        sources = sorted(ran & required)
        status = "checked" if sources else "not_checked"
        reasons = [
            _scanner_reason(run_by_id[sid])
            for sid in required
            if sid in run_by_id and _scanner_status(run_by_id[sid]) != "ran"
        ]
        note = None
        if cap_id == "secrets" and sources:
            note = "Gitleaks 密钥扫描"
        elif cap_id == "vulnerable_dependency" and sources:
            note = "依赖漏洞扫描（npm/pip/OSV）"
        elif cap_id == "python_security" and sources:
            note = "Bandit Python 安全规则"
        if not sources and reasons:
            note = reasons[0]
        capabilities_out.append({
            "id": cap_id,
            "label": label or VULN_SUBTYPE_LABELS.get(cap_id, cap_id),
            "status": status,
            "sources": sources,
            "note": note,
            "rule_count": None,
        })

    def add_rule_capability(cap_id: str, *, label: str | None = None) -> None:
        """Coverage by Semgrep rule inventory counts (实锤)."""
        count = int(by_subtype.get(cap_id) or 0)
        samples = ((evidence or {}).get("sample_rules_by_subtype") or {}).get(cap_id) or []
        codeql_ran = "codeql" in ran
        semgrep_ran = "semgrep" in ran

        if has_inventory and count > 0:
            status = "partial" if partial_inventory else "checked"
            sources = ["semgrep"]
            note = f"规则清单 {count} 条"
            if partial_inventory:
                note += " · 部分规则包未解析"
            if samples and not compact:
                note += f"；样例 {samples[0]}"
            if codeql_ran:
                note += "；CodeQL 工具级补充"
        elif has_inventory and semgrep_ran and count == 0:
            if codeql_ran:
                status = "partial"
                sources = ["codeql"]
                note = "Semgrep 规则清单无此类规则；CodeQL 已执行（工具级）"
            else:
                status = "not_checked"
                sources = []
                note = "规则清单中无此类规则"
        elif semgrep_ran and not has_inventory:
            status = "not_checked"
            sources = []
            note = inventory_error or "规则清单不可用，无法实锤覆盖"
            if codeql_ran:
                status = "partial"
                sources = ["codeql"]
                note = "规则清单不可用；CodeQL 已执行（工具级）"
        elif codeql_ran:
            status = "partial"
            sources = ["codeql"]
            note = "CodeQL 已执行（工具级，非规则清单）"
        else:
            status = "not_checked"
            sources = []
            note = _scanner_reason(run_by_id["semgrep"]) if "semgrep" in run_by_id else None

        capabilities_out.append({
            "id": cap_id,
            "label": label or VULN_SUBTYPE_LABELS.get(cap_id, cap_id),
            "status": status,
            "sources": sources,
            "note": note,
            "rule_count": count if has_inventory else None,
        })

    for cap_id in INJECTION_SUBTYPES:
        add_rule_capability(cap_id)

    add_rule_capability("path_traversal", label=VULN_SUBTYPE_LABELS["path_traversal"])
    add_rule_capability("ssrf", label=VULN_SUBTYPE_LABELS["ssrf"])
    add_rule_capability("hardcoded_secret", label=VULN_SUBTYPE_LABELS["hardcoded_secret"])
    add_rule_capability(
        "deserialization",
        label=VULN_SUBTYPE_LABELS.get("deserialization", "不安全反序列化"),
    )
    # hardcoded_secret: also allow gitleaks
    for cap in capabilities_out:
        if cap["id"] == "hardcoded_secret" and "gitleaks" in ran and cap["status"] == "not_checked":
            cap["status"] = "partial"
            cap["sources"] = list(dict.fromkeys(["gitleaks"] + (cap.get("sources") or [])))
            cap["note"] = (cap.get("note") or "") + " · Gitleaks（工具级）"

    add_tool_capability("secrets", required=SECRETS_SCANNERS, label="密钥泄露")
    add_tool_capability(
        "vulnerable_dependency",
        required=SCA_SCANNERS,
        label=VULN_SUBTYPE_LABELS["vulnerable_dependency"],
    )
    add_tool_capability("python_security", required=PYTHON_SCANNERS, label="Python 安全")

    llm_cov = build_llm_audit_coverage(
        scan_status=scan_status,
        llm_audit_meta=llm_audit_meta,
        configured_focus=configured_llm_focus,
    )
    audited_focus_set = {str(x) for x in (llm_cov.get("audited_focus") or [])}

    owasp_categories = _build_owasp_categories(
        ran,
        run_by_id,
        audited_focus_set,
        by_owasp,
        has_inventory,
        inventory_error,
    )

    if evidence and compact:
        evidence = {
            **evidence,
            "sample_rules_by_subtype": {},
            "sample_rules_by_owasp": {},
        }

    return {
        "scanners": scanners_out,
        "capabilities": capabilities_out,
        "semgrep_configs": semgrep_configs,
        "sast_checked": sast_ok,
        "owasp_categories": owasp_categories,
        "llm_audit": {
            "ran": llm_cov["ran"],
            "status": llm_cov["status"],
            "focus_areas": llm_cov["focus_areas"],
        },
        "semgrep_rule_evidence": evidence,
    }
