from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Finding, Project, RetestVerification, ScanTask, dt_iso
from app.services.llm_audit_service import parse_finding_metadata
from app.services.scanners.common import to_repo_relative_path

TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "templates" / "scan_report.html"
PDF_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "templates" / "scan_report_pdf.html"
PLACEHOLDER = "/*__REPORT_DATA__*/"
STATIC_PLACEHOLDER = "<!--__STATIC_FALLBACK__-->"

_SNIPPET_MAX_LINES = 80
_SNIPPET_MAX_CHARS = 8 * 1024

# 超出该条数时拒绝导出 PDF（WeasyPrint 同步渲染，大文档会耗尽内存）
PDF_MAX_FINDINGS = 2000

_SOURCE_LABEL = {
    "sast": "SAST",
    "llm": "LLM",
}
_OWASP_LABEL = {
    "A01": "A01 访问控制失效",
    "A02": "A02 加密机制失效",
    "A03": "A03 注入",
    "A04": "A04 不安全设计",
    "A05": "A05 安全配置错误",
    "A06": "A06 易受攻击和过时的组件",
    "A07": "A07 身份识别和身份验证失败",
    "A08": "A08 软件和数据完整性失效",
    "A09": "A09 安全日志和监控失效",
    "A10": "A10 服务端请求伪造 (SSRF)",
    "OTHER": "OTHER 未分类",
}
_VERDICT_LABEL = {
    "real_vuln": "真实漏洞",
    "false_positive": "误报",
    "uncertain": "待确认",
    "pending": "待分析",
    "skipped": "已跳过",
}
_REVIEW_LABEL = {
    "unreviewed": "未标记",
    "confirmed": "确认",
    "false_positive": "误报",
    "fixed": "已修复",
}
_RETEST_LABEL = {
    "fixed": "已修复",
    "still_present": "仍然存在",
    "inconclusive": "无法确认",
    "skipped": "已跳过",
}
_EXTERNAL_LABEL = {
    "unreviewed": "未复核",
    "vuln_exists": "确认存在",
    "false_positive": "误报",
    "fixed_claimed": "声称已修复",
}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
_SEVERITY_RANK = {name: idx for idx, name in enumerate(_SEVERITY_ORDER)}

_INCLUDE_DEFAULTS = {
    "snippet": True,
    "poc": False,
    "ai_reason": True,
    "false_positive": True,
    "retest": True,
    "remediation": True,
}

_SORT_KEYS = ("severity", "file", "owasp", "id")
_GROUP_KEYS = ("severity", "owasp", "file", "tool", "none")

_RETEST_CHUNK = 400


def _enum_val(value) -> str:
    if value is None:
        return ""
    return value.value if hasattr(value, "value") else str(value)


def _include_flags(spec) -> dict:
    flags = dict(_INCLUDE_DEFAULTS)
    include = getattr(spec, "include", None)
    if include is not None:
        for key in _INCLUDE_DEFAULTS:
            value = getattr(include, key, None)
            if value is not None:
                flags[key] = bool(value)
    return flags


def _scan_detail_link(scan: ScanTask, project: Project | None, finding_id: int | None = None) -> str:
    from app.config import settings

    base = (settings.frontend_base_url or "").strip().rstrip("/")
    if not base:
        base = f"http://{settings.app_host}:{settings.app_port}"
    params = [f"scanId={scan.id}"]
    if project:
        params.append(f"projectId={project.id}")
    if finding_id is not None:
        params.append(f"findingId={finding_id}")
    return f"{base}/?{'&'.join(params)}"


def _clip_snippet(raw: str | None) -> str:
    text = (raw or "").replace("\x00", "")
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) > _SNIPPET_MAX_LINES:
        text = "\n".join(lines[:_SNIPPET_MAX_LINES]) + "\n…（已截断）"
    if len(text) > _SNIPPET_MAX_CHARS:
        text = text[:_SNIPPET_MAX_CHARS] + "\n…（已截断）"
    return text


def _fmt_dt(value) -> str:
    iso = dt_iso(value)
    if not iso:
        return "-"
    return iso.replace("T", " ").replace("+00:00", " UTC")[:19]


def _safe_filename(text: str) -> str:
    clean = re.sub(r"[^\w\u4e00-\u9fff.-]+", "-", (text or "").strip(), flags=re.UNICODE).strip("-")
    return clean or "scan-report"


def _finding_source(finding: Finding) -> str:
    category = _enum_val(finding.category)
    tool = (finding.tool or "").strip().lower()
    if tool == "llm" or category in {"business_logic", "authorization"}:
        return "llm"
    return "sast"


def _norm_set(values) -> set[str]:
    if not values:
        return set()
    return {str(v).strip().lower() for v in values if str(v).strip()}


def _is_false_positive(finding: Finding) -> bool:
    return (
        _enum_val(finding.review_status) == "false_positive"
        or _enum_val(finding.ai_verdict) == "false_positive"
    )


def _finding_payload(finding: Finding, scan: ScanTask, include: dict, retest: dict | None = None) -> dict:
    title = (finding.message_zh or finding.message or "").strip()
    message = (finding.message_zh or finding.message or "").strip()
    if finding.message_zh and finding.message and finding.message_zh != finding.message:
        message = f"{finding.message_zh}\n\n原文: {finding.message}"

    meta = parse_finding_metadata(finding.metadata_json)
    poc = meta.get("verification_poc") if isinstance(meta.get("verification_poc"), dict) else None
    remediation = meta.get("recommendation") if isinstance(meta.get("recommendation"), str) else ""

    payload = {
        "id": finding.id,
        "severity": _enum_val(finding.severity),
        "category": _enum_val(finding.category),
        "source": _finding_source(finding),
        "tool": finding.tool or "",
        "rule_id": finding.rule_id or "",
        "title": title[:300],
        "message": message,
        "file_path": to_repo_relative_path(finding.file_path, scan.project_path),
        "line_start": finding.line_start or 0,
        "snippet": _clip_snippet(finding.code_snippet) if include["snippet"] else "",
        "ai_verdict": _enum_val(finding.ai_verdict),
        "ai_reason": (finding.ai_reason or "") if include["ai_reason"] else "",
        "ai_confidence": finding.ai_confidence,
        "review_status": _enum_val(finding.review_status),
        "review_note": finding.review_note or "",
        "external_status": _enum_val(finding.external_status),
        "external_note": finding.external_note or "",
        "owasp_id": finding.owasp_id or "OTHER",
        "owasp_name": finding.owasp_name or "",
        "vuln_subtype": finding.vuln_subtype or "",
        "vuln_subtype_name": finding.vuln_subtype_name or "",
    }
    if include["poc"] and poc:
        payload["poc"] = {
            "poc_type": poc.get("poc_type") or "",
            "title": poc.get("title") or "",
            "prerequisites": poc.get("prerequisites") or "",
            "steps": poc.get("steps") or "",
            "poc_content": poc.get("poc_content") or "",
            "expected_result": poc.get("expected_result") or "",
            "safety_note": poc.get("safety_note") or "",
            "generated_at": poc.get("generated_at") or "",
        }
    if include["remediation"] and remediation:
        payload["remediation"] = remediation
    if include["retest"] and retest:
        payload["retest"] = retest
    return payload


def _match_filters(finding: Finding, filters) -> bool:
    if filters is None:
        return True

    severity = _norm_set(filters.severity)
    if severity and _enum_val(finding.severity).lower() not in severity:
        return False

    owasp = _norm_set(filters.owasp)
    if owasp and (finding.owasp_id or "other").lower() not in owasp:
        return False

    source = _norm_set(filters.source)
    if source and _finding_source(finding) not in source:
        return False

    tool = _norm_set(filters.tool)
    if tool and (finding.tool or "").strip().lower() not in tool:
        return False

    category = _norm_set(filters.category)
    if category:
        cat = _enum_val(finding.category).lower()
        # 列表页把 business_logic + authorization 聚合为 llm 分类
        aggregated = cat in {"business_logic", "authorization"} and "llm" in category
        if cat not in category and not aggregated:
            return False

    verdict = _norm_set(filters.ai_verdict)
    if verdict and _enum_val(finding.ai_verdict).lower() not in verdict:
        return False

    review = _norm_set(filters.review_status)
    if review and _enum_val(finding.review_status).lower() not in review:
        return False

    external = _norm_set(getattr(filters, "external_status", None))
    if external and _enum_val(finding.external_status).lower() not in external:
        return False

    subtype = _norm_set(filters.subtype)
    if subtype and (finding.vuln_subtype or "").strip().lower() not in subtype:
        return False

    keyword = (filters.keyword or "").strip().lower()
    if keyword:
        haystack = " ".join(
            [
                finding.message or "",
                finding.message_zh or "",
                finding.rule_id or "",
                finding.file_path or "",
                str(finding.id),
            ]
        ).lower()
        if keyword not in haystack:
            return False

    return True


def _sort_findings(findings: list[Finding], sort_key: str) -> list[Finding]:
    if sort_key == "id":
        return sorted(findings, key=lambda f: f.id)
    if sort_key == "file":
        return sorted(findings, key=lambda f: (f.file_path or "", f.line_start or 0, f.id))
    if sort_key == "owasp":
        return sorted(
            findings,
            key=lambda f: (
                (f.owasp_id or "OTHER"),
                _SEVERITY_RANK.get(_enum_val(f.severity), 99),
                f.id,
            ),
        )
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(_enum_val(f.severity), 99), f.id),
    )


def _stats_from_findings(findings: list[dict], security_score: int | None = None) -> dict:
    """按最终明细重算统计，保证报告头部数字与明细条数完全一致。"""
    by_severity: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_review: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_subtype: dict[str, int] = {}
    by_owasp_subtype: dict[str, dict[str, int]] = {}
    rule_counter: dict[str, int] = {}

    for f in findings:
        sev = str(f.get("severity") or "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        verdict = str(f.get("ai_verdict") or "pending")
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1

        tool = str(f.get("tool") or "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1

        cat = str(f.get("category") or "sast")
        by_category[cat] = by_category.get(cat, 0) + 1

        review = str(f.get("review_status") or "unreviewed")
        by_review[review] = by_review.get(review, 0) + 1

        owasp = str(f.get("owasp_id") or "OTHER")
        by_owasp[owasp] = by_owasp.get(owasp, 0) + 1

        subtype = str(f.get("vuln_subtype") or "other")
        by_subtype[subtype] = by_subtype.get(subtype, 0) + 1
        by_owasp_subtype.setdefault(owasp, {})
        by_owasp_subtype[owasp][subtype] = by_owasp_subtype[owasp].get(subtype, 0) + 1

        rule = str(f.get("rule_id") or "")
        if rule:
            rule_counter[rule] = rule_counter.get(rule, 0) + 1

    by_category["llm"] = by_category.get("business_logic", 0) + by_category.get("authorization", 0)

    top_rules = [
        {"rule_id": rid, "count": cnt}
        for rid, cnt in sorted(rule_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    ]

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_verdict": by_verdict,
        "by_tool": by_tool,
        "by_category": by_category,
        "by_review": by_review,
        "by_owasp": by_owasp,
        "by_subtype": by_subtype,
        "by_owasp_subtype": by_owasp_subtype,
        "top_rules": top_rules,
        "security_score": security_score,
    }


async def _load_retest_map(session: AsyncSession, finding_ids: list[int]) -> dict[int, dict]:
    """取每个漏洞最近一次复测结论。分批查询，避免 IN 子句过长。"""
    if not finding_ids:
        return {}
    out: dict[int, dict] = {}
    for start in range(0, len(finding_ids), _RETEST_CHUNK):
        chunk = finding_ids[start : start + _RETEST_CHUNK]
        rows = (
            await session.execute(
                select(RetestVerification)
                .where(RetestVerification.baseline_finding_id.in_(chunk))
                .order_by(RetestVerification.created_at.desc())
            )
        ).scalars().all()
        for row in rows:
            if row.baseline_finding_id in out:
                continue
            out[row.baseline_finding_id] = {
                "verdict": row.verdict or "",
                "method": row.method or "",
                "scan_id": row.scan_id,
                "created_at": _fmt_dt(row.created_at),
            }
    return out


def _resolve_scope(spec) -> str:
    if spec is None:
        return "all"
    if spec.finding_ids:
        return "selected"
    if spec.filters is not None:
        return "filtered"
    return "all"


def _scope_slug(scope: str, count: int) -> str:
    if scope == "selected":
        return f"selected-{count}"
    if scope == "filtered":
        return f"filtered-{count}"
    return "all"


def _report_title(project_name: str, spec) -> str:
    custom = (getattr(spec, "title", None) or "").strip() if spec is not None else ""
    if custom:
        return custom
    return f"{project_name or '未知项目'} 安全审计报告"


def _group_findings(findings: list[dict], group_by: str) -> list[tuple[str, list[dict]]]:
    """按指定维度分组，组内保持原排序的相对顺序。"""
    if not findings:
        return []
    if group_by == "none":
        return [("", findings)]

    def key_of(f: dict) -> str:
        if group_by == "severity":
            return str(f.get("severity") or "UNKNOWN")
        if group_by == "owasp":
            owasp = str(f.get("owasp_id") or "OTHER")
            return f"{owasp} {f.get('owasp_name') or ''}".strip()
        if group_by == "file":
            return str(f.get("file_path") or "-")
        if group_by == "tool":
            return str(f.get("tool") or "-")
        return ""

    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(key_of(f), []).append(f)

    if group_by == "severity":
        ordered = sorted(groups.items(), key=lambda kv: (_SEVERITY_RANK.get(kv[0], 99), kv[0]))
    else:
        ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return ordered


def _build_markdown_report(payload: dict) -> str:
    meta = payload.get("meta") or {}
    stats = payload.get("stats") or {}
    findings = list(payload.get("findings") or [])
    by_sev = stats.get("by_severity") or {}
    by_src = {"sast": 0, "llm": 0}
    by_owasp = stats.get("by_owasp") or {}
    by_tool = stats.get("by_tool") or {}
    group_by = str(meta.get("group_by") or "none")
    for f in findings:
        src = str(f.get("source") or "sast")
        by_src[src] = by_src.get(src, 0) + 1

    lines: list[str] = []
    # 兼容没有 title 的旧 payload（如历史测试夹具与外部调用方）
    title = meta.get("title") or f"安全审计报告：{meta.get('project_name') or '未知项目'}"
    lines.append(f"# {title}")
    lines.append("")
    lines.append("## 报告概览")
    lines.append(f"- 扫描 ID：{meta.get('scan_id')}")
    lines.append(f"- 扫描名称：{meta.get('scan_name') or '-'}")
    lines.append(f"- 分支：{meta.get('branch') or '-'}")
    lines.append(f"- 版本：{meta.get('version') or '-'}")
    lines.append(f"- 创建时间：{meta.get('created_at') or '-'}")
    lines.append(f"- 完成时间：{meta.get('completed_at') or '-'}")
    lines.append(f"- 报告范围：{meta.get('scope_label') or '全部漏洞'}")
    lines.append(f"- 生成时间：{meta.get('generated_at') or '-'}")
    if meta.get("online_url"):
        lines.append(f"- 在线详情：{meta.get('online_url')}")
    lines.append("")
    lines.append("## 统计摘要")
    lines.append(f"- 总漏洞数：{int(stats.get('total') or 0)}")
    lines.append("- 危害分布：" + "，".join(f"{k}:{int(by_sev.get(k) or 0)}" for k in _SEVERITY_ORDER))
    lines.append(f"- 来源分布：SAST:{int(by_src.get('sast') or 0)}，LLM:{int(by_src.get('llm') or 0)}")
    if by_owasp:
        lines.append("- OWASP 分布：" + "，".join(f"{k}:{int(v)}" for k, v in sorted(by_owasp.items())))
    if by_tool:
        lines.append("- 扫描器分布：" + "，".join(f"{k}:{int(v)}" for k, v in sorted(by_tool.items())))
    lines.append("")
    lines.append("## 漏洞汇总")
    lines.append("")
    lines.append("| ID | 严重级别 | OWASP | 来源 | 规则 | 位置 | 标题 |")
    lines.append("|---|---|---|---|---|---|---|")
    for f in findings:
        loc = str(f.get("file_path") or "")
        line_start = int(f.get("line_start") or 0)
        if line_start:
            loc = f"{loc}:{line_start}"
        lines.append(
            f"| #{f.get('id')} | {f.get('severity') or ''} | "
            f"{f.get('owasp_id') or 'OTHER'} | {str(f.get('source') or '').upper()} | "
            f"{f.get('rule_id') or ''} | {loc} | {str(f.get('title') or '').replace('|', '\\|')} |"
        )
    lines.append("")
    lines.append("## 漏洞详情")
    lines.append("")

    for group_label, group_items in _group_findings(findings, group_by):
        if group_label:
            lines.append(f"### 分组：{group_label}（{len(group_items)} 条）")
            lines.append("")
        for f in group_items:
            lines.append(f"#### #{f.get('id')} {f.get('title') or '未命名问题'}")
            lines.append(f"- 严重级别：{f.get('severity') or '-'}")
            lines.append(f"- OWASP：{f.get('owasp_id') or 'OTHER'} {f.get('owasp_name') or ''}".strip())
            if f.get("vuln_subtype_name") or f.get("vuln_subtype"):
                lines.append(f"- 漏洞子类型：{f.get('vuln_subtype_name') or f.get('vuln_subtype')}")
            lines.append(f"- 来源：{str(f.get('source') or '').upper()} / {f.get('tool') or '-'}")
            lines.append(f"- 规则 ID：{f.get('rule_id') or '-'}")
            lines.append(f"- 位置：{f.get('file_path') or '-'}:{int(f.get('line_start') or 0)}")
            lines.append(f"- AI 判定：{_VERDICT_LABEL.get(str(f.get('ai_verdict') or ''), f.get('ai_verdict') or '-')}")
            lines.append(f"- 人工标记：{_REVIEW_LABEL.get(str(f.get('review_status') or ''), f.get('review_status') or '-')}")
            if f.get("external_status"):
                lines.append(
                    f"- 外部复核：{_EXTERNAL_LABEL.get(str(f.get('external_status') or ''), f.get('external_status') or '-')}"
                )
            if f.get("retest"):
                rt = f.get("retest") or {}
                lines.append(
                    f"- 复测结论：{_RETEST_LABEL.get(str(rt.get('verdict') or ''), rt.get('verdict') or '-')}"
                    f"（{rt.get('method') or '-'} · {rt.get('created_at') or '-'}）"
                )
            if f.get("message"):
                lines.append("")
                lines.append("**问题说明**")
                lines.append("")
                lines.append(str(f.get("message") or ""))
            if f.get("snippet"):
                lines.append("")
                lines.append("**代码片段**")
                lines.append("")
                lines.append("```")
                lines.append(str(f.get("snippet") or ""))
                lines.append("```")
            if f.get("ai_reason"):
                lines.append("")
                lines.append("**AI 判定理由**")
                lines.append("")
                lines.append(str(f.get("ai_reason") or ""))
            if f.get("remediation"):
                lines.append("")
                lines.append("**修复建议**")
                lines.append("")
                lines.append(str(f.get("remediation") or ""))
            if f.get("review_note"):
                lines.append("")
                lines.append("**人工备注**")
                lines.append("")
                lines.append(str(f.get("review_note") or ""))
            if f.get("poc"):
                poc = f.get("poc") or {}
                lines.append("")
                lines.append("**验证 PoC**")
                lines.append("")
                if poc.get("title"):
                    lines.append(f"- 标题：{poc.get('title')}")
                if poc.get("poc_type"):
                    lines.append(f"- 类型：{poc.get('poc_type')}")
                if poc.get("prerequisites"):
                    lines.append(f"- 前置条件：{poc.get('prerequisites')}")
                if poc.get("steps"):
                    lines.append(f"- 步骤：{poc.get('steps')}")
                if poc.get("expected_result"):
                    lines.append(f"- 预期结果：{poc.get('expected_result')}")
                if poc.get("poc_content"):
                    lines.append("")
                    lines.append("```")
                    lines.append(str(poc.get("poc_content") or ""))
                    lines.append("```")
                if poc.get("safety_note"):
                    lines.append("")
                    lines.append(f"> 安全提示：{poc.get('safety_note')}")
            lines.append("")
    lines.append("## 给 AI 的阅读建议")
    lines.append("- 优先处理 `review_status=confirmed` 且 `ai_verdict=real_vuln` 的漏洞。")
    lines.append("- 针对每条漏洞，结合规则 ID、代码位置和片段给出最小修复补丁。")
    lines.append("- 修复后应补充回归测试，避免功能回归和绕过。")
    lines.append("")
    return "\n".join(lines)


def _render_pdf_html(payload: dict) -> str:
    meta = payload.get("meta") or {}
    stats = payload.get("stats") or {}
    findings = list(payload.get("findings") or [])
    by_sev = stats.get("by_severity") or {}
    by_owasp = stats.get("by_owasp") or {}
    by_tool = stats.get("by_tool") or {}
    group_by = str(meta.get("group_by") or "none")
    by_src = {"sast": 0, "llm": 0}
    for f in findings:
        src = str(f.get("source") or "sast")
        by_src[src] = by_src.get(src, 0) + 1

    def bars(title: str, pairs: list[tuple[str, int]]) -> str:
        mx = max([v for _, v in pairs], default=1)
        if not pairs:
            return f'<section class="panel"><h3>{escape(title)}</h3><p class="muted">无数据</p></section>'
        rows = []
        for label, val in pairs:
            pct = max(4, int(100 * val / mx)) if val else 0
            rows.append(
                '<div class="bar"><div class="name">{}</div><div class="track"><div class="fill" style="width:{}%"></div></div><div class="count">{}</div></div>'.format(
                    escape(label), pct, int(val)
                )
            )
        return f'<section class="panel"><h3>{escape(title)}</h3>{"".join(rows)}</section>'

    cards = (
        f'<div class="cards">'
        f'<div class="card"><div class="lbl">总计</div><div class="val">{int(stats.get("total") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">Critical</div><div class="val c1">{int(by_sev.get("CRITICAL") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">High</div><div class="val c2">{int(by_sev.get("HIGH") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">Medium</div><div class="val c3">{int(by_sev.get("MEDIUM") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">Low</div><div class="val c4">{int(by_sev.get("LOW") or 0)}</div></div>'
        f"</div>"
    )

    table_rows = []
    detail_rows = []
    for f in findings:
        loc = f.get("file_path") or ""
        if f.get("line_start"):
            loc = f"{loc}:{f.get('line_start')}"
        table_rows.append(
            "<tr>"
            f"<td>#{int(f.get('id') or 0)}</td>"
            f"<td>{escape(str(f.get('severity') or ''))}</td>"
            f"<td>{escape(str(f.get('title') or ''))}</td>"
            f"<td>{escape(str(f.get('owasp_id') or 'OTHER'))}</td>"
            f"<td>{escape(_SOURCE_LABEL.get(str(f.get('source') or ''), str(f.get('source') or '')))}</td>"
            f"<td>{escape(loc)}</td>"
            "</tr>"
        )

    def detail_html(f: dict) -> str:
        loc = f.get("file_path") or ""
        if f.get("line_start"):
            loc = f"{loc}:{f.get('line_start')}"
        parts = [
            "<article class='finding'>"
            f"<h4>#{int(f.get('id') or 0)} {escape(str(f.get('title') or ''))}</h4>"
            f"<p><b>严重级别：</b>{escape(str(f.get('severity') or '-'))} "
            f"<b>来源：</b>{escape(_SOURCE_LABEL.get(str(f.get('source') or ''), str(f.get('source') or '')))} / {escape(str(f.get('tool') or '-'))}</p>"
            f"<p><b>规则：</b>{escape(str(f.get('rule_id') or '-'))}</p>"
            f"<p><b>位置：</b>{escape(loc)}</p>"
        ]
        if f.get("vuln_subtype_name") or f.get("vuln_subtype"):
            parts.append(
                f"<p><b>子类型：</b>{escape(str(f.get('vuln_subtype_name') or f.get('vuln_subtype')))}</p>"
            )
        if f.get("retest"):
            rt = f.get("retest") or {}
            parts.append(
                f"<p><b>复测：</b>{escape(_RETEST_LABEL.get(str(rt.get('verdict') or ''), str(rt.get('verdict') or '-')))}"
                f"（{escape(str(rt.get('method') or '-'))}）</p>"
            )
        if f.get("external_status"):
            parts.append(
                f"<p><b>外部复核：</b>{escape(_EXTERNAL_LABEL.get(str(f.get('external_status') or ''), str(f.get('external_status') or '-')))}</p>"
            )
        parts.append(f"<p><b>说明：</b>{escape(str(f.get('message') or '')).replace(chr(10), '<br>')}</p>")
        if f.get("snippet"):
            parts.append(f"<pre>{escape(str(f.get('snippet') or ''))}</pre>")
        if f.get("ai_reason"):
            parts.append(
                f"<p><b>AI 判定理由：</b>{escape(str(f.get('ai_reason') or '')).replace(chr(10), '<br>')}</p>"
            )
        if f.get("remediation"):
            parts.append(
                f"<p><b>修复建议：</b>{escape(str(f.get('remediation') or '')).replace(chr(10), '<br>')}</p>"
            )
        if f.get("review_note"):
            parts.append(
                f"<p><b>人工备注：</b>{escape(str(f.get('review_note') or '')).replace(chr(10), '<br>')}</p>"
            )
        poc = f.get("poc") or {}
        if poc:
            poc_bits = [f"<p><b>验证 PoC：</b>{escape(str(poc.get('title') or ''))}</p>"]
            if poc.get("prerequisites"):
                poc_bits.append(f"<p><b>前置条件：</b>{escape(str(poc.get('prerequisites')))}</p>")
            if poc.get("steps"):
                poc_bits.append(
                    f"<p><b>步骤：</b>{escape(str(poc.get('steps'))).replace(chr(10), '<br>')}</p>"
                )
            if poc.get("poc_content"):
                poc_bits.append(f"<pre>{escape(str(poc.get('poc_content')))}</pre>")
            if poc.get("expected_result"):
                poc_bits.append(f"<p><b>预期结果：</b>{escape(str(poc.get('expected_result')))}</p>")
            parts.append("".join(poc_bits))
        parts.append("</article>")
        return "".join(parts)

    for group_label, group_items in _group_findings(findings, group_by):
        if group_label:
            detail_rows.append(f"<h3 class='group'>{escape(group_label)}（{len(group_items)} 条）</h3>")
        for f in group_items:
            detail_rows.append(detail_html(f))

    template = PDF_TEMPLATE_PATH.read_text(encoding="utf-8")
    html = template.replace(
        "{{PROJECT_NAME}}",
        escape(str(meta.get("title") or meta.get("project_name") or "安全审计报告")),
    )
    html = html.replace(
        "{{SCAN_META}}",
        escape(f"扫描 #{meta.get('scan_id')} / {meta.get('scan_name')} · 分支 {meta.get('branch') or '-'}"),
    )
    html = html.replace(
        "{{TIMING}}",
        escape(f"创建 {meta.get('created_at') or '-'} · 完成 {meta.get('completed_at') or '-'}"),
    )
    html = html.replace("{{SCOPE}}", escape(str(meta.get("scope_label") or "全部漏洞")))
    html = html.replace("{{ONLINE_URL}}", escape(str(meta.get("online_url") or "")))
    html = html.replace("{{CARDS}}", cards)
    html = html.replace(
        "{{CHARTS}}",
        bars("危害分布", [(k, int(by_sev.get(k) or 0)) for k in _SEVERITY_ORDER if int(by_sev.get(k) or 0) > 0])
        + bars("漏洞来源分布", [("SAST", int(by_src.get("sast") or 0)), ("LLM", int(by_src.get("llm") or 0))])
        + bars("OWASP 分布", [(k, int(v)) for k, v in sorted(by_owasp.items())])
        + bars("扫描器分布", [(k, int(v)) for k, v in sorted(by_tool.items())]),
    )
    html = html.replace(
        "{{TABLE_ROWS}}", "".join(table_rows) if table_rows else "<tr><td colspan='6'>无漏洞</td></tr>"
    )
    html = html.replace(
        "{{DETAIL_ROWS}}", "".join(detail_rows) if detail_rows else "<p class='muted'>无漏洞详情。</p>"
    )
    return html


def _static_fallback(meta: dict, stats: dict, findings: list[dict]) -> str:
    sev = stats.get("by_severity") or {}
    cards = (
        f'<div class="cards">'
        f'<div class="card"><div class="lbl">总计</div><div class="val">{int(stats.get("total") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">Critical</div><div class="val c-CRITICAL">{int(sev.get("CRITICAL") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">High</div><div class="val c-HIGH">{int(sev.get("HIGH") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">Medium</div><div class="val c-MEDIUM">{int(sev.get("MEDIUM") or 0)}</div></div>'
        f'<div class="card"><div class="lbl">Low</div><div class="val c-LOW">{int(sev.get("LOW") or 0)}</div></div>'
        f"</div>"
    )
    rows = []
    for f in findings:
        loc = f.get("file_path") or ""
        if f.get("line_start"):
            loc = f"{loc}:{f['line_start']}"
        rows.append(
            "<tr>"
            f'<td class="mono">#{int(f["id"])}</td>'
            f"<td>{escape(str(f.get('severity') or ''))}</td>"
            f"<td>{escape(str(f.get('title') or ''))}</td>"
            f"<td>{escape(_OWASP_LABEL.get(str(f.get('owasp_id') or 'OTHER'), str(f.get('owasp_id') or 'OTHER')))}</td>"
            f'<td class="mono">{escape(_SOURCE_LABEL.get(str(f.get("source") or ""), str(f.get("source") or "")))}</td>'
            f'<td class="mono">{escape(loc)}</td>'
            f"<td>{escape(_VERDICT_LABEL.get(str(f.get('ai_verdict') or ''), str(f.get('ai_verdict') or '')))}</td>"
            f"<td>{escape(_REVIEW_LABEL.get(str(f.get('review_status') or ''), str(f.get('review_status') or '')))}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr>"
        "<th>ID</th><th>危害</th><th>漏洞描述</th><th>类型</th><th>来源</th><th>位置</th><th>AI 判定</th><th>人工标记</th>"
        "</tr></thead><tbody>"
        + ("".join(rows) if rows else '<tr><td colspan="8">无漏洞</td></tr>')
        + "</tbody></table>"
    )
    link = escape(str(meta.get("online_url") or ""))
    return (
        f'<h1>{escape(str(meta.get("title") or meta.get("project_name") or "安全审计报告"))}</h1>'
        f'<p class="meta">扫描 #{escape(str(meta.get("scan_id") or ""))} / {escape(str(meta.get("scan_name") or ""))}'
        f' · 分支 {escape(str(meta.get("branch") or "-"))}'
        f' · 范围 {escape(str(meta.get("scope_label") or "全部漏洞"))}</p>'
        + (f'<p class="meta"><a href="{link}">{link}</a></p>' if link else "")
        + cards
        + table
    )


async def build_scan_report_payload(session: AsyncSession, scan_id: int, spec=None) -> dict:
    """装配报告数据。spec 为 None 时等价于全量报告（向后兼容）。

    传入 spec 时按 finding_ids（优先）或 filters 收敛范围，并按最终明细重算 stats，
    保证报告头部数字与明细条数一致。
    """
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")
    project = await session.get(Project, scan.project_id) if scan.project_id else None

    findings_db = (
        await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    ).scalars().all()

    scan_total = len(findings_db)
    scope = _resolve_scope(spec)
    include = _include_flags(spec)

    # 1) 按显式勾选的 ID 收敛（必须校验归属，避免跨扫描越权）
    if scope == "selected":
        requested = [int(fid) for fid in (spec.finding_ids or [])]
        owned = {f.id for f in findings_db}
        unknown = [fid for fid in requested if fid not in owned]
        if unknown:
            shown = ", ".join(str(i) for i in unknown[:20])
            raise ValueError(f"以下漏洞不属于本次扫描，已拒绝生成报告：{shown}")
        selected = set(requested)
        findings_db = [f for f in findings_db if f.id in selected]

    # 2) 再按结构化筛选收敛
    if spec is not None and spec.filters is not None:
        findings_db = [f for f in findings_db if _match_filters(f, spec.filters)]

    # 3) 误报开关（默认保留，与改造前行为一致）
    if not include["false_positive"]:
        findings_db = [f for f in findings_db if not _is_false_positive(f)]

    sort_key = str(getattr(spec, "sort", None) or "severity")
    if sort_key not in _SORT_KEYS:
        sort_key = "severity"
    findings_db = _sort_findings(list(findings_db), sort_key)

    group_by = str(getattr(spec, "group_by", None) or "severity")
    if group_by not in _GROUP_KEYS:
        group_by = "severity"

    retest_map = (
        await _load_retest_map(session, [f.id for f in findings_db]) if include["retest"] else {}
    )
    findings = [_finding_payload(f, scan, include, retest_map.get(f.id)) for f in findings_db]

    security_score = getattr(scan, "security_score", None) if scope == "all" else None
    stats = _stats_from_findings(findings, security_score=security_score)

    tools = sorted({f["tool"] for f in findings if f.get("tool")})
    scope_label = {
        "all": "全部漏洞",
        "selected": f"自定义勾选（{len(findings)} 条）",
        "filtered": f"条件筛选（{len(findings)} 条）",
    }[scope]

    project_name = project.name if project else scan.name
    meta = {
        "project_name": project_name,
        "scan_id": scan.id,
        "scan_name": scan.name,
        "branch": scan.branch or "",
        "version": scan.version_label or "",
        "created_at": _fmt_dt(scan.created_at),
        "completed_at": _fmt_dt(scan.completed_at),
        "online_url": _scan_detail_link(scan, project),
        "tools": tools,
        "title": _report_title(project_name, spec),
        "scope": scope,
        "scope_label": scope_label,
        "scan_total": scan_total,
        "group_by": group_by,
        "sort": sort_key,
        "include": include,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    return {"meta": meta, "stats": stats, "findings": findings}


def _report_filename(payload: dict, scan_id: int, ext: str) -> str:
    meta = payload.get("meta") or {}
    stats = payload.get("stats") or {}
    name = _safe_filename(str(meta.get("project_name") or "scan-report"))
    slug = _scope_slug(str(meta.get("scope") or "all"), int(stats.get("total") or 0))
    stamp = datetime.now().strftime("%Y%m%d%H%M")
    return f"{name}-{slug}-scan-{scan_id}-{stamp}.{ext}"


def _render_html_from_payload(payload: dict) -> str:
    meta = payload["meta"]
    stats = payload["stats"]
    findings = payload["findings"]
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    payload_json = json.dumps(payload, ensure_ascii=False, default=str).replace("<", "\\u003c")
    html = template.replace(PLACEHOLDER, payload_json, 1)
    html = html.replace(STATIC_PLACEHOLDER, _static_fallback(meta, stats, findings), 1)
    return html


async def build_scan_html_report(session: AsyncSession, scan_id: int, spec=None) -> str:
    payload = await build_scan_report_payload(session, scan_id, spec)
    return _render_html_from_payload(payload)


async def build_scan_html_report_download(
    session: AsyncSession, scan_id: int, spec=None
) -> tuple[str, str]:
    """返回 (html, filename)，供「下载 HTML 文件」使用（区别于预览）。"""
    payload = await build_scan_report_payload(session, scan_id, spec)
    return _render_html_from_payload(payload), _report_filename(payload, scan_id, "html")


async def build_scan_pdf_report(session: AsyncSession, scan_id: int, spec=None) -> tuple[bytes, str]:
    payload = await build_scan_report_payload(session, scan_id, spec)
    total = int((payload.get("stats") or {}).get("total") or 0)
    if total > PDF_MAX_FINDINGS:
        raise ValueError(
            f"报告包含 {total} 条漏洞，超过 PDF 导出上限 {PDF_MAX_FINDINGS} 条。"
            "请缩小范围，或改用 HTML / Markdown 导出。"
        )
    html = _render_pdf_html(payload)
    pdf_bytes = await _render_pdf_bytes(html)
    return pdf_bytes, _report_filename(payload, scan_id, "pdf")


# 常见浏览器安装位置（PATH 里找不到时按顺序兜底探测）
_BROWSER_CANDIDATES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)
_BROWSER_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "msedge")

# 跨平台通用的无头打印参数。
# --disable-dev-shm-usage：容器里 /dev/shm 默认仅 64MB，不加会让 Chromium 崩溃或挂住。
# --no-pdf-header-footer：去掉默认页眉页脚（URL/日期/页码），Chromium 108+ 支持，
#   旧版本会忽略未知参数，无副作用。
_BROWSER_FLAGS = (
    "--disable-gpu",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-pdf-header-footer",
)
# Chromium 112+ 才认 --headless=new，旧镜像按顺序回退
_HEADLESS_FLAGS = ("--headless=new", "--headless")


def find_pdf_browser() -> str | None:
    """探测可用于打印 PDF 的无头浏览器；找不到返回 None。"""
    configured = (settings.pdf_chrome_path or "").strip()
    if configured:
        # 显式配置优先，但路径不存在时继续自动探测（配置写错不至于直接失效）
        if Path(configured).exists():
            return configured
    for name in _BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for candidate in _BROWSER_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def _browser_failure_hint(is_windows: bool) -> str:
    """打印失败时的补充提示。Linux/Docker 上的常见成因和 Windows 不同。"""
    if is_windows:
        return ""
    return (
        "。Linux/Docker 上请确认：① 镜像已安装 chromium（不要用 Ubuntu 的 snap 版 "
        "chromium-browser，容器里跑不起来）；② 已安装中文字体 fonts-noto-cjk"
    )


def _pdf_via_browser_sync(html: str, browser: str) -> bytes:
    """用无头浏览器把 HTML 打印成 PDF（同步阻塞，调用方负责放进线程池）。

    跨平台都要处理的坑：

    1. **必须给独立的 `--user-data-dir`**。否则当机器上已有浏览器在运行时，
       新进程会把请求转交给既有实例后立即退出，不产出任何文件且退出码为 0
       （Windows 上尤其明显）。
    2. **进程可能提前返回**。Windows 上 `chrome.exe` 只是启动器，会立刻退出，
       真正渲染在分离出的子进程里异步完成；Linux 上通常是前台等待。
       所以不能假设 `subprocess.run` 返回时 PDF 就已存在，必须轮询等待文件稳定。
    3. **`--disable-dev-shm-usage` 在容器里是必需的**。Docker 默认 `/dev/shm`
       只有 64MB，Chromium 会因此崩溃或静默挂住。这是 Docker + Chromium 最常见的故障。
    4. **`--headless=new` 只被 Chromium 112+ 支持**，旧镜像不认。这里按
       `--headless=new` → `--headless` 依次重试。
    """
    timeout = max(10, int(settings.pdf_chrome_timeout or 180))
    # ignore_cleanup_errors：浏览器可能仍占用 profile 目录，清理失败不应影响结果
    with tempfile.TemporaryDirectory(
        prefix="ai-audit-pdf-", ignore_cleanup_errors=True
    ) as tmp:
        tmp_dir = Path(tmp)
        html_path = tmp_dir / "report.html"
        pdf_path = tmp_dir / "report.pdf"
        profile_dir = tmp_dir / "profile"
        html_path.write_text(html, encoding="utf-8")

        details: list[str] = []
        for headless_flag in _HEADLESS_FLAGS:
            # 每轮都清掉上一轮的残留，避免把旧产物误当成新结果
            with contextlib.suppress(OSError):
                pdf_path.unlink()
            pdf = _run_browser_print_once(
                browser, headless_flag, html_path, pdf_path, profile_dir, timeout, details
            )
            if pdf is not None:
                return pdf

        hint = _browser_failure_hint(os.name == "nt")
        raise RuntimeError(
            f"无头浏览器在 {timeout}s 内未产出 PDF{hint}"
            + (f"；诊断：{' | '.join(details[:2])[:300]}" if details else "")
        )


def _build_browser_cmd(
    browser: str,
    headless_flag: str,
    html_path: Path,
    pdf_path: Path,
    profile_dir: Path,
) -> list[str]:
    """拼装无头打印命令行（单独抽出来便于测试）。"""
    return [
        browser,
        headless_flag,
        *_BROWSER_FLAGS,
        f"--user-data-dir={profile_dir}",
        f"--print-to-pdf={pdf_path}",
        html_path.as_uri(),
    ]


def _run_browser_print_once(
    browser: str,
    headless_flag: str,
    html_path: Path,
    pdf_path: Path,
    profile_dir: Path,
    timeout: int,
    details: list[str],
) -> bytes | None:
    """跑一次打印尝试。成功返回 PDF 字节，失败返回 None 并把诊断信息追加到 details。"""
    cmd = _build_browser_cmd(browser, headless_flag, html_path, pdf_path, profile_dir)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        details.append(f"{headless_flag}: 启动超时")
        return None

    # 轮询等待产物落盘：文件存在且连续两次采样大小一致，视为写入完成
    deadline = time.monotonic() + timeout
    last_size = -1
    stable_hits = 0
    while time.monotonic() < deadline:
        if pdf_path.exists():
            size = pdf_path.stat().st_size
            if size > 0 and size == last_size:
                stable_hits += 1
                if stable_hits >= 2:
                    return pdf_path.read_bytes()
            else:
                stable_hits = 0
            last_size = size
        time.sleep(0.2)

    stderr = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
    details.append(f"{headless_flag}: 未产出文件" + (f"（{stderr[:200]}）" if stderr else ""))
    return None


_weasyprint_cache: tuple[bool, object] | None = None


def _load_weasyprint():
    """惰性加载 WeasyPrint，只尝试一次。

    返回 (可用, HTML类或异常)。WeasyPrint 在缺少 GTK/Pango 时会在 import 阶段
    直接打印一大段安装指引；由于我们有浏览器兜底，这段提示会误导人，因此在首次
    导入时把它静音。缓存也避免每个请求都重试一次失败的导入。

    注意：该提示由 weasyprint/text/ffi.py 里**无参 `print()`** 输出，走的是
    stdout 而不是 stderr，所以必须同时重定向 stdout。
    """
    global _weasyprint_cache
    if _weasyprint_cache is None:
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                from weasyprint import HTML  # noqa: PLC0415  (可选依赖，按需导入)
        except Exception as exc:  # 缺少 GTK/Pango 时在这里失败
            _weasyprint_cache = (False, exc)
        else:
            _weasyprint_cache = (True, HTML)
    return _weasyprint_cache


async def _render_pdf_bytes(html: str) -> bytes:
    """按 `settings.pdf_engine` 选择渲染引擎。

    - auto：优先 WeasyPrint（若已安装 GTK/Pango），否则回退到无头浏览器
    - weasyprint / chrome：只走指定引擎
    """
    engine = (settings.pdf_engine or "auto").strip().lower()
    if engine not in {"auto", "weasyprint", "chrome"}:
        engine = "auto"

    weasyprint_error: Exception | None = None
    if engine in {"auto", "weasyprint"}:
        available, loaded = _load_weasyprint()
        if not available:
            weasyprint_error = loaded  # type: ignore[assignment]
            if engine == "weasyprint":
                raise RuntimeError(
                    "PDF 导出依赖未安装，请安装 WeasyPrint 及系统字体/渲染库"
                    "（或将 PDF_ENGINE 设为 chrome 使用无头浏览器）"
                ) from weasyprint_error
        else:
            try:
                # WeasyPrint 是同步阻塞的，放到线程池避免卡住事件循环
                return await asyncio.to_thread(lambda: loaded(string=html).write_pdf())
            except Exception as exc:
                weasyprint_error = exc
                if engine == "weasyprint":
                    raise RuntimeError(f"PDF 生成失败：{exc}") from exc

    browser = find_pdf_browser()
    if not browser:
        hint = (
            "PDF 导出不可用：WeasyPrint 未安装，且未找到可用的无头浏览器。"
            "请安装 WeasyPrint + 系统字体/渲染库，或安装 Chrome/Chromium/Edge，"
            "也可通过 PDF_CHROME_PATH 指定浏览器路径。"
        )
        if weasyprint_error is not None:
            raise RuntimeError(f"{hint}（WeasyPrint 报错：{weasyprint_error}）") from weasyprint_error
        raise RuntimeError(hint)

    try:
        return await asyncio.to_thread(_pdf_via_browser_sync, html, browser)
    except Exception as exc:
        raise RuntimeError(f"PDF 生成失败（无头浏览器 {browser}）：{exc}") from exc


async def build_scan_markdown_report(session: AsyncSession, scan_id: int, spec=None) -> tuple[str, str]:
    payload = await build_scan_report_payload(session, scan_id, spec)
    text = _build_markdown_report(payload)
    return text, _report_filename(payload, scan_id, "md")


async def build_scan_json_report(session: AsyncSession, scan_id: int, spec=None) -> tuple[bytes, str]:
    payload = await build_scan_report_payload(session, scan_id, spec)
    blob = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return blob, _report_filename(payload, scan_id, "json")


async def build_scan_report_preview(session: AsyncSession, scan_id: int, spec=None) -> dict:
    """生成前的实时预览：条数与分布，用于确认口径是否与预期一致。"""
    payload = await build_scan_report_payload(session, scan_id, spec)
    meta = payload["meta"]
    stats = payload["stats"]
    findings = payload["findings"]
    by_source: dict[str, int] = {}
    for f in findings:
        src = str(f.get("source") or "sast")
        by_source[src] = by_source.get(src, 0) + 1
    return {
        "scope": meta["scope"],
        "title": meta["title"],
        "total": int(stats.get("total") or 0),
        "scan_total": int(meta.get("scan_total") or 0),
        "pdf_max_findings": PDF_MAX_FINDINGS,
        "by_severity": stats.get("by_severity") or {},
        "by_owasp": stats.get("by_owasp") or {},
        "by_source": by_source,
        "by_tool": stats.get("by_tool") or {},
    }
