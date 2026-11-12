"""Targeted retest pipeline: verify baseline findings on new code without full SAST."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models import (
    AiVerdict,
    ExternalReviewStatus,
    Finding,
    FindingCategory,
    RetestMethod,
    RetestStrategy,
    RetestVerdict,
    RetestVerification,
    ReviewStatus,
    ScanKind,
    ScanStatus,
    ScanTask,
    dt_iso,
)
from app.schemas import FindingOut, RetestResultsSummary, RetestVerificationOut
from app.services.dep_exploit_kb import load_java_high_risk_rules, match_rule_for_version, rule_for_package
from app.services.dep_exploit_service import (
    assess_reachability,
    collect_vulnerable_packages,
    find_sink_hits,
)
from app.services.endpoint_discovery_service import discover_controller_units
from app.services.file_service import locate_text_in_project, read_file_with_context, resolve_project_file
from app.services.java_dep_parser import parse_java_dependencies
from app.services.llm_audit_service import chat_completion, extract_json_from_llm_text, is_llm_configured
from app.services.osv_scanner_client import run_osv_scanner
from app.services.scan_diff_service import _normalize_path
from app.services.scan_service import _classification_fields, _log_event, _resolved_severity, _update_scan
from app.services.scan_runtime import check_scan_cancel, clear_scan_cancel, is_scan_cancel_requested
from app.services.scanners.npm_audit import NpmAuditScanner
from app.services.scanners.pip_audit import PipAuditScanner
from app.services.scanners.common import to_repo_relative_path

logger = logging.getLogger(__name__)

_UPLOAD_PREFIX_RE = re.compile(
    r"(^|.*/)"
    r"(?:(?:backend/)?data/)?uploads/"
    r"[^/]+/"
    r"[^/]+/"
    r"(?P<tail>.+)$",
    re.IGNORECASE,
)

RETEST_LLM_PROMPT = """你是一名资深应用安全专家。任务是核实**上一轮 LLM 审计已报告的漏洞在新代码中是否已修复**。

硬性约束：
- 禁止报告新漏洞、禁止改写漏洞标题、禁止新增 finding
- 只能对输入中给出的 finding_id 逐条给出结论
- 不要输出输入列表之外的任何问题

输出 JSON 数组，每条包含：
- finding_id: 整数（必须与输入一致）
- verdict: "fixed" | "still_present" | "inconclusive"
- confidence: 0.0-1.0
- reason: 简短中文说明（≤200字）

判定标准：
- fixed: 原漏洞对应的危险模式/缺失校验已消失，同类问题在新代码中不可复现
- still_present: 原漏洞模式/逻辑仍存在，或仅做了表面改动
- inconclusive: 文件缺失、重构过大或信息不足，无法判断原问题

只输出 JSON，不要 markdown。"""


def _baseline_relative_path(file_path: str, project_path: Path) -> str | None:
    """Map baseline absolute/upload path to a path resolvable in the retest project."""
    text = (file_path or "").replace("\\", "/").strip()
    if not text:
        return None
    root = project_path.resolve()
    candidate = Path(text)
    if candidate.is_absolute():
        try:
            return str(candidate.resolve().relative_to(root)).replace("\\", "/")
        except ValueError:
            pass
    norm = _normalize_path(text)
    m = _UPLOAD_PREFIX_RE.match(text.lower().replace("\\", "/"))
    if m:
        return m.group("tail").lstrip("/")
    # Walk project to find suffix match.
    tail = norm.split("/")[-6:]  # last segments often unique enough
    suffix = "/".join(tail[-4:]) if tail else norm
    if not suffix:
        return text.lstrip("/")
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/").lower()
        if rel.endswith(suffix) or rel == norm:
            return str(path.relative_to(root)).replace("\\", "/")
    if not candidate.is_absolute():
        return text.lstrip("/")
    return None


def _normalize_review_status(value) -> ReviewStatus:
    if isinstance(value, ReviewStatus):
        return value
    if isinstance(value, str):
        try:
            return ReviewStatus(value)
        except ValueError:
            return ReviewStatus.UNREVIEWED
    return ReviewStatus.UNREVIEWED


def _normalize_external_status(value) -> ExternalReviewStatus:
    if isinstance(value, ExternalReviewStatus):
        return value
    if isinstance(value, str):
        try:
            return ExternalReviewStatus(value)
        except ValueError:
            return ExternalReviewStatus.UNREVIEWED
    return ExternalReviewStatus.UNREVIEWED


def _is_false_positive(finding: Finding) -> bool:
    rs = _normalize_review_status(finding.review_status)
    es = _normalize_external_status(finding.external_status)
    if rs == ReviewStatus.FALSE_POSITIVE or es == ExternalReviewStatus.FALSE_POSITIVE:
        return True
    verdict = finding.ai_verdict
    if isinstance(verdict, AiVerdict):
        return verdict == AiVerdict.FALSE_POSITIVE
    if isinstance(verdict, str):
        return verdict == AiVerdict.FALSE_POSITIVE.value
    return False


def is_in_retest_queue(
    finding: Finding,
    *,
    include_unreviewed_high: bool = False,
) -> bool:
    """Default-path gate: any non-false-positive finding is eligible.

    ``include_unreviewed_high`` is retained for API compatibility and is unused
    because unreviewed findings are included by default.
    """
    _ = include_unreviewed_high
    return not _is_false_positive(finding)


def build_retest_queue(
    findings: list[Finding],
    *,
    include_unreviewed_high: bool = False,
    finding_ids: list[int] | None = None,
) -> list[Finding]:
    """Build the targeted-retest queue.

    - With ``finding_ids``: exact ID match only (includes unreviewed and FP).
    - Without ``finding_ids``: all non-false-positive findings.
    """
    _ = include_unreviewed_high
    id_set = set(finding_ids) if finding_ids else None
    queue: list[Finding] = []
    for f in findings:
        if id_set is not None:
            if f.id in id_set:
                queue.append(f)
            continue
        if not _is_false_positive(f):
            queue.append(f)
    return queue


def _parse_retest_options(scan: ScanTask) -> dict:
    raw = scan.retest_options_json
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _verify_sast_finding(baseline: Finding, project_path: Path) -> tuple[str, str, dict]:
    rel = _baseline_relative_path(baseline.file_path, project_path)
    if not rel:
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.PATTERN.value, {"reason": "path_not_resolved"}

    try:
        resolved = resolve_project_file(project_path, rel)
    except FileNotFoundError:
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.PATTERN.value, {
            "reason": "file_missing",
            "path": rel,
        }
    except ValueError as exc:
        return RetestVerdict.SKIPPED.value, RetestMethod.PATTERN.value, {"reason": str(exc)}

    snippet = (baseline.code_snippet or "").strip()
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.PATTERN.value, {"reason": str(exc)}

    if snippet:
        core_lines = [ln.strip() for ln in snippet.splitlines() if ln.strip()]
        core = core_lines[0] if core_lines else snippet[:120]
        if core and core in text:
            line_no = next((i + 1 for i, ln in enumerate(text.splitlines()) if core in ln), baseline.line_start)
            return RetestVerdict.STILL_PRESENT.value, RetestMethod.PATTERN.value, {
                "file_path": rel,
                "line": line_no,
                "matched": core[:200],
            }
        if len(core) >= 12:
            return RetestVerdict.FIXED.value, RetestMethod.PATTERN.value, {
                "file_path": rel,
                "reason": "snippet_not_found",
            }

    rule_tail = (baseline.rule_id or "").split(".")[-1].split("/")[-1]
    if rule_tail and len(rule_tail) >= 4:
        hits = locate_text_in_project(project_path, rule_tail, file_hint=rel, limit=3)
        if hits:
            h = hits[0]
            return RetestVerdict.STILL_PRESENT.value, RetestMethod.PATTERN.value, {
                "file_path": h.get("file_path") or rel,
                "line": h.get("line"),
                "query": rule_tail,
            }

    if baseline.line_start and baseline.line_start > 0:
        try:
            ctx = read_file_with_context(project_path, rel, baseline.line_start, baseline.line_end or baseline.line_start)
            window = ctx.get("content") or ""
            if snippet and any(ln.strip() in window for ln in snippet.splitlines() if ln.strip()):
                return RetestVerdict.STILL_PRESENT.value, RetestMethod.PATTERN.value, {
                    "file_path": rel,
                    "line": baseline.line_start,
                    "reason": "near_line_match",
                }
        except (FileNotFoundError, ValueError):
            pass

    msg_key = (baseline.message or "")[:80].strip()
    if msg_key and len(msg_key) >= 8:
        hits = locate_text_in_project(project_path, msg_key[:60], file_hint=rel, limit=2)
        if hits:
            h = hits[0]
            return RetestVerdict.STILL_PRESENT.value, RetestMethod.PATTERN.value, h

    return RetestVerdict.INCONCLUSIVE.value, RetestMethod.PATTERN.value, {
        "file_path": rel,
        "reason": "no_confident_match",
    }


def _verify_dep_exploit_finding(baseline: Finding, project_path: Path) -> tuple[str, str, dict]:
    meta: dict = {}
    if baseline.metadata_json:
        try:
            meta = json.loads(baseline.metadata_json)
        except json.JSONDecodeError:
            meta = {}

    package = meta.get("package") or ""
    sink = meta.get("sink") or ""
    if not package:
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.DEP_EXPLOIT.value, {
            "reason": "missing_package_metadata",
        }

    root = project_path.resolve()
    rules = load_java_high_risk_rules()
    local_deps = parse_java_dependencies(root)
    osv_hits = run_osv_scanner(root) or []
    vuln_pkgs, _ = collect_vulnerable_packages(
        project_path=root,
        osv_hits=osv_hits,
        local_deps=local_deps,
        rules=rules,
    )
    pkg_key = package.lower()
    matched = next((p for p in vuln_pkgs if p.package.lower() == pkg_key), None)
    if not matched:
        # Package may have been upgraded out of vulnerable range.
        dep = next((d for d in local_deps if d.package.lower() == pkg_key), None)
        if dep:
            rule = rule_for_package(dep.package, rules)
            if rule and not match_rule_for_version(dep.package, dep.version, rules):
                return RetestVerdict.FIXED.value, RetestMethod.DEP_EXPLOIT.value, {
                    "package": dep.package,
                    "version": dep.version,
                    "reason": "upgraded_out_of_range",
                }
        return RetestVerdict.FIXED.value, RetestMethod.DEP_EXPLOIT.value, {
            "package": package,
            "reason": "not_vulnerable_anymore",
        }

    rule = matched.rule
    sink_hits = find_sink_hits(root, rule)
    if sink and sink_hits:
        sink_hits = [h for h in sink_hits if h.sink == sink] or sink_hits

    if not sink_hits:
        return RetestVerdict.FIXED.value, RetestMethod.DEP_EXPLOIT.value, {
            "package": matched.package,
            "version": matched.version,
            "reason": "sink_removed",
        }

    units = discover_controller_units(root)
    for hit in sink_hits[:5]:
        reach = assess_reachability(root, hit, units)
        if reach.reachable:
            return RetestVerdict.STILL_PRESENT.value, RetestMethod.DEP_EXPLOIT.value, {
                "package": matched.package,
                "version": matched.version,
                "sink": hit.sink,
                "file_path": hit.file_path,
                "line": hit.line,
                "endpoint": reach.endpoint,
            }

    return RetestVerdict.FIXED.value, RetestMethod.DEP_EXPLOIT.value, {
        "package": matched.package,
        "version": matched.version,
        "reason": "sink_not_reachable",
    }


async def _verify_sca_finding(baseline: Finding, project_path: Path) -> tuple[str, str, dict]:
    tool = (baseline.tool or "").lower()
    scanner = None
    if tool in ("npm_audit", "npm"):
        scanner = NpmAuditScanner()
    elif tool in ("pip_audit", "pip"):
        scanner = PipAuditScanner()
    else:
        return RetestVerdict.SKIPPED.value, RetestMethod.PATTERN.value, {"reason": f"unsupported_sca:{tool}"}

    if not await scanner.is_available():
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.PATTERN.value, {"reason": "scanner_unavailable"}

    result = await scanner.scan(project_path)
    if result.error:
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.PATTERN.value, {"reason": result.error[:500]}

    rule_id = baseline.rule_id or ""
    for item in result.findings or []:
        if item.get("rule_id") == rule_id or item.get("check_id") == baseline.check_id:
            return RetestVerdict.STILL_PRESENT.value, RetestMethod.PATTERN.value, {
                "rule_id": item.get("rule_id"),
                "file_path": item.get("file_path"),
            }
    return RetestVerdict.FIXED.value, RetestMethod.PATTERN.value, {"rule_id": rule_id, "reason": "not_in_audit"}


async def verify_finding(
    baseline: Finding,
    project_path: Path,
) -> tuple[str, str, dict]:
    tool = (baseline.tool or "semgrep").lower()
    if tool == "dep_exploit":
        return _verify_dep_exploit_finding(baseline, project_path)
    if tool in ("npm_audit", "npm", "pip_audit", "pip"):
        return await _verify_sca_finding(baseline, project_path)
    if tool == "llm":
        return RetestVerdict.INCONCLUSIVE.value, RetestMethod.LLM.value, {"reason": "pending_llm_batch"}
    if tool in ("semgrep", "codeql", "bandit", "gitleaks") or baseline.category == FindingCategory.SAST:
        return _verify_sast_finding(baseline, project_path)
    return _verify_sast_finding(baseline, project_path)


def _parse_finding_meta(finding: Finding) -> dict:
    raw = finding.metadata_json
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def build_llm_retest_payload_item(finding: Finding, project_path: Path) -> dict:
    """Build a verify-only payload for one baseline LLM finding."""
    meta = _parse_finding_meta(finding)
    rel = _baseline_relative_path(finding.file_path, project_path) or finding.file_path
    ctx_snippet = (finding.code_snippet or "")[:1200]
    try:
        if rel:
            ctx = read_file_with_context(
                project_path,
                rel,
                finding.line_start or 1,
                finding.line_end or finding.line_start or 1,
                context_lines=25,
            )
            ctx_snippet = ctx.get("content") or ctx_snippet
    except (FileNotFoundError, ValueError, OSError):
        pass
    description = (
        meta.get("description")
        or finding.ai_reason
        or finding.message_zh
        or finding.message
        or ""
    )
    return {
        "finding_id": finding.id,
        "title": finding.message,
        "description": str(description)[:1200],
        "api_endpoint": meta.get("api_endpoint") or "",
        "data_flow": meta.get("data_flow") or "",
        "attack_scenario": meta.get("attack_scenario") or "",
        "recommendation": meta.get("recommendation") or "",
        "file": rel,
        "line": finding.line_start,
        "baseline_snippet": (finding.code_snippet or "")[:800],
        "current_code": ctx_snippet[:2000],
        "rule_id": finding.rule_id,
    }


def is_retest_scan(scan: ScanTask) -> bool:
    kind = scan.scan_kind
    value = kind.value if hasattr(kind, "value") else str(kind or "")
    return value == ScanKind.RETEST.value


async def review_retest_llm_findings(
    findings: list[Finding],
    project_path: Path,
) -> dict[int, dict]:
    """Batch LLM verification for LLM baseline findings."""
    if not findings:
        return {}
    if not is_llm_configured():
        return {
            f.id: {
                "verdict": RetestVerdict.INCONCLUSIVE.value,
                "reason": "LLM 未配置",
                "confidence": 0.0,
            }
            for f in findings
        }

    results: dict[int, dict] = {}
    batch_size = 6
    for i in range(0, len(findings), batch_size):
        batch = findings[i : i + batch_size]
        payload = [build_llm_retest_payload_item(f, project_path) for f in batch]

        user_content = json.dumps(payload, ensure_ascii=False, indent=2)
        try:
            text = await chat_completion(
                [
                    {"role": "system", "content": RETEST_LLM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            "请只核实以下已报告漏洞是否已修复。"
                            "禁止输出新漏洞，禁止改写标题，必须使用输入中的 finding_id。\n\n"
                            f"{user_content}"
                        ),
                    },
                ],
                task="deep",
                temperature=0.1,
                max_tokens=4096,
            )
            text = extract_json_from_llm_text(text)
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                parsed = parsed.get("findings", [parsed])
            if isinstance(parsed, list):
                for row in parsed:
                    fid = row.get("finding_id")
                    if fid is None:
                        continue
                    verdict = str(row.get("verdict", "inconclusive")).lower()
                    if verdict not in (
                        RetestVerdict.FIXED.value,
                        RetestVerdict.STILL_PRESENT.value,
                        RetestVerdict.INCONCLUSIVE.value,
                    ):
                        verdict = RetestVerdict.INCONCLUSIVE.value
                    results[int(fid)] = {
                        "verdict": verdict,
                        "reason": row.get("reason") or "",
                        "confidence": float(row.get("confidence") or 0.0),
                    }
        except Exception as exc:
            logger.exception("LLM retest batch failed")
            for f in batch:
                results[f.id] = {
                    "verdict": RetestVerdict.INCONCLUSIVE.value,
                    "reason": f"LLM 核实失败: {exc}",
                    "confidence": 0.0,
                }
    return results


async def _persist_still_present_finding(
    session: AsyncSession,
    scan_id: int,
    baseline: Finding,
    evidence: dict,
    project_path: Path,
) -> Finding:
    rel = evidence.get("file_path") or _baseline_relative_path(baseline.file_path, project_path) or baseline.file_path
    rel = to_repo_relative_path(rel, project_path) or rel
    line = int(evidence.get("line") or baseline.line_start or 0)
    meta = {"retest_of_finding_id": baseline.id}
    if baseline.metadata_json:
        try:
            base_meta = json.loads(baseline.metadata_json)
            if isinstance(base_meta, dict):
                meta = {**base_meta, **meta}
        except json.JSONDecodeError:
            pass

    item = {
        "rule_id": baseline.rule_id,
        "check_id": baseline.check_id,
        "severity": baseline.severity.value if hasattr(baseline.severity, "value") else baseline.severity,
        "message": f"[复测仍存在] {baseline.message}",
        "file_path": rel,
        "line_start": line,
        "line_end": line or baseline.line_end,
        "code_snippet": baseline.code_snippet,
        "metadata_json": json.dumps(meta, ensure_ascii=False),
        "tool": baseline.tool,
        "category": baseline.category.value if hasattr(baseline.category, "value") else baseline.category,
    }
    classification = _classification_fields(item)
    finding = Finding(
        scan_id=scan_id,
        rule_id=item["rule_id"],
        check_id=item.get("check_id"),
        severity=_resolved_severity(item, classification),
        message=item["message"],
        file_path=item["file_path"],
        line_start=item["line_start"],
        line_end=item["line_end"],
        code_snippet=item.get("code_snippet"),
        metadata_json=item.get("metadata_json"),
        tool=item.get("tool", baseline.tool),
        category=baseline.category,
        **classification,
    )
    session.add(finding)
    await session.flush()
    return finding


async def start_targeted_retest_task(scan_id: int) -> None:
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            raise ValueError("扫描任务不存在")
        if scan.status not in (ScanStatus.PENDING, ScanStatus.FAILED, ScanStatus.COMPLETED):
            raise ValueError("当前状态不可启动定向复测")
        clear_scan_cancel(scan_id)
        await _update_scan(
            session,
            scan,
            status=ScanStatus.SCANNING,
            progress=5,
            progress_message="定向复测启动中…",
            error_message=None,
        )


async def run_targeted_retest_pipeline(scan_id: int) -> None:
    clear_scan_cancel(scan_id)
    try:
        await _run_targeted_retest_inner(scan_id)
    except Exception as exc:
        logger.exception("Targeted retest failed for scan %s", scan_id)
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan and scan.status != ScanStatus.COMPLETED:
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.FAILED,
                    error_message=str(exc),
                    progress_message="定向复测失败",
                )
    finally:
        clear_scan_cancel(scan_id)


async def _run_targeted_retest_inner(scan_id: int) -> None:
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return
        baseline_id = scan.parent_scan_id
        if not baseline_id:
            await _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                error_message="缺少 baseline 扫描",
                progress_message="定向复测失败",
            )
            return

        baseline = await session.get(ScanTask, baseline_id)
        if not baseline:
            await _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                error_message="baseline 扫描不存在",
                progress_message="定向复测失败",
            )
            return

        options = _parse_retest_options(scan)
        include_unreviewed_high = bool(options.get("include_unreviewed_high"))
        finding_ids = options.get("finding_ids")
        if finding_ids is not None and not isinstance(finding_ids, list):
            finding_ids = None

        baseline_findings = list(
            (await session.execute(select(Finding).where(Finding.scan_id == baseline_id))).scalars().all()
        )
        queue = build_retest_queue(
            baseline_findings,
            include_unreviewed_high=include_unreviewed_high,
            finding_ids=finding_ids,
        )

        if not queue:
            msg = "无待复测漏洞，请先在列表中确认漏洞或接收外部修复声明"
            await _update_scan(
                session,
                scan,
                status=ScanStatus.COMPLETED,
                progress=100,
                progress_message=msg,
                scanner_summary=json.dumps(
                    {"fixed": 0, "still_present": 0, "inconclusive": 0, "skipped": 0, "queue_size": 0},
                    ensure_ascii=False,
                ),
                total_findings=0,
                completed_at=datetime.now(timezone.utc),
            )
            await _log_event(scan_id, msg, phase="retest")
            return

        project_path = Path(scan.project_path)
        await _update_scan(
            session,
            scan,
            progress=10,
            progress_message=f"定向复测：核实 {len(queue)} 条漏洞…",
        )
        baseline_id_saved = baseline_id

    # Verification loop (may call async scanners / LLM).
    llm_pending = [f for f in queue if (f.tool or "").lower() == "llm"]
    non_llm = [f for f in queue if f not in llm_pending]

    project_path = Path((await _get_scan(scan_id)).project_path)
    llm_results = await review_retest_llm_findings(llm_pending, project_path) if llm_pending else {}

    counts = {"fixed": 0, "still_present": 0, "inconclusive": 0, "skipped": 0}
    verifications: list[tuple[Finding, str, str, dict, Finding | None]] = []

    for idx, baseline_f in enumerate(non_llm):
        if is_scan_cancel_requested(scan_id):
            check_scan_cancel(scan_id)
        if idx % 3 == 0:
            pct = 10 + int(70 * idx / max(len(queue), 1))
            async with async_session() as session:
                scan = await session.get(ScanTask, scan_id)
                if scan:
                    await _update_scan(session, scan, progress=min(pct, 80), progress_message=f"核实中 ({idx + 1}/{len(queue)})…")

        verdict, method, evidence = await verify_finding(baseline_f, project_path)
        verifications.append((baseline_f, verdict, method, evidence, None))

    for baseline_f in llm_pending:
        if is_scan_cancel_requested(scan_id):
            check_scan_cancel(scan_id)
        row = llm_results.get(baseline_f.id) or {}
        verdict = row.get("verdict", RetestVerdict.INCONCLUSIVE.value)
        evidence = {"reason": row.get("reason"), "confidence": row.get("confidence")}
        verifications.append((baseline_f, verdict, RetestMethod.LLM.value, evidence, None))

    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return

        # Clear previous retest rows if re-run.
        existing = (
            await session.execute(select(RetestVerification).where(RetestVerification.scan_id == scan_id))
        ).scalars().all()
        for row in existing:
            await session.delete(row)

        current_finding_by_baseline: dict[int, int] = {}
        for baseline_f, verdict, method, evidence, _ in verifications:
            if verdict == RetestVerdict.STILL_PRESENT.value:
                still_finding = await _persist_still_present_finding(
                    session, scan_id, baseline_f, evidence, project_path
                )
                current_finding_by_baseline[baseline_f.id] = still_finding.id

            if verdict in counts:
                counts[verdict] += 1
            session.add(
                RetestVerification(
                    scan_id=scan_id,
                    baseline_scan_id=baseline_id_saved,
                    baseline_finding_id=baseline_f.id,
                    verdict=verdict,
                    method=method,
                    evidence_json=json.dumps(evidence, ensure_ascii=False),
                )
            )

        total_still = counts.get(RetestVerdict.STILL_PRESENT.value, 0)
        summary = {
            **counts,
            "queue_size": len(queue),
        }
        await session.commit()

        scan = await session.get(ScanTask, scan_id)
        if scan:
            await _update_scan(
                session,
                scan,
                status=ScanStatus.COMPLETED,
                progress=100,
                progress_message=(
                    f"定向复测完成：已修复 {counts.get('fixed', 0)} / "
                    f"仍存在 {counts.get('still_present', 0)} / "
                    f"无法判定 {counts.get('inconclusive', 0)}"
                ),
                scanner_summary=json.dumps(summary, ensure_ascii=False),
                total_findings=total_still,
                completed_at=datetime.now(timezone.utc),
            )
        await _log_event(scan_id, f"定向复测完成，队列 {len(queue)} 条", phase="retest")


async def _get_scan(scan_id: int) -> ScanTask:
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            raise ValueError("scan not found")
        return scan


async def run_llm_verify_on_retest_scan(scan_id: int) -> int:
    """Verify baseline LLM findings on a retest scan. Does not run discovery audit."""
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return 0
        baseline_id = scan.parent_scan_id
        if not baseline_id:
            await _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                error_message="复测任务缺少 baseline，无法核实上次 LLM 发现",
                progress_message="LLM 核实失败",
            )
            await _log_event(scan_id, "复测任务缺少 baseline，已跳过发现式 LLM 审计", level="error", phase="llm")
            return 0

        options = _parse_retest_options(scan)
        finding_ids = options.get("finding_ids")
        if finding_ids is not None and not isinstance(finding_ids, list):
            finding_ids = None
        include_unreviewed_high = bool(options.get("include_unreviewed_high"))
        baseline_findings = list(
            (await session.execute(select(Finding).where(Finding.scan_id == baseline_id))).scalars().all()
        )
        queue = [
            f
            for f in build_retest_queue(
                baseline_findings,
                include_unreviewed_high=include_unreviewed_high,
                finding_ids=finding_ids,
            )
            if (f.tool or "").lower() == "llm"
        ]
        project_path = Path(scan.project_path or "")
        await _update_scan(
            session,
            scan,
            status=ScanStatus.LLM_AUDITING,
            progress=15,
            progress_message=f"核实上次 LLM 发现（{len(queue)} 条），不重新发现漏洞…",
            error_message=None,
        )
        await _log_event(
            scan_id,
            f"复测任务改为核实上次 LLM 发现：{len(queue)} 条（不会跑发现式端点审计）",
            phase="llm",
        )

    if not queue:
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan:
                total = (
                    await session.execute(
                        select(Finding).where(Finding.scan_id == scan_id)
                    )
                ).scalars().all()
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.COMPLETED,
                    progress=100,
                    progress_message="基线没有待核实的 LLM 发现（已排除误报）",
                    total_findings=len(total),
                    completed_at=datetime.now(timezone.utc),
                )
            await _log_event(scan_id, "基线没有待核实的 LLM 发现，已跳过发现式审计", phase="llm")
        return 0

    llm_results = await review_retest_llm_findings(queue, project_path)

    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return 0

        baseline_ids = {f.id for f in queue}
        existing_verifications = (
            await session.execute(select(RetestVerification).where(RetestVerification.scan_id == scan_id))
        ).scalars().all()
        for row in existing_verifications:
            method = row.method.value if hasattr(row.method, "value") else str(row.method or "")
            if method == RetestMethod.LLM.value or row.baseline_finding_id in baseline_ids:
                await session.delete(row)

        existing_findings = (
            await session.execute(select(Finding).where(Finding.scan_id == scan_id))
        ).scalars().all()
        for finding in existing_findings:
            meta = {}
            if finding.metadata_json:
                try:
                    parsed = json.loads(finding.metadata_json)
                    if isinstance(parsed, dict):
                        meta = parsed
                except json.JSONDecodeError:
                    meta = {}
            bid = meta.get("retest_of_finding_id")
            try:
                bid = int(bid) if bid is not None else None
            except (TypeError, ValueError):
                bid = None
            if bid in baseline_ids:
                await session.delete(finding)

        still_count = 0
        for baseline_f in queue:
            row = llm_results.get(baseline_f.id) or {}
            verdict = row.get("verdict", RetestVerdict.INCONCLUSIVE.value)
            evidence = {"reason": row.get("reason"), "confidence": row.get("confidence")}
            if verdict == RetestVerdict.STILL_PRESENT.value:
                await _persist_still_present_finding(session, scan_id, baseline_f, evidence, project_path)
                still_count += 1
            session.add(
                RetestVerification(
                    scan_id=scan_id,
                    baseline_scan_id=baseline_id,
                    baseline_finding_id=baseline_f.id,
                    verdict=verdict,
                    method=RetestMethod.LLM.value,
                    evidence_json=json.dumps(evidence, ensure_ascii=False),
                )
            )

        await session.commit()
        scan = await session.get(ScanTask, scan_id)
        total = (
            await session.execute(select(Finding).where(Finding.scan_id == scan_id))
        ).scalars().all()
        if scan:
            await _update_scan(
                session,
                scan,
                status=ScanStatus.COMPLETED,
                progress=100,
                progress_message=(
                    f"已核实上次 LLM 发现 {len(queue)} 条，仍存在 {still_count} 条（未重新发现新漏洞）"
                ),
                total_findings=len(total),
                completed_at=datetime.now(timezone.utc),
            )
        await _log_event(
            scan_id,
            f"LLM 核实完成：队列 {len(queue)}，仍存在 {still_count}",
            phase="llm",
        )
        return still_count


async def get_retest_results(session: AsyncSession, scan_id: int) -> RetestResultsSummary:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("scan not found")

    baseline_id = scan.parent_scan_id
    if not baseline_id:
        raise ValueError("not a retest scan")

    rows = list(
        (
            await session.execute(
                select(RetestVerification)
                .where(RetestVerification.scan_id == scan_id)
                .order_by(RetestVerification.id)
            )
        ).scalars().all()
    )

    baseline_findings = {
        f.id: f
        for f in (
            await session.execute(select(Finding).where(Finding.scan_id == baseline_id))
        ).scalars().all()
    }

    current_by_baseline: dict[int, int] = {}
    for f in (
        await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    ).scalars().all():
        if not f.metadata_json:
            continue
        try:
            meta = json.loads(f.metadata_json)
            bid = meta.get("retest_of_finding_id")
            if bid:
                current_by_baseline[int(bid)] = f.id
        except (json.JSONDecodeError, TypeError, ValueError):
            continue

    items: list[RetestVerificationOut] = []
    counts = {"fixed": 0, "still_present": 0, "inconclusive": 0, "skipped": 0}
    for row in rows:
        verdict_raw = str(row.verdict or "").strip().lower()
        method_raw = str(row.method or "").strip().lower()
        try:
            verdict = RetestVerdict(verdict_raw)
        except ValueError:
            logger.warning("Unexpected retest verdict for row %s: %s", row.id, row.verdict)
            verdict = RetestVerdict.INCONCLUSIVE
        try:
            method = RetestMethod(method_raw)
        except ValueError:
            logger.warning("Unexpected retest method for row %s: %s", row.id, row.method)
            method = RetestMethod.PATTERN
        counts[verdict.value] = counts.get(verdict.value, 0) + 1
        bf = baseline_findings.get(row.baseline_finding_id)
        baseline_finding_out = None
        if bf:
            try:
                baseline_finding_out = FindingOut.model_validate(bf)
            except Exception:
                logger.warning(
                    "Failed to serialize baseline finding %s for retest row %s",
                    row.baseline_finding_id,
                    row.id,
                    exc_info=True,
                )
        items.append(
            RetestVerificationOut(
                id=row.id,
                scan_id=row.scan_id,
                baseline_scan_id=row.baseline_scan_id,
                baseline_finding_id=row.baseline_finding_id,
                verdict=verdict,
                method=method,
                evidence_json=row.evidence_json,
                created_at=dt_iso(row.created_at) or "",
                baseline_finding=baseline_finding_out,
                current_finding_id=current_by_baseline.get(row.baseline_finding_id),
            )
        )

    message = None
    if not rows and scan.status == ScanStatus.COMPLETED:
        try:
            summary = json.loads(scan.scanner_summary or "{}")
            if summary.get("queue_size") == 0:
                message = "无待复测漏洞，请先在列表中确认漏洞或接收外部修复声明"
        except json.JSONDecodeError:
            pass

    return RetestResultsSummary(
        scan_id=scan_id,
        baseline_scan_id=baseline_id,
        queue_size=len(rows),
        fixed_count=counts.get("fixed", 0),
        still_present_count=counts.get("still_present", 0),
        inconclusive_count=counts.get("inconclusive", 0),
        skipped_count=counts.get("skipped", 0),
        message=message,
        items=items,
    )
