import asyncio
import json
import logging
import secrets
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import and_, delete, event, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models import AiVerdict, ExternalReviewStatus, Finding, FindingCategory, Project, ProjectSuppression, ReviewStatus, ScanEvent, ScanKind, ScanSource, ScanStatus, ScanTask, Severity
from app.exceptions import DuplicateGitUrlError, WebhookValidationError
from app.schemas import ReportFilters, ReportSpec
from app.services.webhook_service import find_project_by_source_url
from app.services.url_normalize import normalize_gitlab_url
from app.services.gitlab_service import clone_gitlab_repo, probe_gitlab_repo, split_project_url
from app.services.scanners.common import to_repo_relative_path
from app.services.project_service import ensure_project_for_new_scan, find_project_by_name, next_version_label
from app.services.llm_audit_service import (
    apply_llm_review_results,
    filter_new_llm_findings,
    is_non_vuln_confirmation_text,
    is_llm_pending_review,
    review_llm_findings,
    run_llm_code_audit,
)
from app.services.llm_audit_journal import log_llm_audit_journal
from app.services.llm_audit_runtime import (
    LlmAuditCancelled,
    clear_llm_audit_cancel,
    is_llm_audit_cancel_requested,
    request_llm_audit_cancel,
)
from app.services.scan_runtime import clear_scan_cancel, is_scan_cancel_requested
from app.services.llm_provider import is_llm_configured
from app.services.llm_sast_deep_service import analyze_sast_with_flow, apply_sast_deep_results
from app.services.llm_flow_recon_service import apply_flow_recon_result, reconstruct_finding_flow
from app.services.llm_service import analyze_findings, apply_fp_results, translate_finding_messages
from app.services.scanners.registry import run_scanners
from app.services.project_languages import parse_scan_languages_json
from app.services.scanners.semgrep import (
    build_semgrep_command,
    plan_semgrep_scan,
    reset_forced_scan_languages,
    set_forced_scan_languages,
)
from app.services.poc_http import PocTargetError, execute_http_request, normalize_http_request, request_to_curl
from app.services.poc_service import (
    generate_verification_poc,
    get_stored_poc,
    merge_http_request_into_poc,
    save_poc_to_finding,
)
from app.services.owasp_classifier import classify_finding, classify_owasp
from app.services.severity_policy import adjust_severity
from app.services.sast_flow_service import extract_flow_steps, parse_finding_metadata
from app.services.semgrep_service import extract_upload
from app.services.feishu_service import (
    build_external_review_link,
    send_feishu_finding_notification,
    send_feishu_scan_completed,
    send_feishu_scan_started,
)
from app.services.email_service import send_html_email, smtp_configured
from app.services.report_service import build_scan_html_report
from app.services.path_filters import filter_out_test_findings
from app.services.finding_dedupe import dedupe_sast_findings
from app.services.scan_diff_service import _normalize_path, finding_fingerprint

logger = logging.getLogger(__name__)


def _as_utc(dt: datetime) -> datetime:
    """Normalize SQLite naive datetimes for safe UTC comparison."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _classification_fields(item: dict) -> dict[str, str]:
    cat = item.get("category", FindingCategory.SAST.value)
    if isinstance(cat, FindingCategory):
        cat = cat.value
    return classify_finding(
        rule_id=item.get("rule_id", ""),
        message=item.get("message", ""),
        metadata_json=item.get("metadata_json"),
        tool=item.get("tool", "semgrep"),
        category=cat,
    )


def _normalize_notify_emails(
    notify_emails: list[str] | None = None,
    notify_email: str | None = None,
) -> list[str]:
    values: list[str] = []
    if notify_emails:
        values.extend(str(x or "").strip() for x in notify_emails)
    if notify_email:
        raw = str(notify_email).replace(";", ",")
        values.extend(part.strip() for part in raw.split(","))
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not item or "@" not in item:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _unpack_notify_emails_json(raw: str | None) -> tuple[list[str], bool]:
    if not raw:
        return [], True
    try:
        data = json.loads(raw)
    except Exception:
        return [], True
    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()], True
    if isinstance(data, dict):
        emails_raw = data.get("emails") or []
        if not isinstance(emails_raw, list):
            emails_raw = []
        emails = [str(x).strip() for x in emails_raw if str(x).strip()]
        send_report = bool(data.get("send_html_report", True))
        return emails, send_report
    return [], True


# 邮件报告允许的严重级别，按严重度降序；与 report_service._SEVERITY_RANK 同序。
_REPORT_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _normalize_report_severities(values) -> list[str]:
    """规范化邮件报告的严重级别筛选：转大写、去重、丢弃非法值、按严重度降序。

    返回空列表表示「不筛选」，即沿用旧的全量报告行为。
    """
    if not values:
        return []
    raw = {str(v).strip().upper() for v in values if str(v).strip()}
    valid = {s.value for s in Severity if s is not Severity.UNKNOWN}
    return [s for s in _REPORT_SEVERITY_ORDER if s in raw and s in valid]


def _pack_notify_emails_json(
    notify_emails: list[str] | None = None,
    *,
    notify_email: str | None = None,
    send_html_report: bool = True,
    report_severities: list[str] | None = None,
) -> str | None:
    emails = _normalize_notify_emails(notify_emails, notify_email)
    if not emails and send_html_report:
        return None
    payload: dict = {"emails": emails, "send_html_report": send_html_report}
    severities = _normalize_report_severities(report_severities)
    if severities:
        # 只在显式配置时写入该键：旧数据/旧调用方解析结果完全不变。
        payload["report_severities"] = severities
    return json.dumps(payload, ensure_ascii=False)


def _report_severities_from_notify(raw: str | None) -> list[str]:
    """从 notify_emails_json 里读出邮件报告范围；任何异常一律降级为「不筛选」。"""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    return _normalize_report_severities(data.get("report_severities"))


def _email_report_spec(scan: ScanTask) -> ReportSpec | None:
    """扫描完成邮件使用的报告范围；未配置严重级别筛选时返回 None（= 全量）。"""
    severities = _report_severities_from_notify(scan.notify_emails_json)
    if not severities:
        return None
    return ReportSpec(filters=ReportFilters(severity=severities))


def _load_notify_emails(scan: ScanTask | None) -> list[str]:
    emails, _ = _unpack_notify_emails_json(scan.notify_emails_json if scan else None)
    return emails


def notify_emails_for_scan(scan: ScanTask | None) -> list[str]:
    return _load_notify_emails(scan)


async def explain_llm_no_findings(session: AsyncSession, scan_id: int) -> dict:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("scan not found")

    llm_findings = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .where(Finding.scan_id == scan_id, Finding.tool == "llm")
        )
    ).scalar() or 0

    event_rows = (
        await session.execute(
            select(ScanEvent)
            .where(
                ScanEvent.scan_id == scan_id,
                ScanEvent.phase.in_(("llm", "llm_fp", "llm_audit", "error", "done")),
            )
            .order_by(ScanEvent.id.asc())
        )
    ).scalars().all()

    messages = [str(e.message or "") for e in event_rows]
    no_endpoint_hit = any("未发现 HTTP 端点" in msg for msg in messages)
    fallback_used = any("自动切换文件采样审计" in msg for msg in messages)
    llm_failed = any(("LLM" in msg and "失败" in msg) for msg in messages)
    llm_triggered = any(e.phase in ("llm", "llm_audit") for e in event_rows)

    llm_fp_enabled = bool(settings.llm_enabled)
    llm_endpoint_enabled = bool(settings.llm_code_audit_enabled)
    llm_ready = bool(is_llm_configured())

    if llm_findings > 0:
        code = "llm_found"
        summary = f"LLM 审计已产出 {llm_findings} 条发现。"
    elif not llm_fp_enabled and not llm_endpoint_enabled:
        code = "llm_disabled"
        summary = "未开启自动 LLM 审计（误报审计与端点审计均关闭）。"
    elif (llm_fp_enabled or llm_endpoint_enabled) and not llm_ready:
        code = "llm_not_configured"
        summary = "已开启自动 LLM 审计，但未配置可用的 LLM API Key。"
    elif no_endpoint_hit and fallback_used:
        code = "llm_file_sampling_fallback_no_new"
        summary = "端点审计阶段未识别到 HTTP 路由，系统已自动切换文件采样审计，但仍未新增结构化漏洞发现。"
    elif no_endpoint_hit:
        code = "no_http_endpoints_detected"
        summary = "端点审计阶段未识别到 HTTP 路由。"
    elif llm_failed:
        code = "llm_failed"
        summary = "LLM 审计执行失败，请查看错误日志。"
    elif llm_triggered:
        code = "llm_completed_no_new"
        summary = "LLM 审计已执行完成，但未新增结构化漏洞发现。"
    else:
        code = "llm_not_triggered"
        summary = "本轮扫描未触发 LLM 审计阶段。"

    evidence = [
        {
            "phase": e.phase or "",
            "level": e.level or "info",
            "message": (e.message or "")[:500],
            "created_at": e.created_at.isoformat() if e.created_at else "",
        }
        for e in event_rows[-20:]
    ]

    suggestions: list[str] = []
    if code == "llm_disabled":
        suggestions.append("在系统设置中开启自动 LLM 审计（误报审计或端点审计）。")
    if code == "llm_not_configured":
        suggestions.append("配置可用的 LLM API Key，并执行“测试 LLM 连接”。")
    if code == "no_http_endpoints_detected":
        suggestions.append(
            "确认项目使用 Spring/Flask/Express/NestJS/Koa 等标准路由写法；"
            "若为动态注册或非标准框架，可改用文件采样审计补盲。"
        )
    if code == "llm_file_sampling_fallback_no_new":
        suggestions.append("系统已自动执行文件采样审计；若仍无发现，可提高采样范围、迭代轮次或手动指定高风险模块复审。")
    if code == "llm_completed_no_new":
        suggestions.append("可提高迭代轮次/审计域数量后重试，或缩小范围做定向复审。")
    if code == "llm_failed":
        suggestions.append("查看 LLM 审计日志中的 error 条目，定位超时/模型/网络异常。")
    if not suggestions:
        suggestions.append("查看 LLM 审计日志与事件流，确认具体执行路径。")

    return {
        "scan_id": scan_id,
        "code": code,
        "summary": summary,
        "llm_findings": int(llm_findings),
        "llm_enabled": llm_fp_enabled,
        "llm_code_audit_enabled": llm_endpoint_enabled,
        "llm_configured": llm_ready,
        "evidence": evidence,
        "suggestions": suggestions,
    }


def _stored_file_path(file_path: str | None, project_path: str | Path | None = None) -> str:
    return to_repo_relative_path(file_path or "", project_path)


def _should_send_html_report(scan: ScanTask | None) -> bool:
    _, send_report = _unpack_notify_emails_json(scan.notify_emails_json if scan else None)
    return send_report


def _relaxed_fingerprint_from_parts(
    *,
    tool: str,
    rule_id: str,
    file_path: str,
    message: str,
    owasp_id: str | None = None,
    vuln_subtype: str | None = None,
) -> str:
    parts = [
        (tool or "").lower().strip(),
        (rule_id or "").lower().strip(),
        # 必须和严指纹走同一套路径归一化。这里原来只做斜杠/大小写处理，保留了
        # 盘符和 `data/repos/<hash>/`、`data/uploads/<run>/<ver>/` 前缀，于是
        # 同一份代码换个克隆目录或上传批次就算不出同一个宽松指纹——宽松档本应
        # 比严档更宽容，实际却在路径维度上更严，人工确认过的误报抑制会丢失。
        _normalize_path(file_path),
        " ".join((message or "").strip().lower().split())[:240],
        (owasp_id or "").upper().strip(),
        (vuln_subtype or "").lower().strip(),
    ]
    return "|".join(parts)


def _relaxed_fingerprint_for_finding(finding: Finding | dict) -> str:
    if isinstance(finding, dict):
        return _relaxed_fingerprint_from_parts(
            tool=str(finding.get("tool") or "semgrep"),
            rule_id=str(finding.get("rule_id") or ""),
            file_path=str(finding.get("file_path") or ""),
            message=str(finding.get("message_zh") or finding.get("message") or ""),
            owasp_id=finding.get("owasp_id"),
            vuln_subtype=finding.get("vuln_subtype"),
        )
    return _relaxed_fingerprint_from_parts(
        tool=str(finding.tool or "semgrep"),
        rule_id=str(finding.rule_id or ""),
        file_path=str(finding.file_path or ""),
        message=str(finding.message_zh or finding.message or ""),
        owasp_id=finding.owasp_id,
        vuln_subtype=finding.vuln_subtype,
    )


SUPPRESSION_STATUS_FALSE_POSITIVE = "false_positive"
SUPPRESSION_STATUS_WHITELIST = "whitelist"

# 白名单/误报库命中后写进 finding 的说明，便于 UI 区分来源。
_SUPPRESSION_NOTE_LABELS = {
    SUPPRESSION_STATUS_FALSE_POSITIVE: "继承历史误报",
    SUPPRESSION_STATUS_WHITELIST: "命中项目白名单",
}


def _suppression_note(status: str | None, reason: str | None) -> str:
    label = _SUPPRESSION_NOTE_LABELS.get(
        (status or "").strip().lower(), "命中项目抑制库"
    )
    reason = (reason or "").strip()
    return f"{label}：{reason}" if reason else label


def _suppression_expired(row: ProjectSuppression) -> bool:
    """过期的抑制/白名单条目不再生效；``expires_at`` 为空表示永久。"""
    expires = getattr(row, "expires_at", None)
    if not expires:
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= datetime.now(timezone.utc)


async def _upsert_project_suppression(
    session: AsyncSession,
    *,
    project_id: int,
    finding: Finding,
    reason: str,
    created_by: str | None = None,
    status: str = SUPPRESSION_STATUS_FALSE_POSITIVE,
) -> ProjectSuppression:
    strict = finding_fingerprint(finding)
    relaxed = _relaxed_fingerprint_for_finding(finding)
    existing = (
        await session.execute(
            select(ProjectSuppression).where(
                ProjectSuppression.project_id == project_id,
                ProjectSuppression.fingerprint_strict == strict,
            )
        )
    ).scalars().first()
    if existing:
        existing.reason = reason
        existing.status = status
        existing.rule_id = finding.rule_id
        existing.file_path = finding.file_path
        existing.source_scan_id = finding.scan_id
        existing.source_finding_id = finding.id
        existing.created_by = created_by or existing.created_by
        existing.fingerprint_relaxed = relaxed
        return existing
    row = ProjectSuppression(
        project_id=project_id,
        fingerprint_strict=strict,
        fingerprint_relaxed=relaxed,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        status=status,
        reason=reason,
        source_scan_id=finding.scan_id,
        source_finding_id=finding.id,
        created_by=created_by,
    )
    session.add(row)
    return row


def _canonical_suppression_fingerprint(raw: str | None) -> str:
    """把库里存量指纹的路径分量重新归一化后再用于匹配。

    抑制条目的路径口径历史上变过（早期版本去掉了盘符却留下
    `data/repos/<hash>/` 前缀，宽松指纹则连盘符一起留着）。拿这些旧写法去比
    新算出来的归一化指纹必然对不上，用户标过的误报会重新冒出来。读取时统一
    纠正，等价于对历史数据做一次原地迁移，不需要动数据库。

    指纹格式为 `tool|rule_id|path|...`，路径固定在第 3 段。
    """
    text = raw or ""
    parts = text.split("|")
    if len(parts) < 3:
        return text
    parts[2] = _normalize_path(parts[2])
    return "|".join(parts)


async def _apply_project_suppressions(session: AsyncSession, scan: ScanTask) -> tuple[int, int]:
    if not scan.project_id:
        return 0, 0
    suppressions = (
        await session.execute(
            select(ProjectSuppression).where(ProjectSuppression.project_id == scan.project_id)
        )
    ).scalars().all()
    suppressions = [s for s in suppressions if not _suppression_expired(s)]
    if not suppressions:
        return 0, 0
    by_strict: dict[str, ProjectSuppression] = {}
    by_relaxed: dict[str, ProjectSuppression] = {}
    for s in suppressions:
        if s.fingerprint_strict:
            by_strict[_canonical_suppression_fingerprint(s.fingerprint_strict)] = s
        if s.fingerprint_relaxed:
            by_relaxed[_canonical_suppression_fingerprint(s.fingerprint_relaxed)] = s
    findings = (
        await session.execute(select(Finding).where(Finding.scan_id == scan.id))
    ).scalars().all()
    strict_hits = 0
    relaxed_hits = 0
    for finding in findings:
        strict = finding_fingerprint(finding)
        relaxed = _relaxed_fingerprint_for_finding(finding)
        hit = by_strict.get(strict)
        if hit:
            finding.review_status = ReviewStatus.FALSE_POSITIVE
            finding.review_note = _suppression_note(hit.status, hit.reason)
            strict_hits += 1
            continue
        hit = by_relaxed.get(relaxed)
        if hit:
            finding.ai_verdict = AiVerdict.FALSE_POSITIVE
            finding.ai_reason = f"疑似{_suppression_note(hit.status, hit.reason)}"
            relaxed_hits += 1
    return strict_hits, relaxed_hits


async def list_project_suppressions(
    session: AsyncSession,
    project_id: int,
    *,
    include_expired: bool = False,
) -> list[ProjectSuppression]:
    """项目白名单 / 误报库列表；默认不返回已过期条目。"""
    rows = (
        await session.execute(
            select(ProjectSuppression)
            .where(ProjectSuppression.project_id == project_id)
            .order_by(ProjectSuppression.created_at.desc(), ProjectSuppression.id.desc())
        )
    ).scalars().all()
    if include_expired:
        return list(rows)
    return [r for r in rows if not _suppression_expired(r)]


async def whitelist_finding(
    session: AsyncSession,
    *,
    project_id: int,
    finding_id: int,
    reason: str,
    created_by: str | None = None,
) -> ProjectSuppression:
    """把一条漏洞显式加入项目白名单，之后该项目的新扫描不再上报它。

    当前扫描里的这条也立刻按白名单处理（标为误报 + 说明），
    否则用户会看到「明明加了白，列表里还在」。
    """
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("加入白名单必须填写原因")
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise ValueError("漏洞不存在")
    scan = await session.get(ScanTask, finding.scan_id)
    if not scan or scan.project_id != project_id:
        raise ValueError("该漏洞不属于当前项目")

    row = await _upsert_project_suppression(
        session,
        project_id=project_id,
        finding=finding,
        reason=reason,
        created_by=created_by,
        status=SUPPRESSION_STATUS_WHITELIST,
    )
    finding.review_status = ReviewStatus.FALSE_POSITIVE
    finding.review_note = _suppression_note(SUPPRESSION_STATUS_WHITELIST, reason)
    finding.reviewed_at = datetime.now(timezone.utc)

    # 用同一个 session 写事件（_log_event 会另开真实库 session，不便测试也不便保持原子性）
    session.add(
        ScanEvent(
            scan_id=finding.scan_id,
            level="info",
            phase="whitelist",
            message=f"加入白名单 #{finding_id}: {reason[:120]}",
        )
    )

    await session.commit()
    await session.refresh(row)
    return row


async def delete_project_suppression(
    session: AsyncSession,
    *,
    project_id: int,
    suppression_id: int,
) -> bool:
    """删除一条白名单/误报库条目。

    注意：**不会**回滚历史扫描里已经被它抑制掉的 finding 标记；
    重新跑一次扫描即可按最新白名单重新判定。
    """
    row = await session.get(ProjectSuppression, suppression_id)
    if not row or row.project_id != project_id:
        return False
    await session.delete(row)
    await session.commit()
    return True


async def _maybe_send_scan_report_email(scan_id: int) -> None:
    if not smtp_configured():
        return
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan or not _should_send_html_report(scan):
            return
        emails = _load_notify_emails(scan)
        if not emails:
            return
        spec = _email_report_spec(scan)
        scope_hint = ""
        if spec is not None and spec.filters is not None and spec.filters.severity:
            scope_hint = f"（仅 {'/'.join(spec.filters.severity)}）"
        try:
            html = await build_scan_html_report(session, scan_id, spec)
        except Exception as exc:
            logger.warning("Build HTML report failed for scan %s: %s", scan_id, exc)
            return
        failures: list[str] = []
        for email in emails:
            try:
                await send_html_email(
                    to_email=email,
                    subject=f"AI Audit 扫描报告 #{scan.id} - {scan.name}{scope_hint}",
                    html_body=html,
                )
            except Exception as exc:
                failures.append(f"{email}: {exc}")
        if failures:
            await _log_event(
                scan_id,
                "邮件通知部分失败：" + "；".join(failures[:10]),
                phase="email_notify",
                level="warning",
                tool="email",
            )
        else:
            await _log_event(
                scan_id,
                f"已发送 HTML 报告邮件：{', '.join(emails)}",
                phase="email_notify",
                tool="email",
            )


def _resolved_severity(item: dict, classification: dict[str, str]) -> Severity:
    raw = item.get("severity", "UNKNOWN")
    if isinstance(raw, Severity):
        raw = raw.value
    adjusted = adjust_severity(
        str(raw),
        vuln_subtype=classification.get("vuln_subtype"),
        owasp_id=classification.get("owasp_id"),
    )
    return Severity(adjusted) if adjusted in Severity.__members__ else Severity.UNKNOWN


async def _update_scan(session: AsyncSession, scan: ScanTask, **kwargs) -> None:
    for key, value in kwargs.items():
        setattr(scan, key, value)
    scan.updated_at = datetime.now(timezone.utc)
    if kwargs.get("status") == ScanStatus.COMPLETED:
        try:
            from app.services.score_service import apply_score_fields

            await apply_score_fields(session, scan.id)
        except Exception as exc:
            logger.warning("Failed to compute security score for scan %s: %s", scan.id, exc)
    await session.commit()
    await session.refresh(scan)


_ARCHIVE_BLOCK_STATUSES = {ScanStatus.SCANNING, ScanStatus.ANALYZING, ScanStatus.LLM_AUDITING}


async def update_scan_metadata(
    session: AsyncSession,
    scan_id: int,
    *,
    name: str | None = None,
    notes: str | None = None,
) -> ScanTask | None:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return None
    updates: dict = {}
    if name is not None:
        trimmed = name.strip()
        if not trimmed or len(trimmed) > 255:
            raise ValueError("invalid name")
        updates["name"] = trimmed
    if notes is not None:
        trimmed_notes = notes.strip() if notes else None
        if trimmed_notes and len(trimmed_notes) > 2000:
            raise ValueError("notes too long")
        updates["notes"] = trimmed_notes or None
    if not updates:
        return scan
    await _update_scan(session, scan, **updates)
    return scan


async def set_scan_archived(
    session: AsyncSession,
    scan_id: int,
    *,
    archived: bool,
) -> ScanTask | None:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return None
    if archived:
        if scan.status in _ARCHIVE_BLOCK_STATUSES:
            raise ValueError("cannot archive active scan")
        await _update_scan(session, scan, archived_at=datetime.now(timezone.utc))
    else:
        await _update_scan(session, scan, archived_at=None)
    return scan


async def _log_event(
    scan_id: int,
    message: str,
    *,
    level: str = "info",
    phase: str | None = None,
    tool: str | None = None,
    file_path: str | None = None,
) -> None:
    async with async_session() as s:
        s.add(
            ScanEvent(
                scan_id=scan_id,
                level=level,
                phase=phase,
                tool=tool,
                file_path=file_path,
                message=message,
            )
        )
        await s.commit()


async def _feishu_phase_sent(scan_id: int, phase: str) -> bool:
    async with async_session() as session:
        count = (
            await session.execute(
                select(func.count()).select_from(ScanEvent).where(
                    ScanEvent.scan_id == scan_id,
                    ScanEvent.phase == phase,
                )
            )
        ).scalar() or 0
        return count > 0


async def _notify_feishu_scan_started(scan_id: int) -> None:
    if await _feishu_phase_sent(scan_id, "feishu_notify_scan_start"):
        return
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return
        project = await session.get(Project, scan.project_id) if scan.project_id else None
        kind = scan.scan_kind.value if hasattr(scan.scan_kind, "value") else str(scan.scan_kind)
        source = scan.source.value if hasattr(scan.source, "value") else str(scan.source)
        sent = await asyncio.to_thread(
            send_feishu_scan_started,
            scan_id=scan.id,
            scan_name=scan.name,
            project_id=scan.project_id,
            project_name=project.name if project else None,
            source=source,
            scan_kind=kind,
            version_label=scan.version_label,
            branch=scan.branch,
            source_url=scan.source_url,
            enabled_scanners=list(settings.enabled_scanners or []),
        )
        if sent:
            await _log_event(scan_id, "已发送飞书「扫描开始」通知", phase="feishu_notify_scan_start", tool="feishu")


async def _notify_feishu_scan_completed(
    scan_id: int,
    *,
    failed: bool = False,
    error_message: str | None = None,
) -> None:
    if await _feishu_phase_sent(scan_id, "feishu_notify_scan_complete"):
        return
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return
        project = await session.get(Project, scan.project_id) if scan.project_id else None
        stats = await get_scan_stats(session, scan_id)
        sent = await asyncio.to_thread(
            send_feishu_scan_completed,
            scan_id=scan.id,
            scan_name=scan.name,
            project_id=scan.project_id,
            project_name=project.name if project else None,
            stats=stats,
            failed=failed,
            error_message=error_message or scan.error_message,
        )
        if sent:
            label = "扫描失败" if failed else "扫描完成"
            await _log_event(
                scan_id,
                f"已发送飞书「{label}」通知（共 {stats.get('total', 0)} 条漏洞）",
                phase="feishu_notify_scan_complete",
                tool="feishu",
            )
    try:
        await _maybe_send_scan_report_email(scan_id)
    except Exception as exc:
        logger.warning("Scan report email failed for scan %s: %s", scan_id, exc)


async def _load_known_suppressions_for_llm(session: AsyncSession, project_id: int) -> list[dict]:
    rows = (
        await session.execute(
            select(ProjectSuppression).where(ProjectSuppression.project_id == project_id).limit(50)
        )
    ).scalars().all()
    return [
        {
            "rule_id": row.rule_id,
            "file_path": row.file_path,
            "reason": row.reason,
            "fingerprint_relaxed": row.fingerprint_relaxed,
        }
        for row in rows
    ]


async def _save_llm_audit_findings(session: AsyncSession, scan_id: int, items: list[dict]) -> tuple[int, int]:
    """Persist new LLM findings; skip duplicates already in this scan. Returns (added, skipped)."""
    if not items:
        return 0, 0

    items, skipped_tests = filter_out_test_findings(items)
    if skipped_tests:
        logger.info("LLM audit skipped %s findings under test paths (scan_id=%s)", skipped_tests, scan_id)
    if not items:
        return 0, skipped_tests

    existing = (
        await session.execute(
            select(Finding).where(Finding.scan_id == scan_id, Finding.tool == "llm")
        )
    ).scalars().all()

    to_save, skipped = filter_new_llm_findings(items, existing)
    skipped += skipped_tests
    if not to_save:
        return 0, skipped

    scan = await session.get(ScanTask, scan_id)
    project_path = scan.project_path if scan else None

    for item in to_save:
        sev = item["severity"]
        if not isinstance(sev, Severity):
            sev = Severity(sev) if sev in Severity.__members__ else Severity.MEDIUM
        cat = item["category"]
        if not isinstance(cat, FindingCategory):
            cat = FindingCategory(cat) if cat in [c.value for c in FindingCategory] else FindingCategory.BUSINESS_LOGIC

        classification = _classification_fields({**item, "category": cat.value, "tool": item.get("tool", "llm")})
        finding = Finding(
            scan_id=scan_id,
            rule_id=item["rule_id"],
            severity=_resolved_severity(item, classification),
            message=item["message"],
            file_path=_stored_file_path(item.get("file_path"), project_path),
            line_start=item.get("line_start", 0),
            line_end=item.get("line_end", 0),
            code_snippet=item.get("code_snippet"),
            metadata_json=item.get("metadata_json"),
            tool=item.get("tool", "llm"),
            category=cat,
            ai_verdict=item.get("ai_verdict", AiVerdict.REAL_VULN),
            ai_reason=item.get("ai_reason"),
            ai_confidence=item.get("ai_confidence"),
            **classification,
        )
        session.add(finding)
    await session.commit()
    return len(to_save), skipped


def _count_project_files(root: Path) -> int:
    try:
        return sum(1 for p in root.rglob("*") if p.is_file())
    except Exception:
        return 0


async def run_llm_audit_pipeline(
    scan_id: int,
    categories: list[FindingCategory] | None = None,
) -> int:
    clear_llm_audit_cancel(scan_id)
    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return 0

        project_path = Path(scan.project_path)
        added = 0
        skipped = 0
        try:
            kind = scan.scan_kind
            kind_value = kind.value if hasattr(kind, "value") else str(kind or "")
            if kind_value == ScanKind.RETEST.value and scan.parent_scan_id:
                from app.services.retest_service import run_llm_verify_on_retest_scan

                await _log_event(
                    scan_id,
                    "当前为复测任务，改为核实上次 LLM 发现是否已修复（不跑发现式端点审计）",
                    phase="llm",
                )
                return await run_llm_verify_on_retest_scan(scan_id)

            await _update_scan(
                session,
                scan,
                status=ScanStatus.LLM_AUDITING,
                progress=5,
                progress_message="LLM 端点审计：准备中…",
                error_message=None,
            )
            await _log_event(scan_id, "开始 LLM 端点驱动深度审计", phase="llm")
            if scan.progress_message and "恢复" in scan.progress_message:
                await _log_event(
                    scan_id,
                    "服务重启后自动恢复 LLM 端点审计",
                    level="warning",
                    phase="llm",
                )

            async def on_llm_progress(
                batch_no: int,
                total_batch: int,
                files: list[str],
                unit=None,
            ) -> None:
                pct = 5 + int((batch_no / max(total_batch, 1)) * 90)
                async with async_session() as s:
                    sc = await s.get(ScanTask, scan_id)
                    if sc:
                        await _update_scan(
                            s,
                            sc,
                            progress=min(95, pct),
                            progress_message=(files[0] if files else f"端点审计 验证第 {batch_no} 轮"),
                        )

            items = await run_llm_code_audit(
                project_path,
                categories,
                on_llm_progress,
                scan_id=scan_id,
            )
            added, skipped = await _save_llm_audit_findings(session, scan_id, items)
            cancelled = is_llm_audit_cancel_requested(scan_id)
            cat_counts: dict[str, int] = {}
            for item in items:
                cat = str(item.get("category", "unknown"))
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_summary = ", ".join(f"{k}:{v}" for k, v in cat_counts.items()) or "无"
            complete_detail = f"分类统计: {cat_summary}"
            if not cancelled and added == 0 and not items:
                complete_detail += "（触顶或未产出结构化 findings；见「触顶收尾汇总」日志）"
            elif not cancelled and added > 0:
                complete_detail += f"；已入库 {added} 条"
            await log_llm_audit_journal(
                scan_id,
                "complete" if not cancelled else "cancelled",
                {
                    "title": "审计已暂停" if cancelled else "审计完成",
                    "added": added,
                    "skipped_duplicates": skipped,
                    "by_category": cat_counts,
                    "detail": complete_detail,
                },
                level="warning" if cancelled else "info",
            )
            if cancelled:
                await _log_event(scan_id, "LLM 端点审计已暂停", level="warning", phase="llm")
            elif skipped:
                await _log_event(
                    scan_id,
                    f"LLM 深度审计完成，新增 {added} 条，跳过重复 {skipped} 条",
                    phase="llm",
                )
            else:
                await _log_event(scan_id, f"LLM 深度审计完成，新增 {added} 条", phase="llm")

            scan = await session.get(ScanTask, scan_id)
            if scan:
                count_stmt = select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
                total = (await session.execute(count_stmt)).scalar() or 0
                if cancelled:
                    progress_msg = f"LLM 端点审计已暂停（已新增 {added} 条）"
                else:
                    fallback_used = (
                        (
                            await session.execute(
                                select(func.count()).select_from(ScanEvent).where(
                                    ScanEvent.scan_id == scan_id,
                                    ScanEvent.phase == "llm",
                                    ScanEvent.message.like("%自动切换文件采样审计%"),
                                )
                            )
                        ).scalar()
                        or 0
                    ) > 0
                    progress_msg = (
                        f"LLM 端点审计完成，新增 {added} 条，跳过重复 {skipped} 条"
                        if skipped
                        else (
                            "端点审计未命中，已自动切换文件审计并完成"
                            if fallback_used and added == 0
                            else (
                                f"LLM 端点审计完成，新增 {added} 条发现"
                                if added
                                else "LLM 端点审计完成，未发现新漏洞（若迭代轮次过少，请调高设置后重试）"
                            )
                        )
                    )
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.COMPLETED,
                    progress=100,
                    progress_message=progress_msg,
                    error_message=None,
                    total_findings=total,
                    completed_at=datetime.now(timezone.utc) if not cancelled else None,
                )
                # Feishu notification (MVP): only once per scan for LLM stage.
                if not cancelled:
                    try:
                        already = (
                            await session.execute(
                                select(func.count()).select_from(ScanEvent).where(
                                    ScanEvent.scan_id == scan_id,
                                    ScanEvent.phase == "feishu_notify_llm",
                                )
                            )
                        ).scalar() or 0
                        if already == 0:
                            stmt = (
                                select(Finding)
                                .where(
                                    Finding.scan_id == scan_id,
                                    Finding.review_status == ReviewStatus.UNREVIEWED,
                                    Finding.severity.in_([Severity.HIGH, Severity.CRITICAL]),
                                    Finding.tool == "llm",
                                )
                                .limit(8)
                            )
                            rows = (await session.execute(stmt)).scalars().all()
                            for f in rows:
                                await asyncio.to_thread(
                                    send_feishu_finding_notification,
                                    scan_id=scan_id,
                                    finding=f,
                                    extra_text="LLM发现",
                                )
                            if rows:
                                await _log_event(
                                    scan_id,
                                    f"已触发飞书通知: {len(rows)} 条（LLM）",
                                    phase="feishu_notify_llm",
                                    tool="feishu",
                                )
                    except Exception as exc:
                        logger.warning("Feishu notify (LLM) failed: %s", exc)
            return added
        except LlmAuditCancelled:
            await log_llm_audit_journal(
                scan_id,
                "cancelled",
                {
                    "title": "审计已暂停",
                    "added": 0,
                    "skipped_duplicates": 0,
                    "detail": "已收到暂停请求，任务在安全检查点停止。",
                },
                level="warning",
            )
            await _log_event(scan_id, "LLM 端点审计已暂停", level="warning", phase="llm")
            scan = await session.get(ScanTask, scan_id)
            if scan:
                count_stmt = select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
                total = (await session.execute(count_stmt)).scalar() or 0
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.COMPLETED,
                    progress=100,
                    progress_message="LLM 端点审计已暂停",
                    error_message=None,
                    total_findings=total,
                    completed_at=None,
                )
            return 0
        except Exception as exc:
            logger.exception("LLM audit pipeline failed for scan %s", scan_id)
            await log_llm_audit_journal(
                scan_id,
                "error",
                {"title": "审计失败", "detail": str(exc)[:800]},
                level="error",
            )
            await _log_event(scan_id, f"LLM 深度审计失败: {exc}", level="error", phase="llm")
            scan = await session.get(ScanTask, scan_id)
            if scan:
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.FAILED,
                    error_message=str(exc)[:2000],
                    progress_message=f"LLM 深度审计失败: {str(exc)[:500]}",
                )
            return 0
        finally:
            clear_llm_audit_cancel(scan_id)


def _stale_restart_message_for_scan(*, prior_status: ScanStatus, progress_message: str | None) -> str:
    """User-facing hint after restart; SAST results are kept where possible."""
    msg = progress_message or ""
    if prior_status == ScanStatus.LLM_AUDITING or "LLM" in msg or "端点" in msg:
        return "LLM 端点审计因服务重启中断，请重新发起端点审计"
    if "深度" in msg or ("研判" in msg and "误报" not in msg):
        return "深度研判因服务重启中断，请重新点击「漏洞研判」"
    if "误报" in msg:
        return "误报审计因服务重启中断，可重新发起误报审计"
    return "后台任务因服务重启中断，请按需重新发起"


STALE_RESTART_ERROR = (
    "扫描超时或服务重启导致任务中断，请点击「开始 SAST 扫描」或「重新扫描」重试"
)


@dataclass
class StaleScanRecovery:
    reconciled: int = 0
    sast_resume_ids: list[int] = field(default_factory=list)
    llm_resume_ids: list[int] = field(default_factory=list)


async def _llm_audit_finished(session: AsyncSession, scan_id: int) -> bool:
    count = (
        await session.execute(
            select(func.count()).select_from(ScanEvent).where(
                ScanEvent.scan_id == scan_id,
                ScanEvent.phase == "llm",
                or_(
                    ScanEvent.message.like("%LLM 端点审计完成%"),
                    ScanEvent.message.like("%LLM 深度审计完成%"),
                    ScanEvent.message.like("%LLM 端点审计已暂停%"),
                ),
            )
        )
    ).scalar() or 0
    return int(count) > 0


async def _scan_resume_target(session: AsyncSession, scan: ScanTask) -> str | None:
    """Return 'sast', 'llm', or None when nothing can be resumed."""
    if not scan.project_path or not Path(scan.project_path).is_dir():
        return None

    sast_count = (
        await session.execute(
            select(func.count()).select_from(Finding).where(
                Finding.scan_id == scan.id,
                Finding.category == FindingCategory.SAST,
            )
        )
    ).scalar() or 0
    if int(sast_count) == 0:
        return "sast"

    if settings.llm_code_audit_enabled and is_llm_configured():
        if not await _llm_audit_finished(session, scan.id):
            return "llm"
    return None


async def recover_stale_scans() -> StaleScanRecovery:
    """Reconcile in-flight scans after server restart; schedule auto-resume where possible."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.scan_stale_minutes)
    resume_on_restart = [ScanStatus.CLONING, ScanStatus.SCANNING, ScanStatus.LLM_AUDITING]
    complete_on_restart = [ScanStatus.ANALYZING]
    stale_pending = [ScanStatus.PENDING]
    result = StaleScanRecovery()

    async with async_session() as session:
        stmt = select(ScanTask).where(ScanTask.status.in_(resume_on_restart))
        for scan in (await session.execute(stmt)).scalars().all():
            target = await _scan_resume_target(session, scan)
            if target == "sast":
                scan.status = ScanStatus.SCANNING
                scan.error_message = None
                scan.progress = max(scan.progress or 0, 5)
                scan.progress_message = "服务重启后正在恢复 SAST 扫描…"
                result.sast_resume_ids.append(scan.id)
            elif target == "llm":
                scan.status = ScanStatus.LLM_AUDITING
                scan.error_message = None
                scan.progress_message = "服务重启后正在恢复 LLM 端点审计…"
                result.llm_resume_ids.append(scan.id)
            else:
                scan.status = ScanStatus.FAILED
                scan.error_message = STALE_RESTART_ERROR
                scan.progress_message = "任务已中断（服务已重启）"
            result.reconciled += 1

        stmt = select(ScanTask).where(ScanTask.status.in_(complete_on_restart))
        for scan in (await session.execute(stmt)).scalars().all():
            prior = scan.status
            prior_msg = scan.progress_message
            scan.status = ScanStatus.COMPLETED
            scan.error_message = None
            scan.progress_message = _stale_restart_message_for_scan(
                prior_status=prior,
                progress_message=prior_msg,
            )
            if prior_msg and (
                "深度" in prior_msg or ("研判" in prior_msg and "误报" not in prior_msg)
            ):
                scan.progress = 100
            else:
                scan.progress = max(scan.progress or 0, 75)
            result.reconciled += 1

        stmt = select(ScanTask).where(
            ScanTask.status == ScanStatus.FAILED,
            ScanTask.error_message == STALE_RESTART_ERROR,
        )
        for scan in (await session.execute(stmt)).scalars().all():
            target = await _scan_resume_target(session, scan)
            if target == "sast":
                scan.status = ScanStatus.SCANNING
                scan.error_message = None
                scan.progress = max(scan.progress or 0, 5)
                scan.progress_message = "服务重启后正在恢复 SAST 扫描…"
                result.sast_resume_ids.append(scan.id)
            elif target == "llm":
                scan.status = ScanStatus.LLM_AUDITING
                scan.error_message = None
                scan.progress_message = "服务重启后正在恢复 LLM 端点审计…"
                result.llm_resume_ids.append(scan.id)
            else:
                finding_count = int(
                    (
                        await session.execute(
                            select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)
                        )
                    ).scalar()
                    or 0
                )
                if finding_count <= 0:
                    continue
                scan.status = ScanStatus.COMPLETED
                scan.error_message = None
                scan.progress_message = _stale_restart_message_for_scan(
                    prior_status=ScanStatus.ANALYZING,
                    progress_message=scan.progress_message,
                )
                scan.progress = 100
            result.reconciled += 1

        stmt = select(ScanTask).where(
            ScanTask.status == ScanStatus.COMPLETED,
            ScanTask.error_message == STALE_RESTART_ERROR,
        )
        for scan in (await session.execute(stmt)).scalars().all():
            scan.error_message = None
            result.reconciled += 1

        stmt_pending = select(ScanTask).where(
            ScanTask.status.in_(stale_pending),
            ScanTask.updated_at < cutoff,
        )
        for scan in (await session.execute(stmt_pending)).scalars().all():
            scan.status = ScanStatus.FAILED
            scan.error_message = "扫描超时或服务重启导致任务中断，请点击「重新扫描」重试"
            scan.progress_message = "任务已中断"
            result.reconciled += 1

        if result.reconciled:
            await session.commit()
        return result


async def resume_interrupted_scans_after_restart() -> StaleScanRecovery:
    """Recover DB rows and relaunch pipelines killed by process restart."""
    from app.services.scan_runtime import launch_llm_audit_pipeline, launch_sast_pipeline

    recovery = await recover_stale_scans()
    for scan_id in recovery.sast_resume_ids:
        try:
            await start_scan_task(scan_id, source="auto_resume")
            launch_sast_pipeline(scan_id)
            logger.info("Auto-resumed SAST pipeline for scan_id=%s", scan_id)
        except Exception:
            logger.exception("Auto-resume SAST failed for scan_id=%s", scan_id)
    for scan_id in recovery.llm_resume_ids:
        launch_llm_audit_pipeline(scan_id)
        logger.info("Auto-resumed LLM audit pipeline for scan_id=%s", scan_id)
    return recovery


async def _complete_pause_scan(scan_id: int, *, reason: str = "用户已暂停扫描") -> None:
    """Mark scan paused in DB (does not check whether a pipeline task is still registered)."""
    from app.services.scan_runtime import clear_scan_cancel

    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return
        if scan.status not in (ScanStatus.SCANNING, ScanStatus.ANALYZING, ScanStatus.LLM_AUDITING):
            return
        total = (
            await session.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )
        ).scalar() or 0
        await _update_scan(
            session,
            scan,
            status=ScanStatus.COMPLETED,
            progress=100,
            progress_message=f"扫描已暂停（保留 {total} 条发现）",
            total_findings=total,
            error_message=None,
        )

    try:
        from app.services.scanners.semgrep import kill_active_semgrep_processes

        await asyncio.to_thread(kill_active_semgrep_processes)
    except Exception:
        logger.debug("Semgrep kill on pause failed for scan_id=%s", scan_id, exc_info=True)

    await _log_event(scan_id, reason, level="warning", phase="scan")
    clear_scan_cancel(scan_id)


async def force_pause_scan(scan_id: int, *, reason: str = "用户已暂停扫描") -> bool:
    """Immediately mark scan paused when no in-process pipeline is running (zombie rows)."""
    from app.services.scan_runtime import is_scan_pipeline_active

    if is_scan_pipeline_active(scan_id):
        return False
    await _complete_pause_scan(scan_id, reason=reason)
    return True


async def run_scan_pipeline(scan_id: int) -> None:
    from app.services.scan_runtime import clear_scan_cancel, is_scan_cancel_requested

    try:
        if is_scan_cancel_requested(scan_id):
            await _complete_pause_scan(scan_id)
            return
        clear_scan_cancel(scan_id)
        await _run_scan_pipeline_inner(scan_id)
    except asyncio.CancelledError:
        logger.info("Scan pipeline asyncio task cancelled for scan_id=%s", scan_id)
        await _complete_pause_scan(scan_id, reason="用户已暂停扫描")
    except Exception as exc:
        logger.exception("Scan pipeline crashed for scan %s", scan_id)
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan and scan.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.FAILED,
                    error_message=str(exc),
                    progress_message="扫描失败",
                )
    finally:
        clear_scan_cancel(scan_id)


async def start_scan_task(scan_id: int, *, source: str = "manual") -> None:
    from app.services.scan_runtime import is_scan_pipeline_active

    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            raise ValueError("扫描任务不存在")

        # Allow SAST after LLM-only audit, and reclaim zombie rows left by process restart
        # (DB still says scanning but no in-process pipeline exists).
        reclaimable = (
            ScanStatus.SCANNING,
            ScanStatus.ANALYZING,
            ScanStatus.CLONING,
        )
        if scan.status in reclaimable and is_scan_pipeline_active(scan_id):
            raise ValueError("SAST 扫描正在进行中，请先暂停或等待结束后再试")
        if scan.status == ScanStatus.LLM_AUDITING:
            raise ValueError("LLM 端点审计进行中，请先暂停后再启动 SAST")
        if scan.status not in (
            ScanStatus.PENDING,
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            *reclaimable,
        ):
            raise ValueError("当前状态不可开始 SAST 扫描")

        was_zombie = scan.status in reclaimable and not is_scan_pipeline_active(scan_id)
        clear_scan_cancel(scan_id)
        clear_llm_audit_cancel(scan_id)

        deleted_sast = 0
        llm_left: int | None = None
        # Replacing SAST results only — keep LLM endpoint findings / journals.
        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED) or was_zombie:
            result = await session.execute(
                delete(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.category == FindingCategory.SAST,
                )
            )
            deleted_sast = int(result.rowcount or 0)
            llm_left = (
                await session.execute(
                    select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
                )
            ).scalar() or 0

        update_kwargs: dict = {
            "status": ScanStatus.SCANNING,
            "progress": 5,
            "progress_message": "SAST 扫描启动中…",
            "error_message": None,
        }
        if llm_left is not None:
            update_kwargs.update(
                total_findings=llm_left,
                semgrep_version=None,
                scanner_summary=None,
                completed_at=None,
            )
        await _update_scan(session, scan, **update_kwargs)
        if was_zombie:
            await _log_event(
                scan_id,
                "检测到中断的扫描状态（服务曾重启），已重新开始 SAST",
                level="warning",
                phase="prepare",
            )
        if deleted_sast:
            await _log_event(
                scan_id,
                f"开始 SAST 前清除旧 SAST 发现 {deleted_sast} 条（保留 LLM 发现）",
                phase="prepare",
            )
        if source == "webhook":
            await _log_event(scan_id, "Webhook/Jenkins 触发 SAST 扫描", phase="prepare")
        elif source == "auto_resume":
            await _log_event(
                scan_id,
                "服务重启后自动恢复 SAST 扫描",
                level="warning",
                phase="prepare",
            )
        else:
            await _log_event(scan_id, "用户手动开始 SAST 扫描", phase="prepare")


async def _finish_scan_paused(
    scan_id: int,
    all_findings: list[dict],
    scanner_summary: list[dict],
    semgrep_version: str | None,
) -> None:
    all_findings, skipped_tests = filter_out_test_findings(all_findings)
    if skipped_tests:
        await _log_event(
            scan_id,
            f"已跳过 {skipped_tests} 条测试路径发现",
            phase="persist",
        )

    all_findings, skipped_same, skipped_cross = dedupe_sast_findings(all_findings)
    if skipped_same or skipped_cross:
        await _log_event(
            scan_id,
            f"已按指纹去重：同工具 {skipped_same} 条，跨工具合并 {skipped_cross} 条",
            phase="persist",
        )

    tool_counts: dict[str, int] = {}
    for f in all_findings:
        tool_counts[f.get("tool", "?")] = tool_counts.get(f.get("tool", "?"), 0) + 1
    summary_text = ", ".join(f"{k}:{v}" for k, v in tool_counts.items()) or "无发现"

    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            return
        await _update_scan(
            session,
            scan,
            progress=60,
            progress_message=f"扫描已暂停（{summary_text}），正在保存已完成的发现…",
            semgrep_version=semgrep_version,
            scanner_summary=json.dumps(scanner_summary, ensure_ascii=False),
        )
        existing_sast = (
            await session.execute(
                select(func.count()).select_from(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.category == FindingCategory.SAST,
                )
            )
        ).scalar() or 0
        if existing_sast == 0:
            for item in all_findings:
                classification = _classification_fields(item)
                session.add(Finding(
                    scan_id=scan_id,
                    rule_id=item["rule_id"],
                    check_id=item.get("check_id"),
                    severity=_resolved_severity(item, classification),
                    message=item["message"],
                    file_path=_stored_file_path(item.get("file_path"), scan.project_path),
                    line_start=item["line_start"],
                    line_end=item["line_end"],
                    code_snippet=item.get("code_snippet"),
                    metadata_json=item.get("metadata_json"),
                    tool=item.get("tool", "semgrep"),
                    category=FindingCategory.SAST,
                    **classification,
                ))
            await session.commit()
            await _log_event(scan_id, f"暂停前入库: {len(all_findings)} 条", phase="persist")

        scan = await session.get(ScanTask, scan_id)
        if scan:
            total = (await session.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )).scalar() or 0
            await _update_scan(
                session,
                scan,
                status=ScanStatus.COMPLETED,
                progress=100,
                progress_message=f"扫描已暂停（保留 {total} 条发现）",
                total_findings=total,
            )
    await _log_event(scan_id, "用户暂停扫描", level="warning", phase="scan")


async def _run_scan_pipeline_inner(scan_id: int) -> None:
    project_path: Path | None = None
    forced_langs: list[str] = []
    forced_token = None

    async with async_session() as session:
        scan = await session.get(ScanTask, scan_id)
        if not scan:
            logger.error("Scan pipeline aborted: scan_id=%s not found in database", scan_id)
            return
        project_path = Path(scan.project_path)
        scan_kind_value = scan.scan_kind.value if hasattr(scan.scan_kind, "value") else str(scan.scan_kind or "")
        if scan.project_id:
            project = await session.get(Project, scan.project_id)
            if project:
                forced_langs = parse_scan_languages_json(project.scan_languages_json)
        if not project_path.is_dir():
            await _update_scan(
                session,
                scan,
                status=ScanStatus.FAILED,
                error_message=f"项目目录不存在: {project_path}",
                progress_message="扫描失败：代码目录缺失",
            )
            await _log_event(
                scan_id,
                f"扫描失败：项目目录不存在 {project_path}",
                level="error",
                phase="prepare",
            )
            return

    forced_token = set_forced_scan_languages(forced_langs or None)

    async def on_scanner_progress(name: str, idx: int, total: int, event: str | None = None) -> None:
        pct = 30 + int((idx / max(total, 1)) * 28)
        if event and event.startswith("running:"):
            msg = f"正在运行 {name}（{idx + 1}/{total}，{event.replace('running:', '')}）..."
        else:
            msg = f"正在运行 {name}（{idx + 1}/{total}）..."
        async with async_session() as s:
            sc = await s.get(ScanTask, scan_id)
            if sc:
                await _update_scan(
                    s,
                    sc,
                    status=ScanStatus.SCANNING,
                    progress=pct,
                    progress_message=msg,
                )
        if event and event.startswith("running:"):
            await _log_event(
                scan_id,
                f"{name} 扫描中：已运行 {event.replace('running:', '')}",
                phase="scan",
                tool=name,
            )
        else:
            await _log_event(scan_id, f"开始扫描器 {name}（{idx + 1}/{total}）", phase="scan", tool=name)
            if name.lower() == "semgrep" and project_path:
                plan = await asyncio.to_thread(plan_semgrep_scan, project_path)
                cmd = build_semgrep_command(plan, project_path)
                await _log_event(
                    scan_id,
                    f"Semgrep 规则: {', '.join(plan.configs)}（{plan.config_reason}），源码 {plan.source_file_count} 文件，超时 {plan.wall_timeout}s",
                    phase="scan",
                    tool="semgrep",
                )
                await _log_event(
                    scan_id,
                    f"Semgrep 命令: {' '.join(cmd)}",
                    phase="scan",
                    tool="semgrep",
                )

    try:
        await _log_event(
            scan_id,
            f"扫描根目录: {project_path}",
            phase="prepare",
            file_path=str(project_path),
        )
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan:
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.SCANNING,
                    progress=30,
                    progress_message="正在运行多工具安全扫描...",
                )
        await _log_event(scan_id, "任务启动：进入多工具扫描阶段", phase="scan")
        try:
            await _notify_feishu_scan_started(scan_id)
        except Exception as exc:
            logger.warning("Feishu notify (scan start) failed: %s", exc)

        all_findings, run_results = await run_scanners(
            project_path, on_progress=on_scanner_progress, scan_id=scan_id,
        )

        scanner_summary: list[dict] = []
        semgrep_version = None
        for rr in run_results:
            entry = {
                "scanner": rr.scanner_id,
                "findings": len(rr.findings),
                "skipped": rr.skipped,
                "skip_reason": rr.skip_reason,
                "error": rr.error,
                "version": rr.version,
                "detail": rr.detail,
            }
            scanner_summary.append(entry)
            if rr.scanner_id == "semgrep" and rr.version:
                semgrep_version = rr.version
            if rr.error:
                await _log_event(
                    scan_id,
                    f"{rr.scanner_id} 失败: {rr.error}",
                    level="error",
                    phase="scan",
                    tool=rr.scanner_id,
                )
            elif rr.skipped:
                await _log_event(
                    scan_id,
                    f"{rr.scanner_id} 跳过: {rr.skip_reason or '未安装'}",
                    phase="scan",
                    tool=rr.scanner_id,
                )
            else:
                await _log_event(
                    scan_id,
                    f"{rr.scanner_id} 完成: {len(rr.findings)} 条",
                    phase="scan",
                    tool=rr.scanner_id,
                )
                if rr.scanner_id == "semgrep" and isinstance(rr.detail, dict):
                    inv = rr.detail.get("rule_inventory")
                    if isinstance(inv, dict):
                        from app.services.semgrep_rule_inventory import format_inventory_log_line

                        await _log_event(
                            scan_id,
                            format_inventory_log_line(inv),
                            phase="scan",
                            tool="semgrep",
                        )
                if rr.scanner_id == "codeql" and isinstance(rr.detail, dict) and rr.detail.get("degraded"):
                    hint = rr.detail.get("build_failure_hint") or rr.detail.get("warning") or ""
                    await _log_event(
                        scan_id,
                        f"codeql 已降级为无编译模式（none）"
                        + (f"：{hint}" if hint else "；数据流精度可能低于完整编译"),
                        level="warning",
                        phase="scan",
                        tool="codeql",
                    )
                if rr.scanner_id == "semgrep" and rr.detail:
                    scanned = rr.detail.get("scanned_paths_count")
                    result_count = rr.detail.get("result_count")
                    err_count = rr.detail.get("error_count")
                    elapsed = rr.detail.get("elapsed_seconds")
                    config_reason = rr.detail.get("config_reason")
                    source_count = rr.detail.get("source_file_count")
                    if config_reason:
                        extra = f"，源码文件 {source_count}" if source_count is not None else ""
                        await _log_event(
                            scan_id,
                            f"Semgrep 配置: {config_reason}{extra}",
                            phase="scan",
                            tool="semgrep",
                        )
                    cmd = rr.detail.get("command")
                    if cmd:
                        await _log_event(
                            scan_id,
                            f"Semgrep 命令: {cmd}",
                            phase="scan",
                            tool="semgrep",
                        )
                    await _log_event(
                        scan_id,
                        (
                            f"Semgrep 统计: 耗时={elapsed}s, 扫描文件={scanned if scanned is not None else 'unknown'}, "
                            f"命中={result_count}, 引擎错误={err_count}"
                        ),
                        phase="scan",
                        tool="semgrep",
                    )
                if rr.scanner_id == "codeql" and rr.detail:
                    await _log_event(
                        scan_id,
                        (
                            f"CodeQL 统计: mode={rr.detail.get('build_mode')}, suite={rr.detail.get('query_suite')}, "
                            f"耗时={rr.detail.get('elapsed_seconds')}s, Java文件={rr.detail.get('java_file_count')}, "
                            f"命中={rr.detail.get('result_count')}"
                        ),
                        phase="scan",
                        tool="codeql",
                    )

        if is_scan_cancel_requested(scan_id):
            await _finish_scan_paused(scan_id, all_findings, scanner_summary, semgrep_version)
            return

        all_findings, skipped_tests = filter_out_test_findings(all_findings)
        if skipped_tests:
            await _log_event(
                scan_id,
                f"已跳过 {skipped_tests} 条测试路径发现",
                phase="persist",
            )

        all_findings, skipped_same, skipped_cross = dedupe_sast_findings(all_findings)
        if skipped_same or skipped_cross:
            await _log_event(
                scan_id,
                f"已按指纹去重：同工具 {skipped_same} 条，跨工具合并 {skipped_cross} 条",
                phase="persist",
            )

        tool_counts: dict[str, int] = {}
        for f in all_findings:
            tool_counts[f.get("tool", "?")] = tool_counts.get(f.get("tool", "?"), 0) + 1
        summary_text = ", ".join(f"{k}:{v}" for k, v in tool_counts.items()) or "无发现"

        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if not scan:
                return

            await _update_scan(
                session,
                scan,
                progress=60,
                progress_message=f"扫描完成（{summary_text}），正在入库...",
                semgrep_version=semgrep_version,
                scanner_summary=json.dumps(scanner_summary, ensure_ascii=False),
            )
            await _log_event(scan_id, f"扫描阶段完成: {summary_text}", phase="scan")

            for item in all_findings:
                classification = _classification_fields(item)
                session.add(Finding(
                    scan_id=scan.id,
                    rule_id=item["rule_id"],
                    check_id=item.get("check_id"),
                    severity=_resolved_severity(item, classification),
                    message=item["message"],
                    file_path=_stored_file_path(item.get("file_path"), scan.project_path),
                    line_start=item["line_start"],
                    line_end=item["line_end"],
                    code_snippet=item.get("code_snippet"),
                    metadata_json=item.get("metadata_json"),
                    tool=item.get("tool", "semgrep"),
                    category=FindingCategory.SAST,
                    **classification,
                ))
            await session.commit()
            strict_hits, relaxed_hits = await _apply_project_suppressions(session, scan)
            if strict_hits or relaxed_hits:
                await session.commit()
                await _log_event(
                    scan_id,
                    f"项目抑制库匹配：严格继承 {strict_hits} 条，疑似重复 {relaxed_hits} 条",
                    phase="suppression",
                )
            await _log_event(scan_id, f"入库完成: {len(all_findings)} 条", phase="persist")
            if not settings.llm_enabled and not settings.llm_code_audit_enabled:
                await _log_event(
                    scan_id,
                    "SAST 扫描完成；误报审计与 LLM 端点审计请使用工具栏按钮手动触发",
                    phase="persist",
                )
            elif not settings.llm_enabled:
                await _log_event(
                    scan_id,
                    "SAST 扫描完成；可利用性研判请使用工具栏按钮手动触发",
                    phase="persist",
                )

        if is_scan_cancel_requested(scan_id):
            await _finish_scan_paused(scan_id, all_findings, scanner_summary, semgrep_version)
            return

        if settings.llm_enabled and is_llm_configured() and all_findings:
            async with async_session() as session:
                scan = await session.get(ScanTask, scan_id)
                if scan:
                    await _update_scan(
                        session,
                        scan,
                        status=ScanStatus.ANALYZING,
                        progress=75,
                        progress_message="误报审计：准备中",
                    )
                await _log_event(scan_id, "开始 SAST 误报审计", phase="llm_fp")

                stmt = (
                    select(Finding)
                    .where(Finding.scan_id == scan_id, Finding.category == FindingCategory.SAST)
                    .limit(50)
                )
                findings_db = (await session.execute(stmt)).scalars().all()
                findings_payload = [
                    {
                        "id": f.id,
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "message": f.message,
                        "file_path": f.file_path,
                        "line_start": f.line_start,
                        "code_snippet": f.code_snippet,
                    }
                    for f in findings_db
                ]
                await _log_event(
                    scan_id,
                    f"SAST 误报审计提交: {len(findings_payload)} 条",
                    phase="llm_fp",
                )
                scan = await session.get(ScanTask, scan_id)
                if scan:
                    await _update_scan(
                        session,
                        scan,
                        status=ScanStatus.ANALYZING,
                        progress=75,
                        progress_message=f"误报审计：准备中 / 已提交 {len(findings_payload)} 条",
                    )

            async def _fp_progress(message: str, percent: int) -> None:
                async with async_session() as session:
                    scan = await session.get(ScanTask, scan_id)
                    if scan:
                        await _update_scan(
                            session,
                            scan,
                            status=ScanStatus.ANALYZING,
                            progress=percent,
                            progress_message=message,
                        )

            project_id_for_fp: int | None = None
            async with async_session() as session:
                scan_row = await session.get(ScanTask, scan_id)
                if scan_row:
                    project_id_for_fp = scan_row.project_id

            try:
                known_suppressions: list[dict] = []
                if project_id_for_fp:
                    async with async_session() as session:
                        known_suppressions = await _load_known_suppressions_for_llm(session, project_id_for_fp)
                ai_results = await analyze_findings(
                    findings_payload,
                    project_path,
                    on_progress=_fp_progress,
                    known_suppressions=known_suppressions,
                )
            except Exception as exc:
                logger.exception("SAST FP audit failed for scan %s", scan_id)
                await _log_event(
                    scan_id,
                    f"SAST 误报审计失败，已跳过后续批次: {exc}",
                    level="error",
                    phase="llm_fp",
                )
                ai_results = []
            async with async_session() as session:
                findings_db = (await session.execute(
                    select(Finding).where(Finding.scan_id == scan_id, Finding.category == FindingCategory.SAST).limit(50)
                )).scalars().all()
                apply_fp_results(findings_db, ai_results)

                scan_row = await session.get(ScanTask, scan_id)
                if scan_row and scan_row.project_id:
                    for f in findings_db:
                        if f.ai_verdict == AiVerdict.FALSE_POSITIVE and (f.ai_confidence or 0) >= 0.7:
                            await _upsert_project_suppression(
                                session,
                                project_id=scan_row.project_id,
                                finding=f,
                                reason=f.ai_reason or "LLM 判定误报",
                                created_by="llm",
                            )

                missing_zh = [f for f in findings_db if not f.message_zh]
                if missing_zh:
                    zh_map = await translate_finding_messages(
                        [{"id": f.id, "message": f.message} for f in missing_zh]
                    )
                    for f in missing_zh:
                        if f.id in zh_map:
                            f.message_zh = zh_map[f.id]

                await session.commit()
                verdict_counts: dict[str, int] = {}
                for r in ai_results:
                    verdict = str(r.get("verdict", "unknown"))
                    verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                summary = ", ".join(f"{k}:{v}" for k, v in verdict_counts.items()) or "无"
                await _log_event(scan_id, f"SAST 误报审计结论分布: {summary}", phase="llm_fp")
                await _log_event(scan_id, f"SAST 误报审计完成: {len(findings_db)} 条", phase="llm_fp")

                rest = (await session.execute(
                    select(Finding).where(
                        Finding.scan_id == scan_id,
                        Finding.category == FindingCategory.SAST,
                        Finding.message_zh.is_(None),
                    )
                )).scalars().all()
                if rest:
                    zh_map = await translate_finding_messages(
                        [{"id": f.id, "message": f.message} for f in rest]
                    )
                    for f in rest:
                        if f.id in zh_map:
                            f.message_zh = zh_map[f.id]
                    await session.commit()
                    await _log_event(scan_id, f"漏洞描述中文化: {len(zh_map)} 条", phase="llm_fp")

        if is_scan_cancel_requested(scan_id):
            await _finish_scan_paused(scan_id, all_findings, scanner_summary, semgrep_version)
            return

        if settings.llm_code_audit_enabled:
            if not is_llm_configured():
                await _log_event(
                    scan_id,
                    "已开启自动 LLM 端点审计，但未配置 LLM API Key，已跳过（扫描仍完成）",
                    level="warning",
                    phase="llm",
                )
            else:
                if scan_kind_value == ScanKind.RETEST.value:
                    await _log_event(
                        scan_id,
                        "SAST 完成后改为核实上次 LLM 发现是否已修复（复测任务不跑发现式端点审计）",
                        phase="llm",
                    )
                else:
                    await _log_event(scan_id, "SAST 完成后自动开始 LLM 端点审计", phase="llm")
                await run_llm_audit_pipeline(scan_id)
                try:
                    await _notify_feishu_scan_completed(scan_id)
                except Exception as exc:
                    logger.warning("Feishu notify (scan complete after LLM) failed: %s", exc)
                return

        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan:
                total = (await session.execute(
                    select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
                )).scalar() or 0
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.COMPLETED,
                    progress=100,
                    progress_message="扫描完成",
                    total_findings=total,
                    completed_at=datetime.now(timezone.utc),
                )
                await _log_event(scan_id, f"任务完成，总计 {total} 条", phase="done")

                # Feishu notification (MVP):
                # - Notify only once per scan for SAST stage (dedupe by ScanEvent phase).
                # - Only notify unreviewed HIGH/CRITICAL findings.
                try:
                    already = (
                        await session.execute(
                            select(func.count()).select_from(ScanEvent).where(
                                ScanEvent.scan_id == scan_id,
                                ScanEvent.phase == "feishu_notify_sast",
                            )
                        )
                    ).scalar() or 0
                    if already == 0:
                        stmt = (
                            select(Finding)
                            .where(
                                Finding.scan_id == scan_id,
                                Finding.review_status == ReviewStatus.UNREVIEWED,
                                Finding.severity.in_([Severity.HIGH, Severity.CRITICAL]),
                                Finding.tool != "llm",
                            )
                            .limit(8)
                        )
                        rows = (await session.execute(stmt)).scalars().all()
                        for f in rows:
                            await asyncio.to_thread(
                                send_feishu_finding_notification,
                                scan_id=scan_id,
                                finding=f,
                                extra_text="SAST发现",
                            )
                        if rows:
                            await _log_event(
                                scan_id,
                                f"已触发飞书通知: {len(rows)} 条（SAST）",
                                phase="feishu_notify_sast",
                                tool="feishu",
                            )
                except Exception as exc:
                    logger.warning("Feishu notify (SAST) failed: %s", exc)
                try:
                    await _notify_feishu_scan_completed(scan_id)
                except Exception as exc:
                    logger.warning("Feishu notify (scan complete) failed: %s", exc)
    except Exception as exc:
        logger.exception("Scan pipeline failed for scan %s", scan_id)
        await _log_event(scan_id, f"扫描失败: {exc}", level="error", phase="error")
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan:
                await _update_scan(
                    session,
                    scan,
                    status=ScanStatus.FAILED,
                    error_message=str(exc),
                    progress_message="扫描失败",
                )
        try:
            await _notify_feishu_scan_completed(scan_id, failed=True, error_message=str(exc))
        except Exception as notify_exc:
            logger.warning("Feishu notify (scan failed) failed: %s", notify_exc)
        raise
    finally:
        if forced_token is not None:
            reset_forced_scan_languages(forced_token)


async def create_upload_scan(
    session: AsyncSession,
    archive_path: Path,
    name: str | None,
    *,
    project_id: int | None = None,
    parent_scan_id: int | None = None,
    scan_kind: ScanKind | None = None,
    notify_emails: list[str] | None = None,
    notify_email: str | None = None,
    send_html_report: bool = True,
    report_severities: list[str] | None = None,
    scan_languages: list[str] | None = None,
) -> ScanTask:
    scan_id = uuid.uuid4().hex[:12]
    work_dir = settings.uploads_dir / scan_id
    display_name = name or archive_path.stem
    project, kind, version_label = await ensure_project_for_new_scan(
        session,
        name=display_name,
        source=ScanSource.UPLOAD,
        project_id=project_id,
        scan_languages=scan_languages if project_id is None else None,
    )
    if scan_kind is not None:
        kind = scan_kind
    scan = ScanTask(
        project_id=project.id,
        parent_scan_id=parent_scan_id,
        scan_kind=kind,
        version_label=version_label,
        name=display_name,
        source=ScanSource.UPLOAD,
        status=ScanStatus.PENDING,
        project_path=str(work_dir.resolve()),
        notify_emails_json=_pack_notify_emails_json(
            notify_emails,
            notify_email=notify_email,
            send_html_report=send_html_report,
            report_severities=report_severities,
        ),
        progress=0,
        progress_message="代码已就绪，请点击「开始扫描」",
        notes=project.notes,
    )
    session.add(scan)
    project.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(scan)

    await _log_event(
        scan.id,
        f"收到上传文件: {archive_path.name}",
        phase="prepare",
        file_path=str(archive_path),
    )
    await _log_event(scan.id, "开始解压上传内容", phase="prepare")

    project_path = extract_upload(archive_path, work_dir)
    total_files = _count_project_files(project_path)
    scan.project_path = str(project_path.resolve())
    scan.progress = 0
    scan.progress_message = "代码已就绪，请点击「开始扫描」"
    if not name:
        scan.name = project_path.name
        if project_id is None:
            extracted = project_path.name.strip()
            if extracted and extracted.lower() != (project.name or "").strip().lower():
                existing = await find_project_by_name(session, extracted, exclude_id=project.id)
                if not existing:
                    project.name = extracted
    await session.commit()
    await session.refresh(scan)
    await _log_event(
        scan.id,
        f"解压完成: 根目录={project_path.name}, 文件数={total_files}",
        phase="prepare",
        file_path=str(project_path),
    )
    return scan


async def create_gitlab_scan(
    session: AsyncSession,
    project_url: str,
    branch: str,
    access_token: str,
    name: str | None,
    *,
    project_id: int | None = None,
    parent_scan_id: int | None = None,
    scan_kind: ScanKind | None = None,
    notify_emails: list[str] | None = None,
    notify_email: str | None = None,
    send_html_report: bool = True,
    report_severities: list[str] | None = None,
    enforce_allowed_host: bool = True,
    scan_languages: list[str] | None = None,
) -> ScanTask:
    normalized_url = normalize_gitlab_url(project_url)

    from urllib.parse import urlparse as _urlparse

    try:
        gitlab_url, project_path_id = split_project_url(project_url)
    except ValueError as exc:
        # 2. Git 地址不对：URL / 权限 / 路径错（统一归类）
        raise WebhookValidationError("gitlab_address_invalid", str(exc)) from exc

    # All GitLab entry points must stay on the configured instance; otherwise
    # this endpoint becomes an authenticated SSRF primitive.
    if enforce_allowed_host:
        allowed = _urlparse(settings.gitlab_default_url)
        parsed = _urlparse(project_url)
        allowed_host = (allowed.hostname or "").strip().lower()
        parsed_host = (parsed.hostname or "").strip().lower()
        if not allowed_host:
            raise WebhookValidationError(
                "gitlab_address_invalid", "未配置受信任的 GitLab 主机"
            )
        allowed_port = allowed.port or (443 if allowed.scheme == "https" else 80)
        parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme.lower() != (allowed.scheme or "https").lower()
            or parsed_host != allowed_host
            or parsed_port != allowed_port
        ):
            raise WebhookValidationError(
                "gitlab_address_invalid", f"Git 地址须使用已配置的 GitLab：{allowed_host}"
            )

    actual_branch = branch or "main"

    # 1. Token 权限不足 / 2. Git 地址不对 / 3. 分支不存在
    # 在写 DB rows 前探测，探测失败不创建项目/扫描。
    await probe_gitlab_repo(gitlab_url, project_path_id, actual_branch, access_token)

    if project_id is None:
        existing = await find_project_by_source_url(session, project_url)
        if existing:
            raise DuplicateGitUrlError(existing)

    # NOTE: We intentionally avoid calling GitLab API here.
    # Some internal GitLab deployments work in browsers/git but fail TLS handshake via Python HTTP client.
    # We can still proceed by cloning directly with git and derive basic metadata from URL.
    project_info = {
        "id": project_path_id,
        "name": project_path_id.split("/")[-1] if project_path_id else "gitlab-project",
        "path_with_namespace": project_path_id,
        "default_branch": "main",
        "web_url": normalized_url,
    }
    scan_id = uuid.uuid4().hex[:12]
    dest_dir = settings.repos_dir / scan_id
    display_name = name or project_info.get("name") or project_path_id
    actual_branch = branch or project_info.get("default_branch", "main")

    project, kind, version_label = await ensure_project_for_new_scan(
        session,
        name=display_name,
        source=ScanSource.GITLAB,
        source_url=project_info.get("web_url"),
        branch=actual_branch,
        project_id=project_id,
        scan_languages=scan_languages if project_id is None else None,
    )
    if scan_kind is not None:
        kind = scan_kind

    scan = ScanTask(
        project_id=project.id,
        parent_scan_id=parent_scan_id,
        scan_kind=kind,
        version_label=version_label,
        name=display_name,
        source=ScanSource.GITLAB,
        status=ScanStatus.CLONING,
        project_path=str(dest_dir.resolve()),
        source_url=project_info.get("web_url"),
        branch=actual_branch,
        notify_emails_json=_pack_notify_emails_json(
            notify_emails,
            notify_email=notify_email,
            send_html_report=send_html_report,
            report_severities=report_severities,
        ),
        progress=5,
        progress_message="正在从 GitLab 克隆代码...",
        notes=project.notes,
    )
    session.add(scan)
    project.source_url = normalized_url
    project.default_branch = actual_branch
    project.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(scan)

    try:
        await clone_gitlab_repo(gitlab_url, project_path_id, actual_branch, access_token, dest_dir)
        scan.branch = actual_branch
        scan.status = ScanStatus.PENDING
        scan.progress = 0
        scan.progress_message = "代码已就绪，请点击「开始扫描」"
        await session.commit()
        await session.refresh(scan)
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)
        await session.commit()
        raise

    return scan


async def create_retest_scan(
    session: AsyncSession,
    baseline_scan_id: int,
    *,
    branch: str | None = None,
    access_token: str | None = None,
    name: str | None = None,
    strategy: str = "targeted",
    finding_ids: list[int] | None = None,
    include_unreviewed_high: bool = False,
) -> ScanTask:
    """Create a new scan under the same project, baselined against the given scan."""
    from app.models import RetestStrategy

    baseline = await session.get(ScanTask, baseline_scan_id)
    if not baseline:
        raise ValueError("scan not found")
    if baseline.project_id is None:
        raise ValueError("scan has no project")

    retest_strategy = RetestStrategy.TARGETED
    if strategy:
        try:
            retest_strategy = RetestStrategy(strategy)
        except ValueError:
            retest_strategy = RetestStrategy.TARGETED

    options: dict = {}
    if finding_ids:
        options["finding_ids"] = finding_ids
    if include_unreviewed_high:
        options["include_unreviewed_high"] = True
    options_json = json.dumps(options, ensure_ascii=False) if options else None

    if baseline.source == ScanSource.UPLOAD:
        latest = (
            await session.execute(
                select(ScanTask)
                .where(
                    ScanTask.project_id == baseline.project_id,
                    ScanTask.status == ScanStatus.COMPLETED,
                    ScanTask.id != baseline.id,
                )
                .order_by(ScanTask.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if not latest or latest.id == baseline.id:
            raise ValueError(
                "upload_retest_requires_new_archive: 上传型项目无法直接复用原包，请在同一项目下重新上传新版本代码"
            )
        version_label = await next_version_label(session, baseline.project_id)
        display = name or f"{baseline.name} ({version_label})"
        scan = ScanTask(
            project_id=baseline.project_id,
            parent_scan_id=baseline.id,
            scan_kind=ScanKind.RETEST,
            retest_strategy=retest_strategy.value,
            retest_options_json=options_json,
            version_label=version_label,
            name=display,
            source=ScanSource.UPLOAD,
            status=ScanStatus.PENDING,
            project_path=latest.project_path,
            progress=0,
            progress_message="代码已就绪，可启动定向复测",
            notes=baseline.notes,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan

    if baseline.source != ScanSource.GITLAB:
        raise ValueError("retest only supported for gitlab or upload scans")

    project_url = baseline.source_url
    if not project_url:
        raise ValueError("baseline scan missing source_url")

    token = (access_token or "").strip() or (settings.gitlab_access_token or "").strip()
    if not token:
        raise ValueError("GitLab access token required for retest")

    version_label = await next_version_label(session, baseline.project_id)
    display = name or f"{baseline.name} ({version_label})"
    scan = await create_gitlab_scan(
        session,
        project_url=project_url if project_url.endswith(".git") else f"{project_url.rstrip('/')}.git",
        branch=branch or baseline.branch or "main",
        access_token=token,
        name=display,
        project_id=baseline.project_id,
        parent_scan_id=baseline.id,
        scan_kind=ScanKind.RETEST,
    )
    scan.retest_strategy = retest_strategy.value
    scan.retest_options_json = options_json
    await session.commit()
    await session.refresh(scan)
    return scan


async def ensure_scan_classifications(session: AsyncSession, scan_id: int) -> int:
    """Recompute and persist OWASP/subtype so filters match displayed counts.

    Skips work when every finding already has owasp_id (common hot path for stats/page).
    """
    missing = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.scan_id == scan_id,
                    or_(Finding.owasp_id.is_(None), Finding.owasp_id == ""),
                )
            )
        ).scalar()
        or 0
    )
    if missing == 0:
        return 0

    findings = (
        await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    ).scalars().all()
    updated = 0
    removed = 0
    for f in findings:
        if f.tool == "llm" and is_non_vuln_confirmation_text(
            f.message,
            f.message_zh,
            f.ai_reason,
            f.metadata_json,
        ):
            await session.delete(f)
            removed += 1
            continue
        fields = classify_finding(
            rule_id=f.rule_id,
            message=f.message,
            metadata_json=f.metadata_json,
            tool=f.tool,
            category=f.category.value,
        )
        changed = (
            f.owasp_id != fields["owasp_id"]
            or f.owasp_name != fields["owasp_name"]
            or f.vuln_subtype != fields["vuln_subtype"]
            or f.vuln_subtype_name != fields["vuln_subtype_name"]
        )
        new_severity = adjust_severity(
            f.severity.value,
            vuln_subtype=fields["vuln_subtype"],
            owasp_id=fields["owasp_id"],
        )
        new_sev_enum = Severity(new_severity) if new_severity in Severity.__members__ else f.severity
        if new_sev_enum != f.severity:
            f.severity = new_sev_enum
            changed = True
        if not changed:
            continue
        f.owasp_id = fields["owasp_id"]
        f.owasp_name = fields["owasp_name"]
        f.vuln_subtype = fields["vuln_subtype"]
        f.vuln_subtype_name = fields["vuln_subtype_name"]
        updated += 1
    if updated or removed:
        await session.commit()
    if removed:
        logger.info("Removed %s non-vuln LLM confirmations from scan %s", removed, scan_id)
    return updated + removed


def _enum_or_str(value) -> str:
    if value is None:
        return "unknown"
    return value.value if hasattr(value, "value") else str(value)


async def get_scan_stats(session: AsyncSession, scan_id: int) -> dict:
    await ensure_scan_classifications(session, scan_id)

    async def _group(column) -> dict[str, int]:
        rows = (
            await session.execute(
                select(column, func.count())
                .where(Finding.scan_id == scan_id)
                .group_by(column)
            )
        ).all()
        out: dict[str, int] = {}
        for key, count in rows:
            out[_enum_or_str(key)] = int(count)
        return out

    by_severity = await _group(Finding.severity)
    by_verdict = await _group(Finding.ai_verdict)
    by_tool = await _group(Finding.tool)
    by_category = await _group(Finding.category)
    by_review = await _group(Finding.review_status)
    by_owasp = await _group(Finding.owasp_id)
    if "unknown" in by_owasp or None in by_owasp or "" in by_owasp:
        # Normalize empty owasp keys
        empty = by_owasp.pop("unknown", 0) + by_owasp.pop("", 0) + by_owasp.pop("None", 0)
        if empty:
            by_owasp["other"] = by_owasp.get("other", 0) + empty
    by_subtype_raw = await _group(Finding.vuln_subtype)
    by_subtype = {("other" if k in ("unknown", "None", "") else k): v for k, v in by_subtype_raw.items()}

    owasp_subtype_rows = (
        await session.execute(
            select(Finding.owasp_id, Finding.vuln_subtype, func.count())
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.owasp_id, Finding.vuln_subtype)
        )
    ).all()
    by_owasp_subtype: dict[str, dict[str, int]] = {}
    for owasp_id, subtype, count in owasp_subtype_rows:
        owasp_key = _enum_or_str(owasp_id) if owasp_id else "other"
        if owasp_key in ("unknown", "None", ""):
            owasp_key = "other"
        subtype_key = subtype or "other"
        by_owasp_subtype.setdefault(owasp_key, {})
        by_owasp_subtype[owasp_key][subtype_key] = int(count)

    top_rule_rows = (
        await session.execute(
            select(Finding.rule_id, func.count().label("cnt"))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.rule_id)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    top_rules = [{"rule_id": rid, "count": int(cnt)} for rid, cnt in top_rule_rows]

    total = int(
        (
            await session.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )
        ).scalar()
        or 0
    )

    by_category["llm"] = by_category.get(FindingCategory.BUSINESS_LOGIC.value, 0) + by_category.get(
        FindingCategory.AUTHORIZATION.value, 0
    )

    scan = await session.get(ScanTask, scan_id)
    security_score = getattr(scan, "security_score", None) if scan else None
    if security_score is None:
        from app.services.score_service import get_or_compute_scan_score

        scored = await get_or_compute_scan_score(session, scan_id, refresh=False)
        security_score = int(scored["score"]) if scored else None

    return {
        "total": total,
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


async def update_finding_review(
    session: AsyncSession,
    scan_id: int,
    finding_id: int,
    review_status: ReviewStatus,
    review_note: str | None,
    generate_poc: bool = False,
) -> Finding:
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise ValueError("Finding not found")

    if review_status == ReviewStatus.FALSE_POSITIVE and not (review_note or "").strip():
        raise ValueError("标记误报必须填写原因")

    finding.review_status = review_status
    finding.review_note = (review_note or "").strip() or None
    finding.reviewed_at = datetime.now(timezone.utc)

    if review_status == ReviewStatus.FALSE_POSITIVE:
        scan = await session.get(ScanTask, scan_id)
        if scan and scan.project_id:
            await _upsert_project_suppression(
                session,
                project_id=scan.project_id,
                finding=finding,
                reason=finding.review_note or "",
                created_by="review",
            )
        note_preview = (finding.review_note or "")[:120]
        await _log_event(
            scan_id,
            f"误报确认 #{finding_id}: {note_preview}",
            phase="review_fp",
        )

    if generate_poc and review_status == ReviewStatus.CONFIRMED:
        scan = await session.get(ScanTask, scan_id)
        if scan and is_llm_configured():
            try:
                poc = await generate_verification_poc(finding, Path(scan.project_path))
                save_poc_to_finding(finding, poc)
            except ValueError as exc:
                logger.warning("PoC generation on confirm failed: %s", exc)

    await session.commit()
    await session.refresh(finding)

    try:
        from app.services.score_service import persist_scan_score

        await persist_scan_score(session, scan_id)
    except Exception as exc:
        logger.warning("Failed to refresh security score after review scan=%s: %s", scan_id, exc)

    # Best-effort notification after triage/confirmation.
    # Minimal rule: when status changes to confirmed/false_positive/fixed.
    try:
        if finding.review_status in (ReviewStatus.CONFIRMED, ReviewStatus.FALSE_POSITIVE, ReviewStatus.FIXED):
            await asyncio.to_thread(
                send_feishu_finding_notification,
                scan_id=scan_id,
                finding=finding,
                extra_text="状态已更新",
            )
    except Exception as exc:
        logger.warning("Feishu notify on review failed: %s", exc)

    return finding


async def create_external_review_link(
    session: AsyncSession,
    scan_id: int,
    finding_id: int,
    *,
    expires_hours: int = 72,
) -> Finding:
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise ValueError("Finding not found")

    hours = max(1, min(int(expires_hours or 72), 24 * 30))
    finding.external_review_token = secrets.token_urlsafe(24)
    finding.external_review_expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
    finding.external_review_revoked_at = None
    await session.commit()
    await session.refresh(finding)
    return finding


async def revoke_external_review_link(
    session: AsyncSession,
    scan_id: int,
    finding_id: int,
) -> Finding:
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise ValueError("Finding not found")
    if not finding.external_review_token:
        return finding

    finding.external_review_revoked_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(finding)
    return finding


async def get_finding_by_external_token(
    session: AsyncSession,
    token: str,
) -> Finding:
    token = (token or "").strip()
    if not token:
        raise ValueError("Invalid token")

    stmt = select(Finding).where(Finding.external_review_token == token)
    finding = (await session.execute(stmt)).scalars().first()
    if not finding:
        raise ValueError("Link not found")

    if finding.external_review_revoked_at is not None:
        raise PermissionError("Link revoked")
    expires_at = finding.external_review_expires_at
    if expires_at and _as_utc(expires_at) < datetime.now(timezone.utc):
        raise PermissionError("Link expired")
    return finding


async def submit_external_review(
    session: AsyncSession,
    token: str,
    *,
    status: ExternalReviewStatus,
    note: str | None = None,
    actor: str | None = None,
) -> Finding:
    finding = await get_finding_by_external_token(session, token)
    if status == ExternalReviewStatus.FALSE_POSITIVE and not (note or "").strip():
        raise ValueError("标记误报必须填写说明")

    finding.external_status = status
    finding.external_note = (note or "").strip() or None
    finding.external_updated_by = (actor or "").strip() or "external"
    finding.external_updated_at = datetime.now(timezone.utc)

    if status == ExternalReviewStatus.FALSE_POSITIVE:
        scan = await session.get(ScanTask, finding.scan_id)
        if scan and scan.project_id:
            await _upsert_project_suppression(
                session,
                project_id=scan.project_id,
                finding=finding,
                reason=finding.external_note or "",
                created_by=finding.external_updated_by,
            )

    await session.commit()
    await session.refresh(finding)

    status_labels = {
        ExternalReviewStatus.VULN_EXISTS: "漏洞存在",
        ExternalReviewStatus.FALSE_POSITIVE: "漏洞误报",
        ExternalReviewStatus.FIXED_CLAIMED: "漏洞修复完成",
    }
    label = status_labels.get(status, status.value)
    try:
        from app.services.feishu_service import send_feishu_finding_notification

        scan = await session.get(ScanTask, finding.scan_id)
        if scan:
            send_feishu_finding_notification(
                scan_id=scan.id,
                finding=finding,
                extra_text=f"外部确认: {label}",
            )
    except Exception:
        pass

    return finding


async def create_project_review_link(
    session: AsyncSession,
    scan_id: int,
    *,
    expires_hours: int = 168,
) -> ScanTask:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")

    hours = max(1, min(int(expires_hours or 168), 24 * 30))
    scan.project_review_token = secrets.token_urlsafe(24)
    scan.project_review_expires_at = datetime.now(timezone.utc) + timedelta(hours=hours)
    scan.project_review_revoked_at = None
    await session.commit()
    await session.refresh(scan)
    return scan


async def revoke_project_review_link(session: AsyncSession, scan_id: int) -> ScanTask:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")
    if not scan.project_review_token:
        return scan
    scan.project_review_revoked_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(scan)
    return scan


def _project_review_token_active(scan: ScanTask) -> bool:
    return bool(scan.project_review_token and not scan.project_review_revoked_at)


async def get_scan_by_project_review_token(
    session: AsyncSession,
    token: str,
) -> ScanTask:
    token = (token or "").strip()
    if not token:
        raise ValueError("Invalid token")

    stmt = select(ScanTask).where(ScanTask.project_review_token == token)
    scan = (await session.execute(stmt)).scalars().first()
    if not scan:
        raise ValueError("Link not found")

    if scan.project_review_revoked_at is not None:
        raise PermissionError("Link revoked")
    expires_at = scan.project_review_expires_at
    if expires_at and _as_utc(expires_at) < datetime.now(timezone.utc):
        raise PermissionError("Link expired")
    return scan


async def list_project_review_findings(
    session: AsyncSession,
    token: str,
) -> tuple[ScanTask, list[Finding]]:
    scan = await get_scan_by_project_review_token(session, token)
    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.severity.desc(), Finding.id.asc())
    )
    findings = list((await session.execute(stmt)).scalars().all())
    return scan, findings


async def get_project_review_finding(
    session: AsyncSession,
    token: str,
    finding_id: int,
) -> tuple[ScanTask, Finding]:
    scan = await get_scan_by_project_review_token(session, token)
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan.id:
        raise ValueError("Finding not found")
    return scan, finding


async def submit_project_review_finding(
    session: AsyncSession,
    token: str,
    finding_id: int,
    *,
    status: ExternalReviewStatus,
    note: str | None = None,
    actor: str | None = None,
) -> Finding:
    scan, finding = await get_project_review_finding(session, token, finding_id)
    finding.external_status = status
    finding.external_note = (note or "").strip() or None
    finding.external_updated_by = (actor or "").strip() or "external"
    finding.external_updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(finding)

    status_labels = {
        ExternalReviewStatus.VULN_EXISTS: "漏洞存在",
        ExternalReviewStatus.FALSE_POSITIVE: "漏洞误报",
        ExternalReviewStatus.FIXED_CLAIMED: "漏洞修复完成",
    }
    label = status_labels.get(status, status.value)
    try:
        from app.services.feishu_service import send_feishu_finding_notification

        send_feishu_finding_notification(
            scan_id=scan.id,
            finding=finding,
            extra_text=f"项目链接外部确认: {label}",
        )
    except Exception:
        pass

    return finding


async def generate_finding_poc(
    session: AsyncSession,
    scan_id: int,
    finding_id: int,
    force: bool = False,
) -> dict:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")

    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise ValueError("Finding not found")

    if not is_llm_configured():
        raise ValueError("请先在系统设置中配置 LLM API Key")

    existing = get_stored_poc(finding)
    if existing and not force:
        return {
            "generated": False,
            "cached": True,
            "message": "已有验证 PoC，如需重新生成请使用 force=true",
            "poc": existing,
        }

    poc = await generate_verification_poc(finding, Path(scan.project_path))
    save_poc_to_finding(finding, poc)
    await session.commit()
    await session.refresh(finding)
    stored = get_stored_poc(finding)
    return {
        "generated": True,
        "cached": False,
        "message": "验证 PoC 已生成",
        "poc": stored,
    }


async def save_finding_poc_draft(
    session: AsyncSession,
    scan_id: int,
    finding_id: int,
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str | None,
    poc_content: str | None = None,
) -> dict:
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise ValueError("Finding not found")
    req = normalize_http_request(method, url, headers, body)
    content = poc_content if poc_content is not None else request_to_curl(req)
    poc = merge_http_request_into_poc(finding, req, poc_content=content)
    await session.commit()
    await session.refresh(finding)
    return {"message": "验证请求已保存", "poc": get_stored_poc(finding) or poc}


async def execute_finding_poc(
    session: AsyncSession,
    scan_id: int,
    finding_id: int,
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str | None,
) -> dict:
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise ValueError("Finding not found")
    req = normalize_http_request(method, url, headers, body)
    try:
        return await asyncio.to_thread(
            execute_http_request,
            req["method"],
            req["url"],
            req["headers"],
            req["body"],
        )
    except PocTargetError as exc:
        raise ValueError(str(exc)) from exc


async def analyze_scan_findings(
    session: AsyncSession,
    scan_id: int,
    finding_ids: list[int] | None,
    max_findings: int,
    force: bool = False,
) -> dict:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")

    base_stmt = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.category == FindingCategory.SAST,
    )
    all_sast = (await session.execute(base_stmt)).scalars().all()
    pending_count = sum(1 for f in all_sast if f.ai_verdict == AiVerdict.PENDING)
    already_audited = len(all_sast) - pending_count

    stmt = base_stmt
    if finding_ids:
        stmt = stmt.where(Finding.id.in_(finding_ids))
    elif force:
        stmt = stmt.limit(max_findings)
    else:
        stmt = stmt.where(Finding.ai_verdict == AiVerdict.PENDING).limit(max_findings)

    findings_db = (await session.execute(stmt)).scalars().all()
    if not findings_db:
        if not force and already_audited > 0:
            msg = f"已有 {already_audited} 条完成误报审计，无待分析项。再次点击将重新审计。"
        elif not all_sast:
            msg = "当前扫描无 SAST 漏洞，无需误报审计。"
        elif not is_llm_configured():
            msg = "请先在系统设置中配置 LLM API Key，再执行误报审计。"
        else:
            msg = "无待分析的 SAST 漏洞。"
        return {
            "analyzed": 0,
            "pending": pending_count,
            "already_audited": already_audited,
            "message": msg,
        }

    payload = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "message": f.message,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "code_snippet": f.code_snippet,
        }
        for f in findings_db
    ]
    results = await analyze_findings(payload, Path(scan.project_path))
    apply_fp_results(findings_db, results)

    missing_zh = [f for f in findings_db if not f.message_zh]
    if missing_zh:
        zh_map = await translate_finding_messages(
            [{"id": f.id, "message": f.message} for f in missing_zh]
        )
        for f in missing_zh:
            if f.id in zh_map:
                f.message_zh = zh_map[f.id]

    await session.commit()
    action = "重新审计" if force else "审计"
    return {
        "analyzed": len(findings_db),
        "pending": max(0, pending_count - len(findings_db)),
        "already_audited": already_audited,
        "message": f"已{action} {len(findings_db)} 条 SAST 漏洞。",
    }


def _is_sast_deep_pending(finding) -> bool:
    return not parse_finding_metadata(finding.metadata_json).get("sast_deep_reviewed")


def _has_tool_taint_flow(meta: dict) -> bool:
    """True only when Semgrep/CodeQL provided a taint trace (not AI-reconstructed)."""
    trace = meta.get("dataflow_trace")
    if isinstance(trace, dict) and (trace.get("taint_source") or trace.get("taint_sink")):
        return True
    thread_flows = meta.get("codeql_thread_flows")
    if isinstance(thread_flows, list) and thread_flows:
        return True
    return False


def _sast_recon_priority(finding) -> tuple:
    """Prefer HIGH/CRITICAL and SSRF-like rules when reconstructing flows."""
    sev = (finding.severity.value if finding.severity else "").upper()
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)
    blob = f"{finding.rule_id or ''} {finding.message or ''}".lower()
    ssrf_boost = 0 if any(k in blob for k in ("ssrf", "request-forgery", "cwe-918", "urlopen", "openconnection")) else 1
    return (ssrf_boost, sev_rank, finding.id or 0)


def _deep_audit_eligible_clause():
    """SAST (semgrep/codeql) or LLM endpoint-audit findings eligible for deep flow audit."""
    return or_(
        and_(
            Finding.category == FindingCategory.SAST,
            Finding.tool.in_(["semgrep", "codeql"]),
        ),
        and_(
            Finding.tool == "llm",
            Finding.category.in_([FindingCategory.BUSINESS_LOGIC, FindingCategory.AUTHORIZATION]),
        ),
    )


async def _select_deep_audit_findings(
    session: AsyncSession,
    scan_id: int,
    finding_ids: list[int] | None,
    max_findings: int,
    force: bool,
) -> tuple[list, int, int, list]:
    """Return (findings_db, pending_count, already_audited, all_eligible)."""
    base_stmt = select(Finding).where(Finding.scan_id == scan_id, _deep_audit_eligible_clause())
    all_eligible = list((await session.execute(base_stmt)).scalars().all())
    pending_count = sum(1 for f in all_eligible if _is_sast_deep_pending(f))
    already_audited = len(all_eligible) - pending_count

    stmt = base_stmt
    if finding_ids:
        stmt = stmt.where(Finding.id.in_(finding_ids))
    elif force:
        ordered = sorted(all_eligible, key=_sast_recon_priority)[:max_findings]
        stmt = stmt.where(Finding.id.in_([f.id for f in ordered] or [-1]))
    else:
        pending = [f for f in all_eligible if _is_sast_deep_pending(f)]

        def _pending_key(f):
            has_flow = 1 if _has_tool_taint_flow(parse_finding_metadata(f.metadata_json)) else 0
            return (has_flow, *_sast_recon_priority(f))

        pending_ids = [f.id for f in sorted(pending, key=_pending_key)[:max_findings]]
        stmt = stmt.where(Finding.id.in_(pending_ids or [-1]))

    findings_db = list((await session.execute(stmt)).scalars().all())
    return findings_db, pending_count, already_audited, all_eligible


# Backward-compatible alias
_select_sast_deep_findings = _select_deep_audit_findings


def _short_rule(rule_id: str | None) -> str:
    text = (rule_id or "finding").strip()
    if len(text) <= 48:
        return text
    return text[:45] + "…"


async def analyze_sast_deep_findings(
    session: AsyncSession,
    scan_id: int,
    finding_ids: list[int] | None,
    max_findings: int,
    force: bool = False,
    *,
    track_progress: bool = True,
) -> dict:
    """LLM deep review: use tool taint flows when present; otherwise reverse-reconstruct."""
    from app.services.sast_deep_runtime import (
        SastDeepCancelled,
        check_sast_deep_cancel,
        finish_sast_deep_progress,
        init_sast_deep_progress,
        update_sast_deep_progress,
    )

    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")

    findings_db, pending_count, already_audited, all_eligible = await _select_deep_audit_findings(
        session, scan_id, finding_ids, max_findings, force
    )
    if not findings_db:
        if not force and already_audited > 0:
            msg = f"已有 {already_audited} 条完成深度研判，无待分析项。再次点击将重新研判。"
        elif not all_eligible:
            msg = "当前扫描无可用于深度研判的发现（SAST 或 LLM 端点审计）。"
        elif not is_llm_configured():
            msg = "请先在系统设置中配置 LLM API Key。"
        else:
            msg = "无待深度研判的发现。"
        return {
            "analyzed": 0,
            "pending": pending_count,
            "already_audited": already_audited,
            "message": msg,
        }

    project_path = Path(scan.project_path)
    with_flow: list = []
    without_flow: list = []
    for f in findings_db:
        meta = parse_finding_metadata(f.metadata_json)
        item = {
            "id": f.id,
            "tool": f.tool,
            "category": f.category.value if f.category else "",
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "message": f.message,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "code_snippet": f.code_snippet,
            "metadata_json": f.metadata_json,
            "ai_reason": f.ai_reason,
        }
        if f.tool == "llm" or not _has_tool_taint_flow(meta):
            without_flow.append((f, item))
        else:
            with_flow.append((f, item))

    without_flow.sort(key=lambda pair: _sast_recon_priority(pair[0]))

    tasks: list[dict] = []
    for f, _ in without_flow:
        prefix = "LLM" if f.tool == "llm" else _short_rule(f.rule_id)
        tasks.append(
            {
                "id": f"recon-{f.id}",
                "label": f"#{f.id} {prefix}",
                "kind": "recon",
                "status": "pending",
                "finding_id": f.id,
            }
        )
    if with_flow:
        tasks.append(
            {
                "id": "batch-flow",
                "label": f"工具污点流批量研判（{len(with_flow)} 条）",
                "kind": "batch",
                "status": "pending",
            }
        )

    if track_progress:
        init_sast_deep_progress(
            scan_id,
            tasks,
            message=f"共 {len(tasks)} 项任务（追认 {len(without_flow)} · 批量 {len(with_flow)}）",
        )
        scan.progress = 1
        scan.progress_message = f"深度研判进行中：0/{len(tasks)}"
        await session.commit()

    reconstructed = 0
    for idx, (f, item) in enumerate(without_flow):
        check_sast_deep_cancel(scan_id)
        task_id = f"recon-{f.id}"
        if track_progress:
            update_sast_deep_progress(
                scan_id,
                phase="recon",
                current_task_id=task_id,
                task_id=task_id,
                task_status="running",
                message=f"数据流追认 {idx + 1}/{len(without_flow)}：#{f.id}",
            )
            scan.progress = min(95, int(((idx) / max(1, len(tasks))) * 100))
            scan.progress_message = f"数据流追认 #{f.id}（{idx + 1}/{len(without_flow)}）"
            await session.commit()

        await _log_event(
            scan_id,
            f"数据流追认: #{f.id} {('LLM' if f.tool == 'llm' else (f.rule_id or ''))}"
            f"（{'LLM 发现' if f.tool == 'llm' else '工具未提供污点流'}）",
            phase="llm_fp",
            tool=f.tool or "sast",
        )
        try:
            async def _recon_progress(round_no: int, max_rounds: int, detail: str) -> None:
                if not track_progress:
                    return
                total_tasks = max(1, len(tasks))
                soft = (idx + (round_no / max(1, max_rounds))) / total_tasks
                update_sast_deep_progress(
                    scan_id,
                    phase="recon",
                    current_task_id=task_id,
                    task_id=task_id,
                    task_status="running",
                    task_detail=f"第 {round_no}/{max_rounds} 轮 · {detail}"[:160],
                    message=f"追认 #{f.id}（{idx + 1}/{len(without_flow)}）· 第 {round_no}/{max_rounds} 轮",
                    percent=min(99, int(soft * 100)),
                )
                scan.progress = min(95, int(soft * 100))
                scan.progress_message = f"追认 #{f.id} · 第 {round_no}/{max_rounds} 轮 · {detail}"[:200]
                await session.commit()

            result = await reconstruct_finding_flow(
                item,
                project_path,
                progress_callback=_recon_progress,
                cancel_check=lambda: check_sast_deep_cancel(scan_id),
            )
            check_sast_deep_cancel(scan_id)
            if apply_flow_recon_result(f, result):
                reconstructed += 1
                summary = (result.get("data_flow_summary") or "")[:120]
                verdict = result.get("verdict") or ""
                await _log_event(
                    scan_id,
                    f"数据流追认完成: #{f.id} → {verdict} {summary}",
                    phase="llm_fp",
                    tool=f.tool or "sast",
                )
                if track_progress:
                    update_sast_deep_progress(
                        scan_id,
                        task_id=task_id,
                        task_status="done",
                        task_detail=f"{verdict} · {summary}"[:160],
                    )
            elif track_progress:
                update_sast_deep_progress(scan_id, task_id=task_id, task_status="skipped", task_detail="无结果")
            await session.commit()
        except SastDeepCancelled:
            raise
        except Exception as exc:
            logger.exception("Flow recon failed for finding %s", f.id)
            await _log_event(
                scan_id,
                f"数据流追认失败: #{f.id} {exc}",
                level="error",
                phase="llm_fp",
                tool=f.tool or "sast",
            )
            if track_progress:
                update_sast_deep_progress(
                    scan_id,
                    task_id=task_id,
                    task_status="error",
                    task_detail=str(exc)[:160],
                )
            await session.commit()

    if with_flow:
        check_sast_deep_cancel(scan_id)
        if track_progress:
            update_sast_deep_progress(
                scan_id,
                phase="batch",
                current_task_id="batch-flow",
                task_id="batch-flow",
                task_status="running",
                message=f"工具污点流批量研判（{len(with_flow)} 条）…",
            )
            scan.progress_message = f"批量研判工具污点流 {len(with_flow)} 条…"
            await session.commit()
        try:
            batch_items = [item for _, item in with_flow]
            results = await analyze_sast_with_flow(batch_items, project_path)
            apply_sast_deep_results([f for f, _ in with_flow], results)
            if track_progress:
                update_sast_deep_progress(
                    scan_id,
                    task_id="batch-flow",
                    task_status="done",
                    task_detail=f"完成 {len(with_flow)} 条",
                )
        except SastDeepCancelled:
            raise
        except Exception as exc:
            logger.exception("Batch sast deep failed scan=%s", scan_id)
            if track_progress:
                update_sast_deep_progress(
                    scan_id,
                    task_id="batch-flow",
                    task_status="error",
                    task_detail=str(exc)[:160],
                )
            raise

    await session.commit()
    action = "重新研判" if force else "深度研判"
    llm_count = sum(1 for f, _ in without_flow if f.tool == "llm")
    sast_recon = len(without_flow) - llm_count
    parts = [f"已{action} {len(findings_db)} 条"]
    if reconstructed:
        parts.append(f"其中 {reconstructed} 条完成 AI 数据流追认")
    if llm_count:
        parts.append(f"含 LLM 发现 {llm_count} 条")
    if with_flow:
        parts.append(f"{len(with_flow)} 条基于 SAST 工具污点流")
    elif sast_recon:
        parts.append(f"{sast_recon} 条 SAST 无工具流已追认")
    message = "；".join(parts) + "。"
    if track_progress:
        finish_sast_deep_progress(scan_id, status="done", message=message)
    return {
        "analyzed": len(findings_db),
        "pending": max(0, pending_count - len(findings_db)),
        "already_audited": already_audited,
        "message": message,
        "reconstructed": reconstructed,
        "with_tool_flow": len(with_flow),
    }


async def run_sast_deep_pipeline(
    scan_id: int,
    finding_ids: list[int] | None = None,
    max_findings: int = 12,
    force: bool = False,
) -> None:
    """Background entry for SAST deep audit with progress + cancel support."""
    from app.services.sast_deep_runtime import (
        SastDeepCancelled,
        clear_sast_deep_cancel,
        finish_sast_deep_progress,
    )

    clear_sast_deep_cancel(scan_id)
    try:
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if not scan:
                return
            scan.status = ScanStatus.ANALYZING
            scan.progress = 1
            scan.progress_message = "深度研判启动中…"
            scan.error_message = None
            await session.commit()

            # Auto force if nothing pending (same UX as sync endpoint).
            result = await analyze_sast_deep_findings(
                session, scan_id, finding_ids, max_findings, force=force, track_progress=True
            )
            if (
                result.get("analyzed", 0) == 0
                and not finding_ids
                and not force
                and result.get("already_audited", 0) > 0
            ):
                result = await analyze_sast_deep_findings(
                    session, scan_id, finding_ids, max_findings, force=True, track_progress=True
                )
                if result.get("analyzed", 0) > 0:
                    result["message"] = f"已重新深度研判 {result['analyzed']} 条 SAST 发现。"

            scan = await session.get(ScanTask, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.progress = 100
                scan.progress_message = result.get("message") or "深度研判完成"
                await session.commit()
                try:
                    from app.services.score_service import persist_scan_score

                    await persist_scan_score(session, scan_id)
                except Exception as score_exc:
                    logger.warning("Failed to refresh security score after deep audit: %s", score_exc)
            finish_sast_deep_progress(
                scan_id,
                status="done",
                message=result.get("message") or "深度研判完成",
            )
            await _log_event(scan_id, result.get("message") or "深度研判完成", phase="llm_fp")
    except SastDeepCancelled:
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.progress_message = "深度研判已暂停（已保存完成项）"
                await session.commit()
                try:
                    from app.services.score_service import persist_scan_score

                    await persist_scan_score(session, scan_id)
                except Exception as score_exc:
                    logger.warning("Failed to refresh security score after deep audit cancel: %s", score_exc)
        finish_sast_deep_progress(scan_id, status="cancelled", message="已暂停深度研判")
        await _log_event(scan_id, "深度研判已暂停", level="warning", phase="llm_fp")
    except Exception as exc:
        logger.exception("SAST deep pipeline failed scan=%s", scan_id)
        async with async_session() as session:
            scan = await session.get(ScanTask, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.error_message = str(exc)[:500]
                scan.progress_message = f"深度研判失败: {exc}"[:300]
                await session.commit()
                try:
                    from app.services.score_service import persist_scan_score

                    await persist_scan_score(session, scan_id)
                except Exception as score_exc:
                    logger.warning("Failed to refresh security score after deep audit failure: %s", score_exc)
        finish_sast_deep_progress(scan_id, status="failed", message=str(exc)[:300], error=str(exc)[:500])
        await _log_event(scan_id, f"深度研判失败: {exc}", level="error", phase="llm_fp")
    finally:
        clear_sast_deep_cancel(scan_id)


async def preview_sast_deep_start(
    session: AsyncSession,
    scan_id: int,
    finding_ids: list[int] | None,
    max_findings: int,
    force: bool,
) -> dict:
    """Lightweight check before starting background deep audit."""
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")
    findings_db, pending_count, already_audited, all_eligible = await _select_deep_audit_findings(
        session, scan_id, finding_ids, max_findings, force
    )
    if findings_db:
        recon = sum(
            1
            for f in findings_db
            if f.tool == "llm" or not _has_tool_taint_flow(parse_finding_metadata(f.metadata_json))
        )
        llm_n = sum(1 for f in findings_db if f.tool == "llm")
        batch_n = len(findings_db) - recon
        detail = f"数据流追认 {recon}"
        if llm_n:
            detail += f"（含 LLM {llm_n}）"
        if batch_n:
            detail += f" · 污点流批量 {batch_n}"
        return {
            "ok": True,
            "count": len(findings_db),
            "recon_count": recon,
            "batch_count": batch_n,
            "llm_count": llm_n,
            "pending": pending_count,
            "already_audited": already_audited,
            "force": force,
            "message": f"将后台深度研判 {len(findings_db)} 条（{detail}）",
        }
    if not force and already_audited > 0:
        return {
            "ok": False,
            "count": 0,
            "pending": pending_count,
            "already_audited": already_audited,
            "suggest_force": True,
            "message": f"已有 {already_audited} 条完成深度研判，无待分析项。",
        }
    if not all_eligible:
        msg = "当前扫描无可用于深度研判的发现（SAST 或 LLM 端点审计）。"
    elif not is_llm_configured():
        msg = "请先在系统设置中配置 LLM API Key。"
    else:
        msg = "无待深度研判的发现。"
    return {
        "ok": False,
        "count": 0,
        "pending": pending_count,
        "already_audited": already_audited,
        "suggest_force": False,
        "message": msg,
    }


async def review_llm_scan_findings(
    session: AsyncSession,
    scan_id: int,
    finding_ids: list[int] | None,
    max_findings: int,
    force: bool = False,
) -> dict:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        raise ValueError("Scan not found")

    base_stmt = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.tool == "llm",
        Finding.category.in_([FindingCategory.BUSINESS_LOGIC, FindingCategory.AUTHORIZATION]),
    )
    all_llm = (await session.execute(base_stmt)).scalars().all()
    pending_count = sum(1 for f in all_llm if is_llm_pending_review(f))
    already_audited = len(all_llm) - pending_count

    stmt = base_stmt
    if finding_ids:
        stmt = stmt.where(Finding.id.in_(finding_ids))
    elif force:
        stmt = stmt.limit(max_findings)
    else:
        pending_ids = [f.id for f in all_llm if is_llm_pending_review(f)][:max_findings]
        stmt = stmt.where(Finding.id.in_(pending_ids or [-1]))

    findings_db = (await session.execute(stmt)).scalars().all()

    if not findings_db:
        if not force and already_audited > 0:
            msg = f"已有 {already_audited} 条完成 AI 复审，无待复审项。再次点击将重新复审。"
        elif not all_llm:
            msg = "当前扫描无 LLM 深度审计发现，请先执行 LLM 深度审计。"
        elif not is_llm_configured():
            msg = "请先在系统设置中配置 LLM API Key，再执行 AI 复审。"
        else:
            msg = "无待复审的 LLM 发现。"
        return {
            "analyzed": 0,
            "pending": pending_count,
            "already_audited": already_audited,
            "message": msg,
        }

    payload = [
        {
            "id": f.id,
            "category": f.category.value,
            "severity": f.severity.value,
            "message": f.message,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "code_snippet": f.code_snippet,
            "ai_reason": f.ai_reason,
            "ai_confidence": f.ai_confidence,
        }
        for f in findings_db
    ]
    results = await review_llm_findings(payload, Path(scan.project_path))
    apply_llm_review_results(findings_db, results)
    await session.commit()
    action = "重新复审" if force else "复审"
    return {
        "analyzed": len(findings_db),
        "pending": max(0, pending_count - len(findings_db)),
        "already_audited": already_audited,
        "message": f"已{action} {len(findings_db)} 条 LLM 发现。",
    }


async def reset_scan_for_rerun(session: AsyncSession, scan: ScanTask) -> None:
    """Clear findings/events and return scan to manual SAST start state."""
    await session.execute(delete(Finding).where(Finding.scan_id == scan.id))
    await session.execute(delete(ScanEvent).where(ScanEvent.scan_id == scan.id))
    await _update_scan(
        session,
        scan,
        status=ScanStatus.PENDING,
        progress=0,
        progress_message="代码已就绪，请点击「开始 SAST 扫描」",
        error_message=None,
        total_findings=0,
        completed_at=None,
        semgrep_version=None,
        scanner_summary=None,
    )


async def delete_scan(session: AsyncSession, scan_id: int) -> bool:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return False

    await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
    await session.execute(delete(ScanEvent).where(ScanEvent.scan_id == scan_id))

    project_path = Path(scan.project_path)
    uploads_root = settings.uploads_dir.resolve()
    repos_root = settings.repos_dir.resolve()

    try:
        resolved_project = project_path.resolve()
        if resolved_project.exists():
            for root in (resolved_project, resolved_project.parent):
                if not root.exists():
                    continue
                if root == uploads_root or root == repos_root:
                    continue
                if uploads_root in root.parents or repos_root in root.parents:
                    shutil.rmtree(root, ignore_errors=True)
                    break
    except Exception:
        logger.warning("Failed to remove project files for scan %s", scan_id, exc_info=True)

    await session.delete(scan)
    await session.commit()
    return True
