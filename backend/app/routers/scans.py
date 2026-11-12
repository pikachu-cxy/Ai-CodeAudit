import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, Response
import fnmatch
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import build_database_url, database_backend_name, normalize_mysql_charset, persist_runtime_settings, settings
from app.database import get_db
from app.dependencies.auth import require_admin, require_auth
from app.exceptions import DuplicateGitUrlError, DuplicateProjectNameError, WebhookValidationError, duplicate_project_http_detail
from app.models import AiVerdict, ExternalReviewStatus, Finding, FindingCategory, ReviewStatus, ScanEvent, ScanKind, ScanStatus, ScanTask, Severity, dt_iso
from app.schemas import (
    AgentTaskRequest,
    AgentTaskResponse,
    AgentActionOut,
    AgentChatMessageOut,
    AgentChatRequest,
    AgentChatResponse,
    AnalyzeRequest,
    AnalyzeResult,
    DatabaseTestRequest,
    DatabaseTestResult,
    EmailTestRequest,
    EmailTestResult,
    FeishuTestRequest,
    FeishuTestResult,
    GitLabTestRequest,
    GitLabTestResult,
    CodeqlFlowGraphOut,
    CodeLocationOut,
    ExternalReviewCodeContext,
    ExternalReviewLinkRequest,
    ExternalReviewLinkOut,
    ExternalReviewOut,
    ExternalReviewSubmitRequest,
    ExternalReviewSubmitResult,
    ProjectReviewFindingListItem,
    ProjectReviewLinkOut,
    ProjectReviewLinkRequest,
    ProjectReviewOut,
    FileContentOut,
    FindingOut,
    FindingPageOut,
    FindingReviewUpdate,
    LlmAuditCancelResponse,
    LlmDiagnosisOut,
    LlmAuditJournalEntry,
    LlmAuditRequest,
    LlmTestResult,
    PocExecuteResult,
    PocGenerateRequest,
    PocHttpRequest,
    PocResult,
    ReportPreviewOut,
    ReportSpec,
    ScanEventOut,
    ScannerInfoOut,
    ScanCreateGitLab,
    ScanDetail,
    ScanScoreOut,
    ScanStats,
    ScanSummary,
    ScanCoverageOut,
    DetectedLanguageOut,
    ScanUpdateRequest,
    SettingsOut,
    SettingsUpdate,
)
from app.services.agent_chat_service import (
    answer_scan_chat,
    append_action_event,
    append_chat_event,
    list_action_events,
    list_chat_messages,
)
from app.services.llm_audit_journal import LLM_AUDIT_PHASE, parse_journal_message
from app.services.llm_audit_runtime import is_llm_audit_cancel_requested, request_llm_audit_cancel
from app.services.scan_runtime import cancel_scan_pipeline, is_scan_cancel_requested, request_scan_cancel
from app.services.scan_service import force_pause_scan
from app.services.feishu_service import build_external_review_link, build_project_review_link, send_feishu_test_message
from app.services.email_service import send_html_email
from app.services.report_service import (
    build_scan_html_report,
    build_scan_html_report_download,
    build_scan_json_report,
    build_scan_markdown_report,
    build_scan_pdf_report,
    build_scan_report_preview,
)
from app.services.llm_provider import is_llm_configured, normalize_provider
from app.services.owasp_classifier import classify_finding
from app.services.llm_service import test_llm_connection
from app.services.database_service import test_database_connection
from app.services.scanners.common import to_repo_relative_path
from app.services.llm_audit_coverage import batch_load_llm_audit_meta
from app.services.project_languages import detected_languages_from_scanner_summary, normalize_scan_languages
from app.services.scan_coverage import build_scan_coverage, ensure_rule_inventory_persisted
from app.services.scanners.registry import list_scanners
from app.services.file_service import locate_text_in_project, read_file_with_context
from app.services.sast_flow_service import build_project_codeql_flow_graph
from app.services.scan_service import (
    analyze_scan_findings,
    analyze_sast_deep_findings,
    create_gitlab_scan,
    create_upload_scan,
    create_external_review_link,
    create_project_review_link,
    delete_scan,
    reset_scan_for_rerun,
    execute_finding_poc,
    generate_finding_poc,
    save_finding_poc_draft,
    get_scan_stats,
    ensure_scan_classifications,
    explain_llm_no_findings,
    get_finding_by_external_token,
    get_project_review_finding,
    list_project_review_findings,
    preview_sast_deep_start,
    review_llm_scan_findings,
    revoke_external_review_link,
    revoke_project_review_link,
    run_scan_pipeline,
    notify_emails_for_scan,
    start_scan_task,
    submit_external_review,
    submit_project_review_finding,
    set_scan_archived,
    update_finding_review,
    update_scan_metadata,
)
from app.services.sast_deep_runtime import (
    get_sast_deep_progress,
    is_sast_deep_cancel_requested,
    request_sast_deep_cancel,
)

router = APIRouter(prefix="/api", tags=["scans"], dependencies=[Depends(require_auth)])
public_router = APIRouter(prefix="/api", tags=["external-review"])

OWASP_IDS = {f"A{n:02d}" for n in range(1, 11)}

KNOWN_SUBTYPES = {
    "sql_injection", "xss", "command_injection", "ldap_injection", "xpath_injection",
    "nosql_injection", "ssti", "header_injection", "code_injection", "xml_injection",
    "expression_injection", "log_injection", "other_injection",
    "path_traversal", "idor", "open_redirect", "csrf", "broken_access_control",
    "hardcoded_secret", "weak_crypto", "security_misconfiguration", "vulnerable_dependency",
    "auth_failure", "deserialization", "ssrf", "other",
}


def _apply_subtype_filter(where_clauses: list, subtype: str | None) -> None:
    if not subtype:
        return
    key = subtype.strip().lower()
    if key in KNOWN_SUBTYPES:
        where_clauses.append(Finding.vuln_subtype == key)


def _apply_owasp_filter(where_clauses: list, owasp: str | None) -> None:
    if not owasp:
        return
    key = owasp.strip().upper()
    if key in OWASP_IDS:
        where_clauses.append(Finding.owasp_id == key)


LLM_FINDING_CATEGORIES = (FindingCategory.BUSINESS_LOGIC, FindingCategory.AUTHORIZATION)


def _category_filter_clause(category: str | None):
    if not category:
        return None
    c_key = category.lower().replace("-", "_")
    if c_key == "llm":
        return Finding.category.in_(LLM_FINDING_CATEGORIES)
    c = FindingCategory(c_key) if c_key in {e.value for e in FindingCategory} else None
    if c:
        return Finding.category == c
    return None


def _apply_category_filter(where_clauses: list, category: str | None) -> None:
    clause = _category_filter_clause(category)
    if clause is not None:
        where_clauses.append(clause)


def _external_status_clause(external: str | None):
    if not external:
        return None
    key = external.lower().replace("-", "_")
    if key in {e.value for e in ExternalReviewStatus}:
        return Finding.external_status == ExternalReviewStatus(key)
    return None


def _apply_external_status_filter(where_clauses: list, external: str | None) -> None:
    clause = _external_status_clause(external)
    if clause is not None:
        where_clauses.append(clause)


def _scan_status_str(scan: ScanTask) -> str:
    st = scan.status
    return st.value if hasattr(st, "value") else str(st)


def _scan_summary(
    scan: ScanTask,
    llm_audit_meta: dict | None = None,
    *,
    compact: bool = False,
) -> ScanSummary:
    kind = scan.scan_kind or ScanKind.BASELINE
    if isinstance(kind, str):
        try:
            kind = ScanKind(kind)
        except ValueError:
            kind = ScanKind.BASELINE
    cov = build_scan_coverage(
        scan.scanner_summary,
        scan_status=_scan_status_str(scan),
        llm_audit_meta=llm_audit_meta,
        compact=compact,
    )
    detected = [
        DetectedLanguageOut(**row)
        for row in detected_languages_from_scanner_summary(scan.scanner_summary)
    ]
    return ScanSummary(
        id=scan.id,
        project_id=scan.project_id,
        parent_scan_id=scan.parent_scan_id,
        scan_kind=kind,
        version_label=scan.version_label,
        name=scan.name,
        source=scan.source,
        status=scan.status,
        source_url=scan.source_url,
        branch=scan.branch,
        notify_emails=notify_emails_for_scan(scan) or None,
        progress=scan.progress,
        progress_message=scan.progress_message,
        total_findings=scan.total_findings,
        security_score=getattr(scan, "security_score", None),
        semgrep_version=scan.semgrep_version,
        # List/history payloads already carry scan_coverage; omit heavy raw JSON.
        scanner_summary=None if compact else scan.scanner_summary,
        scan_coverage=ScanCoverageOut(**cov),
        detected_languages=detected,
        error_message=scan.error_message,
        notes=scan.notes,
        created_at=dt_iso(scan.created_at) or "",
        updated_at=dt_iso(scan.updated_at),
        completed_at=dt_iso(scan.completed_at),
        archived_at=dt_iso(scan.archived_at),
    )


async def _scan_summary_with_db(db: AsyncSession, scan: ScanTask) -> ScanSummary:
    meta_map = await batch_load_llm_audit_meta(db, [scan.id])
    new_summary, changed = ensure_rule_inventory_persisted(scan.scanner_summary)
    if changed and new_summary is not None:
        scan.scanner_summary = new_summary
        await db.commit()
        await db.refresh(scan)
    return _scan_summary(scan, llm_audit_meta=meta_map.get(scan.id))


async def _scan_summaries_with_db(db: AsyncSession, scans: list[ScanTask]) -> list[ScanSummary]:
    if not scans:
        return []
    meta_map = await batch_load_llm_audit_meta(db, [s.id for s in scans])
    return [_scan_summary(s, llm_audit_meta=meta_map.get(s.id), compact=True) for s in scans]


async def _build_external_review_out(db: AsyncSession, finding: Finding) -> ExternalReviewOut:
    token_active = bool(finding.external_review_token and not finding.external_review_revoked_at)
    title = finding.message_zh or finding.message
    relative_path = finding.file_path.replace("\\", "/")
    code_context: ExternalReviewCodeContext | None = None

    scan = await db.get(ScanTask, finding.scan_id)
    if scan:
        try:
            data = read_file_with_context(
                Path(scan.project_path),
                finding.file_path,
                finding.line_start,
                finding.line_end or finding.line_start,
                context_lines=25,
            )
            relative_path = data["relative_path"]
            code_context = ExternalReviewCodeContext(
                relative_path=data["relative_path"],
                content=data["content"],
                line_start=data["line_start"],
                line_end=data["line_end"],
                highlight_start=data["highlight_start"],
                highlight_end=data["highlight_end"],
            )
        except (FileNotFoundError, ValueError, OSError):
            pass

    owasp_id = finding.owasp_id
    owasp_name = finding.owasp_name
    vuln_subtype = finding.vuln_subtype
    vuln_subtype_name = finding.vuln_subtype_name
    if not owasp_id or not vuln_subtype:
        fields = classify_finding(
            rule_id=finding.rule_id or "",
            message=finding.message or "",
            metadata_json=finding.metadata_json,
            tool=finding.tool or "",
            category=finding.category.value,
        )
        owasp_id = owasp_id or fields.get("owasp_id")
        owasp_name = owasp_name or fields.get("owasp_name")
        vuln_subtype = vuln_subtype or fields.get("vuln_subtype")
        vuln_subtype_name = vuln_subtype_name or fields.get("vuln_subtype_name")

    return ExternalReviewOut(
        finding_id=finding.id,
        title=title,
        message=finding.message,
        message_zh=finding.message_zh,
        severity=finding.severity,
        file_path=finding.file_path,
        relative_path=relative_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        rule_id=finding.rule_id,
        code_snippet=finding.code_snippet,
        ai_reason=finding.ai_reason,
        category=finding.category,
        tool=finding.tool,
        owasp_id=owasp_id,
        owasp_name=owasp_name,
        vuln_subtype=vuln_subtype,
        vuln_subtype_name=vuln_subtype_name,
        review_status=finding.review_status,
        external_status=finding.external_status,
        external_note=finding.external_note,
        external_updated_at=dt_iso(finding.external_updated_at),
        external_updated_by=finding.external_updated_by,
        token_active=token_active,
        expires_at=dt_iso(finding.external_review_expires_at),
        code_context=code_context,
    )


def _normalize_settings_focus_areas(raw) -> list[str]:
    allowed = {
        "authz",
        "business_logic",
        "ai_prompt",
        "injection",
        "rce_command",
        "deserialization",
        "ssrf",
        "sensitive_data",
    }
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in list(raw or []):
        key = str(item or "").strip().lower()
        if key not in allowed or key in seen:
            continue
        seen.add(key)
        cleaned.append(key)
    return cleaned


async def _build_settings(db: AsyncSession | None = None) -> SettingsOut:
    scanners = await list_scanners()

    auth_token_hours = settings.auth_token_expire_hours
    auth_refresh_days = settings.auth_refresh_token_expire_days
    if db is not None:
        from app.services.auth_service import get_system_setting
        val = await get_system_setting(db, "auth_token_expire_hours")
        if val is not None:
            try:
                auth_token_hours = max(0.5, min(float(val), 168))
            except (ValueError, TypeError):
                pass
        val = await get_system_setting(db, "auth_refresh_token_expire_days")
        if val is not None:
            try:
                auth_refresh_days = max(1, min(int(val), 365))
            except (ValueError, TypeError):
                pass

    return SettingsOut(
        llm_provider=settings.llm_provider,
        llm_api_base=settings.llm_api_base,
        llm_model=settings.llm_model,
        llm_model_fp=settings.llm_model_fp,
        llm_model_deep=settings.llm_model_deep,
        llm_model_agent=settings.llm_model_agent,
        llm_provider_fp=settings.llm_provider_fp,
        llm_provider_deep=settings.llm_provider_deep,
        llm_provider_agent=settings.llm_provider_agent,
        llm_enabled=settings.llm_enabled,
        llm_configured=is_llm_configured(),
        llm_timeout=settings.llm_timeout,
        semgrep_config=settings.semgrep_config,
        codeql_query_suite=settings.codeql_query_suite,
        codeql_build_mode=settings.codeql_build_mode,
        codeql_java_build_command=settings.codeql_java_build_command,
        codeql_timeout=settings.codeql_timeout,
        codeql_db_timeout=settings.codeql_db_timeout,
        llm_code_audit_enabled=settings.llm_code_audit_enabled,
        llm_audit_max_files=settings.llm_audit_max_files,
        llm_audit_file_max_chars=settings.llm_audit_file_max_chars,
        llm_audit_max_tokens=settings.llm_audit_max_tokens,
        llm_endpoint_audit_max_controllers=settings.llm_endpoint_audit_max_controllers,
        llm_endpoint_max_related_files=settings.llm_endpoint_max_related_files,
        llm_endpoint_audit_max_iterations=settings.llm_endpoint_audit_max_iterations,
        llm_endpoint_audit_max_domains=settings.llm_endpoint_audit_max_domains,
        llm_endpoint_origin_sample_per_domain=settings.llm_endpoint_origin_sample_per_domain,
        llm_agent_max_tool_rounds=settings.llm_agent_max_tool_rounds,
        llm_audit_profile=settings.llm_audit_profile,
        llm_audit_require_stronger_evidence=bool(settings.llm_audit_require_stronger_evidence),
        llm_audit_enable_broader_hypotheses=bool(settings.llm_audit_enable_broader_hypotheses),
        llm_audit_focus_areas=_normalize_settings_focus_areas(settings.llm_audit_focus_areas),
        feishu_webhook_url=settings.feishu_webhook_url,
        feishu_at_user_ids=settings.feishu_at_user_ids,
        feishu_notify_min_severity=settings.feishu_notify_min_severity,
        feishu_configured=bool((settings.feishu_webhook_url or "").strip()),
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_user=settings.smtp_user,
        smtp_tls=bool(settings.smtp_tls),
        email_from=settings.email_from,
        smtp_password_configured=bool((settings.smtp_password or "").strip()),
        frontend_base_url=settings.frontend_base_url,
        gitlab_default_url=settings.gitlab_default_url,
        gitlab_default_branch=settings.gitlab_default_branch,
        gitlab_access_token_configured=bool((settings.gitlab_access_token or "").strip()),
        gitlab_tls_verify=bool(settings.gitlab_tls_verify),
        webhook_token_configured=bool((settings.webhook_token or "").strip()),
        semgrep_timeout=settings.semgrep_timeout,
        enabled_scanners=settings.enabled_scanners,
        exclude_test_paths=bool(settings.exclude_test_paths),
        scanners=[ScannerInfoOut.model_validate(s) for s in scanners],
        database_backend=database_backend_name(),
        database_url=settings.database_url or "",
        mysql_host=settings.mysql_host,
        mysql_port=settings.mysql_port,
        mysql_user=settings.mysql_user,
        mysql_database=settings.mysql_database,
        mysql_charset=normalize_mysql_charset(settings.mysql_charset),
        mysql_password_configured=bool((settings.mysql_password or "").strip()),
        database_restart_required=False,
        database_switched=False,
        auth_token_expire_hours=auth_token_hours,
        auth_refresh_token_expire_days=auth_refresh_days,
        score_weight_critical=int(settings.score_weight_critical),
        score_weight_high=int(settings.score_weight_high),
        score_weight_medium=int(settings.score_weight_medium),
        score_weight_low=int(settings.score_weight_low),
        score_weight_info=int(settings.score_weight_info),
        score_weight_unknown=int(settings.score_weight_unknown),
        score_exclude_ai_fp=bool(settings.score_exclude_ai_fp),
    )


@router.post("/settings/test-llm", response_model=LlmTestResult)
async def test_llm(_user: dict = Depends(require_admin)):
    result = await test_llm_connection()
    return LlmTestResult(**result)


@router.post("/settings/test-feishu", response_model=FeishuTestResult)
async def test_feishu(
    body: FeishuTestRequest | None = None,
    _user: dict = Depends(require_admin),
):
    req = body or FeishuTestRequest()
    # Apply form values to runtime settings so test uses latest UI input.
    changed: dict[str, object] = {}
    if req.feishu_webhook_url is not None:
        settings.feishu_webhook_url = (req.feishu_webhook_url or "").strip()
        changed["FEISHU_WEBHOOK_URL"] = settings.feishu_webhook_url
    if req.feishu_at_user_ids is not None:
        settings.feishu_at_user_ids = [str(u).strip() for u in req.feishu_at_user_ids if str(u).strip()]
        changed["FEISHU_AT_USER_IDS"] = settings.feishu_at_user_ids
    if req.frontend_base_url is not None:
        settings.frontend_base_url = (req.frontend_base_url or "").strip().rstrip("/")
        changed["FRONTEND_BASE_URL"] = settings.frontend_base_url
    if changed:
        persist_runtime_settings(changed)

    result = send_feishu_test_message(
        override_webhook_url=settings.feishu_webhook_url,
        override_at_user_ids=settings.feishu_at_user_ids,
        override_frontend_base_url=settings.frontend_base_url,
    )
    return FeishuTestResult(**result)


@router.post("/settings/test-email", response_model=EmailTestResult)
async def test_email(
    body: EmailTestRequest | None = None,
    _user: dict = Depends(require_admin),
):
    req = body or EmailTestRequest()
    host = (req.smtp_host if req.smtp_host is not None else settings.smtp_host).strip()
    port = int(req.smtp_port if req.smtp_port is not None else settings.smtp_port or 465)
    user = (req.smtp_user if req.smtp_user is not None else settings.smtp_user).strip()
    pwd = (req.smtp_password if req.smtp_password is not None else settings.smtp_password).strip()
    tls = bool(req.smtp_tls if req.smtp_tls is not None else settings.smtp_tls)
    email_from = (req.email_from if req.email_from is not None else settings.email_from).strip()
    to_email = (req.to_email or "").strip()
    if not host or not email_from or not to_email:
        return EmailTestResult(ok=False, message="请填写 smtp_host、email_from、to_email")
    if user and not pwd:
        return EmailTestResult(ok=False, message="已填写 SMTP 用户名但未提供密码。请填写密码或先在设置中保存。")
    old_cfg = (
        settings.smtp_host,
        settings.smtp_port,
        settings.smtp_user,
        settings.smtp_password,
        settings.smtp_tls,
        settings.email_from,
    )
    try:
        settings.smtp_host = host
        settings.smtp_port = port
        settings.smtp_user = user
        settings.smtp_password = pwd
        settings.smtp_tls = tls
        settings.email_from = email_from
        await send_html_email(
            to_email=to_email,
            subject="AI Audit 邮件测试",
            html_body="<h3>邮件配置成功</h3><p>这是一封测试邮件。</p>",
        )
        return EmailTestResult(ok=True, message="测试邮件发送成功")
    except Exception as exc:
        return EmailTestResult(ok=False, message=f"发送失败: {exc}")
    finally:
        settings.smtp_host, settings.smtp_port, settings.smtp_user, settings.smtp_password, settings.smtp_tls, settings.email_from = old_cfg


@router.post("/settings/test-gitlab", response_model=GitLabTestResult)
async def test_gitlab(
    body: GitLabTestRequest | None = None,
    _user: dict = Depends(require_admin),
):
    from urllib.parse import urlparse

    from app.services.gitlab_service import probe_gitlab_repo, split_project_url

    req = body or GitLabTestRequest()
    project_url = (req.project_url or "").strip()
    if not project_url:
        return GitLabTestResult(ok=False, code="missing_parameter", http_status=400, message="请填写 project_url")
    token = (req.access_token or "").strip() or (settings.gitlab_access_token or "").strip()
    if not token:
        return GitLabTestResult(
            ok=False,
            code="token_permission_insufficient",
            http_status=403,
            message="未配置 GitLab Access Token",
        )
    branch = (req.branch or "").strip() or (settings.gitlab_default_branch or "main")
    try:
        gitlab_url, project_path_id = split_project_url(project_url)
    except ValueError as exc:
        return GitLabTestResult(ok=False, code="gitlab_address_invalid", http_status=404, message=str(exc))
    allowed_host = (urlparse(settings.gitlab_default_url).netloc or "").strip().lower()
    parsed_host = (urlparse(project_url).netloc or "").strip().lower()
    if allowed_host and parsed_host and parsed_host != allowed_host:
        return GitLabTestResult(
            ok=False,
            code="gitlab_address_invalid",
            http_status=404,
            message=f"Git 地址须使用已配置的 GitLab：{allowed_host}",
        )
    try:
        await probe_gitlab_repo(gitlab_url, project_path_id, branch, token)
        return GitLabTestResult(ok=True, message="GitLab 仓库可访问")
    except WebhookValidationError as exc:
        return GitLabTestResult(ok=False, code=exc.code, http_status=exc.http_status, message=exc.message)


@router.post("/settings/test-database", response_model=DatabaseTestResult)
async def test_database(
    body: DatabaseTestRequest | None = None,
    _user: dict = Depends(require_admin),
):
    req = body or DatabaseTestRequest()
    backend = (req.database_backend or settings.database_backend or "sqlite").strip().lower()
    password = req.mysql_password
    if password is None or password == "":
        password = settings.mysql_password
    ok, message = await test_database_connection(
        database_backend=backend,
        database_url=(req.database_url or settings.database_url or "").strip(),
        mysql_host=(req.mysql_host or settings.mysql_host or "127.0.0.1").strip(),
        mysql_port=req.mysql_port if req.mysql_port is not None else settings.mysql_port,
        mysql_user=(req.mysql_user or settings.mysql_user or "ai_audit").strip(),
        mysql_password=password or "",
        mysql_database=(req.mysql_database or settings.mysql_database or "ai_audit_dev").strip(),
        mysql_charset=(req.mysql_charset or settings.mysql_charset or "utf8mb4"),
        db_path=str(settings.db_path),
    )
    return DatabaseTestResult(ok=ok, message=message)


@router.get("/scanners", response_model=list[ScannerInfoOut])
async def get_scanners():
    scanners = await list_scanners()
    return [ScannerInfoOut.model_validate(s) for s in scanners]


@router.get("/settings", response_model=SettingsOut)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    return await _build_settings(db)


@router.put("/settings", response_model=SettingsOut)
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _user: dict = Depends(require_admin),
):
    changed: dict[str, object] = {}
    if body.llm_provider is not None:
        settings.llm_provider = normalize_provider(body.llm_provider)
        changed["LLM_PROVIDER"] = settings.llm_provider
    if body.llm_api_base is not None:
        settings.llm_api_base = body.llm_api_base
        changed["LLM_API_BASE"] = body.llm_api_base
    if body.llm_api_key is not None:
        settings.llm_api_key = body.llm_api_key
        changed["LLM_API_KEY"] = body.llm_api_key
    if body.llm_model is not None:
        settings.llm_model = body.llm_model
        changed["LLM_MODEL"] = body.llm_model
    if body.llm_model_fp is not None:
        settings.llm_model_fp = body.llm_model_fp
        changed["LLM_MODEL_FP"] = body.llm_model_fp
    if body.llm_model_deep is not None:
        settings.llm_model_deep = body.llm_model_deep
        changed["LLM_MODEL_DEEP"] = body.llm_model_deep
    if body.llm_model_agent is not None:
        settings.llm_model_agent = body.llm_model_agent
        changed["LLM_MODEL_AGENT"] = body.llm_model_agent
    if body.llm_provider_fp is not None:
        settings.llm_provider_fp = normalize_provider(body.llm_provider_fp) if body.llm_provider_fp else ""
        changed["LLM_PROVIDER_FP"] = settings.llm_provider_fp
    if body.llm_provider_deep is not None:
        settings.llm_provider_deep = normalize_provider(body.llm_provider_deep) if body.llm_provider_deep else ""
        changed["LLM_PROVIDER_DEEP"] = settings.llm_provider_deep
    if body.llm_provider_agent is not None:
        settings.llm_provider_agent = normalize_provider(body.llm_provider_agent) if body.llm_provider_agent else ""
        changed["LLM_PROVIDER_AGENT"] = settings.llm_provider_agent
    if body.llm_timeout is not None:
        settings.llm_timeout = body.llm_timeout
        changed["LLM_TIMEOUT"] = body.llm_timeout
    if body.llm_enabled is not None:
        settings.llm_enabled = body.llm_enabled
        changed["LLM_ENABLED"] = body.llm_enabled
    if body.semgrep_config is not None:
        settings.semgrep_config = body.semgrep_config
        changed["SEMGREP_CONFIG"] = body.semgrep_config
    if body.codeql_query_suite is not None:
        settings.codeql_query_suite = body.codeql_query_suite
        changed["CODEQL_QUERY_SUITE"] = body.codeql_query_suite
    if body.codeql_build_mode is not None:
        mode = (body.codeql_build_mode or "").strip().lower()
        if mode in ("autobuild", "manual", "none"):
            settings.codeql_build_mode = mode
            changed["CODEQL_BUILD_MODE"] = mode
        else:
            raise HTTPException(400, "codeql_build_mode 仅支持 autobuild / manual / none")
    if body.codeql_java_build_command is not None:
        settings.codeql_java_build_command = body.codeql_java_build_command
        changed["CODEQL_JAVA_BUILD_COMMAND"] = body.codeql_java_build_command
    if body.codeql_timeout is not None:
        settings.codeql_timeout = body.codeql_timeout
        changed["CODEQL_TIMEOUT"] = body.codeql_timeout
    if body.codeql_db_timeout is not None:
        settings.codeql_db_timeout = body.codeql_db_timeout
        changed["CODEQL_DB_TIMEOUT"] = body.codeql_db_timeout
    if body.llm_code_audit_enabled is not None:
        settings.llm_code_audit_enabled = body.llm_code_audit_enabled
        changed["LLM_CODE_AUDIT_ENABLED"] = body.llm_code_audit_enabled
    if body.llm_audit_max_files is not None:
        settings.llm_audit_max_files = max(1, body.llm_audit_max_files)
        changed["LLM_AUDIT_MAX_FILES"] = settings.llm_audit_max_files
    if body.llm_audit_file_max_chars is not None:
        settings.llm_audit_file_max_chars = max(1000, body.llm_audit_file_max_chars)
        changed["LLM_AUDIT_FILE_MAX_CHARS"] = settings.llm_audit_file_max_chars
    if body.llm_audit_max_tokens is not None:
        settings.llm_audit_max_tokens = max(1024, body.llm_audit_max_tokens)
        changed["LLM_AUDIT_MAX_TOKENS"] = settings.llm_audit_max_tokens
    if body.llm_endpoint_audit_max_controllers is not None:
        settings.llm_endpoint_audit_max_controllers = max(1, min(body.llm_endpoint_audit_max_controllers, 200))
        changed["LLM_ENDPOINT_AUDIT_MAX_CONTROLLERS"] = settings.llm_endpoint_audit_max_controllers
    if body.llm_endpoint_max_related_files is not None:
        settings.llm_endpoint_max_related_files = max(0, min(body.llm_endpoint_max_related_files, 20))
        changed["LLM_ENDPOINT_MAX_RELATED_FILES"] = settings.llm_endpoint_max_related_files
    if body.llm_endpoint_audit_max_iterations is not None:
        settings.llm_endpoint_audit_max_iterations = max(5, min(body.llm_endpoint_audit_max_iterations, 80))
        changed["LLM_ENDPOINT_AUDIT_MAX_ITERATIONS"] = settings.llm_endpoint_audit_max_iterations
    if body.llm_endpoint_audit_max_domains is not None:
        settings.llm_endpoint_audit_max_domains = max(1, min(body.llm_endpoint_audit_max_domains, 10))
        changed["LLM_ENDPOINT_AUDIT_MAX_DOMAINS"] = settings.llm_endpoint_audit_max_domains
    if body.llm_endpoint_origin_sample_per_domain is not None:
        settings.llm_endpoint_origin_sample_per_domain = max(1, min(body.llm_endpoint_origin_sample_per_domain, 20))
        changed["LLM_ENDPOINT_ORIGIN_SAMPLE_PER_DOMAIN"] = settings.llm_endpoint_origin_sample_per_domain
    if body.llm_agent_max_tool_rounds is not None:
        settings.llm_agent_max_tool_rounds = max(1, min(body.llm_agent_max_tool_rounds, 30))
        changed["LLM_AGENT_MAX_TOOL_ROUNDS"] = settings.llm_agent_max_tool_rounds
    if body.llm_audit_profile is not None:
        profile = (body.llm_audit_profile or "").strip().lower()
        if profile not in ("stable", "balanced", "broad"):
            raise HTTPException(400, "llm_audit_profile 仅支持 stable / balanced / broad")
        settings.llm_audit_profile = profile
        changed["LLM_AUDIT_PROFILE"] = settings.llm_audit_profile
    if body.llm_audit_require_stronger_evidence is not None:
        settings.llm_audit_require_stronger_evidence = bool(body.llm_audit_require_stronger_evidence)
        changed["LLM_AUDIT_REQUIRE_STRONGER_EVIDENCE"] = settings.llm_audit_require_stronger_evidence
    if body.llm_audit_enable_broader_hypotheses is not None:
        settings.llm_audit_enable_broader_hypotheses = bool(body.llm_audit_enable_broader_hypotheses)
        changed["LLM_AUDIT_ENABLE_BROADER_HYPOTHESES"] = settings.llm_audit_enable_broader_hypotheses
    if body.llm_audit_focus_areas is not None:
        cleaned = _normalize_settings_focus_areas(body.llm_audit_focus_areas)
        settings.llm_audit_focus_areas = cleaned
        changed["LLM_AUDIT_FOCUS_AREAS"] = settings.llm_audit_focus_areas
    if body.feishu_webhook_url is not None:
        settings.feishu_webhook_url = (body.feishu_webhook_url or "").strip()
        changed["FEISHU_WEBHOOK_URL"] = settings.feishu_webhook_url
    if body.feishu_at_user_ids is not None:
        cleaned = [str(u).strip() for u in (body.feishu_at_user_ids or []) if str(u).strip()]
        settings.feishu_at_user_ids = cleaned
        changed["FEISHU_AT_USER_IDS"] = settings.feishu_at_user_ids
    if body.feishu_notify_min_severity is not None:
        sev = (body.feishu_notify_min_severity or "").strip().upper()
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if sev in valid:
            settings.feishu_notify_min_severity = sev
            changed["FEISHU_NOTIFY_MIN_SEVERITY"] = settings.feishu_notify_min_severity
    if body.smtp_host is not None:
        settings.smtp_host = (body.smtp_host or "").strip()
        changed["SMTP_HOST"] = settings.smtp_host
    if body.smtp_port is not None:
        settings.smtp_port = max(1, min(int(body.smtp_port), 65535))
        changed["SMTP_PORT"] = settings.smtp_port
    if body.smtp_user is not None:
        settings.smtp_user = (body.smtp_user or "").strip()
        changed["SMTP_USER"] = settings.smtp_user
    if body.smtp_password is not None:
        pwd = (body.smtp_password or "").strip()
        if pwd:
            settings.smtp_password = pwd
            changed["SMTP_PASSWORD"] = pwd
    if body.smtp_tls is not None:
        settings.smtp_tls = bool(body.smtp_tls)
        changed["SMTP_TLS"] = settings.smtp_tls
    if body.email_from is not None:
        settings.email_from = (body.email_from or "").strip()
        changed["EMAIL_FROM"] = settings.email_from
    if body.frontend_base_url is not None:
        settings.frontend_base_url = (body.frontend_base_url or "").strip().rstrip("/")
        changed["FRONTEND_BASE_URL"] = settings.frontend_base_url
    if body.gitlab_default_url is not None:
        settings.gitlab_default_url = (body.gitlab_default_url or "").strip().rstrip("/") or "https://gitlab.com"
        changed["GITLAB_DEFAULT_URL"] = settings.gitlab_default_url
    if body.gitlab_access_token is not None:
        token = (body.gitlab_access_token or "").strip()
        # Empty string means "keep existing" so UI can leave password blank.
        if token:
            settings.gitlab_access_token = token
            changed["GITLAB_ACCESS_TOKEN"] = token
    if body.gitlab_default_branch is not None:
        settings.gitlab_default_branch = (body.gitlab_default_branch or "").strip() or "main"
        changed["GITLAB_DEFAULT_BRANCH"] = settings.gitlab_default_branch
    if body.gitlab_tls_verify is not None:
        settings.gitlab_tls_verify = bool(body.gitlab_tls_verify)
        changed["GITLAB_TLS_VERIFY"] = settings.gitlab_tls_verify
    if body.webhook_token is not None:
        token = (body.webhook_token or "").strip()
        # Empty string means "keep existing" so UI can leave password blank.
        if token:
            settings.webhook_token = token
            changed["WEBHOOK_TOKEN"] = token
    if body.semgrep_timeout is not None:
        settings.semgrep_timeout = max(60, body.semgrep_timeout)
        changed["SEMGREP_TIMEOUT"] = settings.semgrep_timeout
    if body.enabled_scanners is not None:
        settings.enabled_scanners = body.enabled_scanners
        changed["ENABLED_SCANNERS"] = body.enabled_scanners
    if body.exclude_test_paths is not None:
        settings.exclude_test_paths = bool(body.exclude_test_paths)
        changed["EXCLUDE_TEST_PATHS"] = settings.exclude_test_paths
    if body.auth_token_expire_hours is not None:
        hours = max(0.5, min(float(body.auth_token_expire_hours), 168))
        settings.auth_token_expire_hours = hours
        from app.services.auth_service import set_system_setting
        await set_system_setting(db, "auth_token_expire_hours", str(hours))
    if body.auth_refresh_token_expire_days is not None:
        days = max(1, min(int(body.auth_refresh_token_expire_days), 365))
        settings.auth_refresh_token_expire_days = days
        from app.services.auth_service import set_system_setting
        await set_system_setting(db, "auth_refresh_token_expire_days", str(days))
    if body.score_weight_critical is not None:
        v = max(0, min(int(body.score_weight_critical), 100))
        if v != int(settings.score_weight_critical):
            settings.score_weight_critical = v
            changed["SCORE_WEIGHT_CRITICAL"] = v
    if body.score_weight_high is not None:
        v = max(0, min(int(body.score_weight_high), 100))
        if v != int(settings.score_weight_high):
            settings.score_weight_high = v
            changed["SCORE_WEIGHT_HIGH"] = v
    if body.score_weight_medium is not None:
        v = max(0, min(int(body.score_weight_medium), 100))
        if v != int(settings.score_weight_medium):
            settings.score_weight_medium = v
            changed["SCORE_WEIGHT_MEDIUM"] = v
    if body.score_weight_low is not None:
        v = max(0, min(int(body.score_weight_low), 100))
        if v != int(settings.score_weight_low):
            settings.score_weight_low = v
            changed["SCORE_WEIGHT_LOW"] = v
    if body.score_weight_info is not None:
        v = max(0, min(int(body.score_weight_info), 100))
        if v != int(settings.score_weight_info):
            settings.score_weight_info = v
            changed["SCORE_WEIGHT_INFO"] = v
    if body.score_weight_unknown is not None:
        v = max(0, min(int(body.score_weight_unknown), 100))
        if v != int(settings.score_weight_unknown):
            settings.score_weight_unknown = v
            changed["SCORE_WEIGHT_UNKNOWN"] = v
    if body.score_exclude_ai_fp is not None:
        v = bool(body.score_exclude_ai_fp)
        if v != bool(settings.score_exclude_ai_fp):
            settings.score_exclude_ai_fp = v
            changed["SCORE_EXCLUDE_AI_FP"] = v

    db_snapshot = {
        "database_backend": settings.database_backend,
        "database_url": settings.database_url,
        "mysql_host": settings.mysql_host,
        "mysql_port": settings.mysql_port,
        "mysql_user": settings.mysql_user,
        "mysql_password": settings.mysql_password,
        "mysql_database": settings.mysql_database,
        "mysql_charset": settings.mysql_charset,
    }
    old_db_url = build_database_url()
    db_changed = False
    if body.database_backend is not None:
        backend = (body.database_backend or "sqlite").strip().lower()
        if backend not in ("sqlite", "mysql"):
            raise HTTPException(400, "database_backend 必须是 sqlite 或 mysql")
        settings.database_backend = backend
        changed["DATABASE_BACKEND"] = backend
        db_changed = True
    if body.database_url is not None:
        settings.database_url = (body.database_url or "").strip()
        changed["DATABASE_URL"] = settings.database_url
        db_changed = True
    if body.mysql_host is not None:
        settings.mysql_host = (body.mysql_host or "127.0.0.1").strip()
        changed["MYSQL_HOST"] = settings.mysql_host
        db_changed = True
    if body.mysql_port is not None:
        settings.mysql_port = max(1, min(int(body.mysql_port), 65535))
        changed["MYSQL_PORT"] = settings.mysql_port
        db_changed = True
    if body.mysql_user is not None:
        settings.mysql_user = (body.mysql_user or "").strip()
        changed["MYSQL_USER"] = settings.mysql_user
        db_changed = True
    if body.mysql_password is not None:
        pwd = (body.mysql_password or "").strip()
        if pwd:
            settings.mysql_password = pwd
            changed["MYSQL_PASSWORD"] = pwd
            db_changed = True
    if body.mysql_database is not None:
        settings.mysql_database = (body.mysql_database or "ai_audit_dev").strip()
        changed["MYSQL_DATABASE"] = settings.mysql_database
        db_changed = True
    if body.mysql_charset is not None:
        settings.mysql_charset = normalize_mysql_charset(body.mysql_charset)
        changed["MYSQL_CHARSET"] = settings.mysql_charset
        db_changed = True

    db_target_changed = db_changed and build_database_url() != old_db_url

    score_setting_keys = {
        "SCORE_WEIGHT_CRITICAL",
        "SCORE_WEIGHT_HIGH",
        "SCORE_WEIGHT_MEDIUM",
        "SCORE_WEIGHT_LOW",
        "SCORE_WEIGHT_INFO",
        "SCORE_WEIGHT_UNKNOWN",
        "SCORE_EXCLUDE_AI_FP",
    }
    scores_recalculated: int | None = None
    if changed.keys() & score_setting_keys:
        from app.services.score_service import recalculate_all_cached_scores

        scores_recalculated = await recalculate_all_cached_scores(db, commit=False)

    if changed:
        persist_runtime_settings(changed)
    await db.commit()
    out = await _build_settings(db)
    if scores_recalculated is not None:
        out.scores_recalculated = scores_recalculated
    if db_target_changed:
        try:
            from app.database import reconfigure_database

            await reconfigure_database()
        except Exception as exc:
            for key, value in db_snapshot.items():
                setattr(settings, key, value)
            persist_runtime_settings(
                {
                    "DATABASE_BACKEND": settings.database_backend,
                    "DATABASE_URL": settings.database_url or "",
                    "MYSQL_HOST": settings.mysql_host,
                    "MYSQL_PORT": settings.mysql_port,
                    "MYSQL_USER": settings.mysql_user,
                    "MYSQL_PASSWORD": settings.mysql_password,
                    "MYSQL_DATABASE": settings.mysql_database,
                    "MYSQL_CHARSET": settings.mysql_charset,
                }
            )
            raise HTTPException(400, f"数据库切换失败，已保持原连接: {exc}") from exc
        return out.model_copy(update={"database_switched": True, "database_restart_required": False})
    return out


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    q: str | None = None,
    status: ScanStatus | None = None,
    archived: str = Query("false", pattern="^(false|true|all)$"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ScanTask)
    if archived == "false":
        stmt = stmt.where(ScanTask.archived_at.is_(None))
    elif archived == "true":
        stmt = stmt.where(ScanTask.archived_at.isnot(None))
    if status is not None:
        stmt = stmt.where(ScanTask.status == status)
    if q and q.strip():
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                ScanTask.name.ilike(pattern),
                ScanTask.notes.ilike(pattern),
                ScanTask.source_url.ilike(pattern),
            )
        )
    stmt = stmt.order_by(ScanTask.updated_at.desc(), ScanTask.created_at.desc())
    scans = (await db.execute(stmt)).scalars().all()
    return await _scan_summaries_with_db(db, list(scans))


@router.patch("/scans/{scan_id}", response_model=ScanSummary)
async def patch_scan(scan_id: int, body: ScanUpdateRequest, db: AsyncSession = Depends(get_db)):
    if body.name is None and body.notes is None:
        raise HTTPException(400, "No fields to update")
    try:
        scan = await update_scan_metadata(db, scan_id, name=body.name, notes=body.notes)
    except ValueError as exc:
        msg = str(exc)
        if msg == "invalid name":
            raise HTTPException(400, "Name must be 1–255 characters") from exc
        if msg == "notes too long":
            raise HTTPException(400, "Notes must be at most 2000 characters") from exc
        raise HTTPException(400, msg) from exc
    if not scan:
        raise HTTPException(404, "Scan not found")
    return await _scan_summary_with_db(db, scan)


@router.post("/scans/{scan_id}/archive", response_model=ScanSummary)
async def archive_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    try:
        scan = await set_scan_archived(db, scan_id, archived=True)
    except ValueError as exc:
        raise HTTPException(400, "Cannot archive a scan that is currently running") from exc
    if not scan:
        raise HTTPException(404, "Scan not found")
    return await _scan_summary_with_db(db, scan)


@router.post("/scans/{scan_id}/unarchive", response_model=ScanSummary)
async def unarchive_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await set_scan_archived(db, scan_id, archived=False)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return await _scan_summary_with_db(db, scan)


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: int,
    include_findings: bool = Query(False, description="Include all findings (heavy; prefer /findings/page)"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ScanTask).where(ScanTask.id == scan_id)
    if include_findings:
        stmt = stmt.options(selectinload(ScanTask.findings))
    scan = (await db.execute(stmt)).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    detail = await _scan_summary_with_db(db, scan)
    findings_out: list[FindingOut] = []
    if include_findings:
        findings_out = [FindingOut.model_validate(f) for f in (scan.findings or [])]
    return ScanDetail(**detail.model_dump(), findings=findings_out)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
async def get_findings(
    scan_id: int,
    severity: str | None = None,
    verdict: str | None = None,
    review: str | None = None,
    external: str | None = None,
    category: str | None = None,
    tool: str | None = None,
    owasp: str | None = None,
    subtype: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        sev_key = severity.upper()
        sev = Severity[sev_key] if sev_key in Severity.__members__ else None
        if sev:
            stmt = stmt.where(Finding.severity == sev)
    if verdict:
        v_key = verdict.lower().replace("-", "_")
        v = AiVerdict(v_key) if v_key in {e.value for e in AiVerdict} else None
        if v:
            stmt = stmt.where(Finding.ai_verdict == v)
    if review:
        r_key = review.lower().replace("-", "_")
        r = ReviewStatus(r_key) if r_key in {e.value for e in ReviewStatus} else None
        if r:
            stmt = stmt.where(Finding.review_status == r)
    ext_clause = _external_status_clause(external)
    if ext_clause is not None:
        stmt = stmt.where(ext_clause)
    cat_clause = _category_filter_clause(category)
    if cat_clause is not None:
        stmt = stmt.where(cat_clause)
    if tool and tool.lower() != "undefined":
        stmt = stmt.where(Finding.tool == tool)
    if owasp:
        key = owasp.strip().upper()
        if key in OWASP_IDS:
            stmt = stmt.where(Finding.owasp_id == key)
    if subtype:
        sub = subtype.strip().lower()
        if sub in KNOWN_SUBTYPES:
            stmt = stmt.where(Finding.vuln_subtype == sub)
    findings = (await db.execute(stmt)).scalars().all()
    return [FindingOut.model_validate(f) for f in findings]


@router.get("/scans/{scan_id}/findings/page", response_model=FindingPageOut)
async def get_findings_page(
    scan_id: int,
    severity: str | None = None,
    verdict: str | None = None,
    review: str | None = None,
    external: str | None = None,
    category: str | None = None,
    tool: str | None = None,
    owasp: str | None = None,
    subtype: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    await ensure_scan_classifications(db, scan_id)

    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    where_clauses = [Finding.scan_id == scan_id]

    if severity:
        sev_key = severity.upper()
        sev = Severity[sev_key] if sev_key in Severity.__members__ else None
        if sev:
            where_clauses.append(Finding.severity == sev)
    if verdict:
        v_key = verdict.lower().replace("-", "_")
        v = AiVerdict(v_key) if v_key in {e.value for e in AiVerdict} else None
        if v:
            where_clauses.append(Finding.ai_verdict == v)
    if review:
        r_key = review.lower().replace("-", "_")
        r = ReviewStatus(r_key) if r_key in {e.value for e in ReviewStatus} else None
        if r:
            where_clauses.append(Finding.review_status == r)
    _apply_external_status_filter(where_clauses, external)
    _apply_category_filter(where_clauses, category)
    if tool and tool.lower() != "undefined":
        where_clauses.append(Finding.tool == tool)
    _apply_owasp_filter(where_clauses, owasp)
    _apply_subtype_filter(where_clauses, subtype)
    if q:
        qq = q.strip()
        if qq:
            like = f"%{qq}%"
            where_clauses.append(
                (Finding.message.ilike(like))
                | (Finding.message_zh.ilike(like))
                | (Finding.rule_id.ilike(like))
                | (Finding.file_path.ilike(like))
            )

    total_stmt = select(func.count()).select_from(Finding).where(*where_clauses)
    total = (await db.execute(total_stmt)).scalar() or 0

    stmt = (
        select(Finding)
        .where(*where_clauses)
        .order_by(Finding.severity.desc(), Finding.id.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return FindingPageOut(
        total=total,
        limit=limit,
        offset=offset,
        items=[FindingOut.model_validate(f) for f in rows],
    )


@router.get("/scans/{scan_id}/findings/{finding_id}", response_model=FindingOut)
async def get_finding(scan_id: int, finding_id: int, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(404, "Finding not found")
    return FindingOut.model_validate(finding)


@router.patch("/scans/{scan_id}/findings/{finding_id}/review", response_model=FindingOut)
async def review_finding(
    scan_id: int,
    finding_id: int,
    body: FindingReviewUpdate,
    db: AsyncSession = Depends(get_db),
):
    try:
        finding = await update_finding_review(
            db, scan_id, finding_id, body.review_status, body.review_note, body.generate_poc
        )
    except ValueError as exc:
        msg = str(exc)
        if "误报" in msg:
            raise HTTPException(400, msg) from exc
        raise HTTPException(404, "Finding not found") from exc
    return FindingOut.model_validate(finding)


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def get_scan_report_html(
    scan_id: int,
    download: bool = Query(
        False,
        description="true 时以附件形式返回（带 Content-Disposition），否则作为 HTML 预览返回",
    ),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if download:
        html, filename = await build_scan_html_report_download(db, scan_id)
        return Response(
            content=html.encode("utf-8"),
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    html = await build_scan_html_report(db, scan_id)
    return HTMLResponse(content=html)


@router.get("/scans/{scan_id}/report.pdf")
async def get_scan_report_pdf(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(400, "Scan is not completed")
    try:
        blob, filename = await build_scan_pdf_report(db, scan_id)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return Response(
        content=blob,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.md")
async def get_scan_report_markdown(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(400, "Scan is not completed")
    text, filename = await build_scan_markdown_report(db, scan_id)
    return Response(
        content=text.encode("utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.json")
async def get_scan_report_json(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(400, "Scan is not completed")
    blob, filename = await build_scan_json_report(db, scan_id)
    return Response(
        content=blob,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# 自定义报告（POST 版本）
#
# 与上面的 GET 端点等价，但接受 ReportSpec：可按 finding_ids 勾选、按条件筛选，
# 并配置内容开关 / 分组 / 排序。不传 body 时行为与 GET 完全一致。
# 批量 id 走 body 而非 query，避免 URL 超长。
# ---------------------------------------------------------------------------


def _report_http_error(exc: Exception) -> HTTPException:
    """RuntimeError 视为服务端依赖问题（503），其余为请求参数问题（400）。"""
    if isinstance(exc, RuntimeError):
        return HTTPException(503, str(exc))
    return HTTPException(400, str(exc))


async def _require_completed_scan(db: AsyncSession, scan_id: int) -> ScanTask:
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(400, "Scan is not completed")
    return scan


@router.post("/scans/{scan_id}/report/preview", response_model=ReportPreviewOut)
async def preview_scan_report(
    scan_id: int,
    body: ReportSpec | None = None,
    db: AsyncSession = Depends(get_db),
):
    await _require_completed_scan(db, scan_id)
    try:
        return await build_scan_report_preview(db, scan_id, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def post_scan_report_html(
    scan_id: int,
    body: ReportSpec | None = None,
    download: bool = Query(
        False,
        description="true 时以附件形式返回（带 Content-Disposition），否则作为 HTML 预览返回",
    ),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    try:
        if download:
            html, filename = await build_scan_html_report_download(db, scan_id, body)
            return Response(
                content=html.encode("utf-8"),
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        html = await build_scan_html_report(db, scan_id, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return HTMLResponse(content=html)


@router.post("/scans/{scan_id}/report.pdf")
async def post_scan_report_pdf(
    scan_id: int,
    body: ReportSpec | None = None,
    db: AsyncSession = Depends(get_db),
):
    await _require_completed_scan(db, scan_id)
    try:
        blob, filename = await build_scan_pdf_report(db, scan_id, body)
    except (ValueError, RuntimeError) as exc:
        raise _report_http_error(exc) from exc
    return Response(
        content=blob,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scans/{scan_id}/report.md")
async def post_scan_report_markdown(
    scan_id: int,
    body: ReportSpec | None = None,
    db: AsyncSession = Depends(get_db),
):
    await _require_completed_scan(db, scan_id)
    try:
        text, filename = await build_scan_markdown_report(db, scan_id, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return Response(
        content=text.encode("utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scans/{scan_id}/report.json")
async def post_scan_report_json(
    scan_id: int,
    body: ReportSpec | None = None,
    db: AsyncSession = Depends(get_db),
):
    await _require_completed_scan(db, scan_id)
    try:
        blob, filename = await build_scan_json_report(db, scan_id, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return Response(
        content=blob,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/scans/{scan_id}/findings/{finding_id}/external-review-link", response_model=ExternalReviewLinkOut)
async def create_external_link(
    scan_id: int,
    finding_id: int,
    body: ExternalReviewLinkRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        finding = await create_external_review_link(
            db, scan_id, finding_id, expires_hours=body.expires_hours
        )
    except ValueError:
        raise HTTPException(404, "Finding not found")
    return ExternalReviewLinkOut(
        ok=True,
        url=build_external_review_link(str(finding.external_review_token or "")),
        token_active=bool(finding.external_review_token and not finding.external_review_revoked_at),
        expires_at=dt_iso(finding.external_review_expires_at),
    )


@router.post("/scans/{scan_id}/findings/{finding_id}/external-review-link/revoke", response_model=ExternalReviewLinkOut)
async def revoke_external_link(
    scan_id: int,
    finding_id: int,
    db: AsyncSession = Depends(get_db),
):
    try:
        finding = await revoke_external_review_link(db, scan_id, finding_id)
    except ValueError:
        raise HTTPException(404, "Finding not found")
    return ExternalReviewLinkOut(
        ok=True,
        url=build_external_review_link(str(finding.external_review_token or "")) if finding.external_review_token else "",
        token_active=bool(finding.external_review_token and not finding.external_review_revoked_at),
        expires_at=dt_iso(finding.external_review_expires_at),
    )


@router.post("/scans/{scan_id}/findings/{finding_id}/poc", response_model=PocResult)
async def generate_poc(
    scan_id: int,
    finding_id: int,
    body: PocGenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        return await generate_finding_poc(db, scan_id, finding_id, force=body.force)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put("/scans/{scan_id}/findings/{finding_id}/poc", response_model=PocResult)
async def save_poc_draft(
    scan_id: int,
    finding_id: int,
    body: PocHttpRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await save_finding_poc_draft(
            db,
            scan_id,
            finding_id,
            body.method,
            body.url,
            body.headers,
            body.body,
            body.poc_content,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(404, msg) from exc
        raise HTTPException(400, msg) from exc
    return {
        "generated": False,
        "cached": False,
        "message": result.get("message") or "验证请求已保存",
        "poc": result.get("poc"),
    }


@router.post("/scans/{scan_id}/findings/{finding_id}/poc/execute", response_model=PocExecuteResult)
async def execute_poc(
    scan_id: int,
    finding_id: int,
    body: PocHttpRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await execute_finding_poc(
            db,
            scan_id,
            finding_id,
            body.method,
            body.url,
            body.headers,
            body.body,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(404, msg) from exc
        raise HTTPException(400, msg) from exc
    return PocExecuteResult(
        ok=bool(result.get("ok")),
        status_code=result.get("status_code"),
        elapsed_ms=int(result.get("elapsed_ms") or 0),
        headers=result.get("headers") or {},
        body=result.get("body") or "",
        truncated=bool(result.get("truncated")),
        final_url=result.get("final_url"),
        error=result.get("error"),
    )


@public_router.get("/external-review/{token}", response_model=ExternalReviewOut)
async def get_external_review(token: str, db: AsyncSession = Depends(get_db)):
    try:
        finding = await get_finding_by_external_token(db, token)
    except PermissionError as exc:
        raise HTTPException(410, str(exc))
    except ValueError:
        raise HTTPException(404, "Review link not found")
    return await _build_external_review_out(db, finding)


@public_router.post("/external-review/{token}", response_model=ExternalReviewSubmitResult)
async def submit_external_review_by_link(
    token: str,
    body: ExternalReviewSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    if body.status == ExternalReviewStatus.UNREVIEWED:
        raise HTTPException(400, "Invalid status")
    try:
        finding = await submit_external_review(
            db,
            token,
            status=body.status,
            note=body.note,
            actor=body.actor,
        )
    except PermissionError as exc:
        raise HTTPException(410, str(exc)) from exc
    except ValueError as exc:
        msg = str(exc)
        if "误报" in msg:
            raise HTTPException(400, msg) from exc
        raise HTTPException(404, "Review link not found") from exc
    return ExternalReviewSubmitResult(
        ok=True,
        status=finding.external_status,
        message="外部确认已记录，等待安全侧复测。",
    )


def _project_link_out(scan: ScanTask) -> ProjectReviewLinkOut:
    active = bool(scan.project_review_token and not scan.project_review_revoked_at)
    url = ""
    if scan.project_review_token:
        url = build_project_review_link(str(scan.project_review_token))
    return ProjectReviewLinkOut(
        ok=True,
        url=url if active else (url or ""),
        token_active=active,
        expires_at=dt_iso(scan.project_review_expires_at),
    )


@router.get("/scans/{scan_id}/project-review-link", response_model=ProjectReviewLinkOut)
async def get_project_review_link(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _project_link_out(scan)


@router.post("/scans/{scan_id}/project-review-link", response_model=ProjectReviewLinkOut)
async def create_project_link(
    scan_id: int,
    body: ProjectReviewLinkRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan = await create_project_review_link(db, scan_id, expires_hours=body.expires_hours)
    except ValueError:
        raise HTTPException(404, "Scan not found")
    return _project_link_out(scan)


@router.post("/scans/{scan_id}/project-review-link/revoke", response_model=ProjectReviewLinkOut)
async def revoke_project_link(scan_id: int, db: AsyncSession = Depends(get_db)):
    try:
        scan = await revoke_project_review_link(db, scan_id)
    except ValueError:
        raise HTTPException(404, "Scan not found")
    return _project_link_out(scan)


@public_router.get("/project-review/{token}", response_model=ProjectReviewOut)
async def get_project_review(token: str, db: AsyncSession = Depends(get_db)):
    try:
        scan, findings = await list_project_review_findings(db, token)
    except PermissionError as exc:
        raise HTTPException(410, str(exc))
    except ValueError:
        raise HTTPException(404, "Review link not found")

    items: list[ProjectReviewFindingListItem] = []
    for f in findings:
        title = f.message_zh or f.message
        items.append(
            ProjectReviewFindingListItem(
                id=f.id,
                title=title,
                severity=f.severity,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                category=f.category,
                tool=f.tool,
                external_status=f.external_status,
                owasp_id=f.owasp_id,
                owasp_name=f.owasp_name,
                vuln_subtype=f.vuln_subtype,
                vuln_subtype_name=f.vuln_subtype_name,
            )
        )
    return ProjectReviewOut(
        scan_id=scan.id,
        project_name=scan.name,
        token_active=True,
        expires_at=dt_iso(scan.project_review_expires_at),
        total_findings=len(items),
        findings=items,
    )


@public_router.get("/project-review/{token}/findings/{finding_id}", response_model=ExternalReviewOut)
async def get_project_review_finding_detail(
    token: str,
    finding_id: int,
    db: AsyncSession = Depends(get_db),
):
    try:
        scan, finding = await get_project_review_finding(db, token, finding_id)
    except PermissionError as exc:
        raise HTTPException(410, str(exc))
    except ValueError as exc:
        msg = str(exc)
        if "Finding" in msg:
            raise HTTPException(404, "Finding not found")
        raise HTTPException(404, "Review link not found")
    out = await _build_external_review_out(db, finding)
    out.token_active = True
    out.expires_at = dt_iso(scan.project_review_expires_at)
    return out


@public_router.post(
    "/project-review/{token}/findings/{finding_id}",
    response_model=ExternalReviewSubmitResult,
)
async def submit_project_review_by_link(
    token: str,
    finding_id: int,
    body: ExternalReviewSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    if body.status == ExternalReviewStatus.UNREVIEWED:
        raise HTTPException(400, "Invalid status")
    try:
        finding = await submit_project_review_finding(
            db,
            token,
            finding_id,
            status=body.status,
            note=body.note,
            actor=body.actor,
        )
    except PermissionError as exc:
        raise HTTPException(410, str(exc))
    except ValueError as exc:
        msg = str(exc)
        if "Finding" in msg:
            raise HTTPException(404, "Finding not found")
        raise HTTPException(404, "Review link not found")
    return ExternalReviewSubmitResult(
        ok=True,
        status=finding.external_status,
        message="外部确认已记录，等待安全侧复测。",
    )


@router.get("/scans/{scan_id}/files/content", response_model=FileContentOut)
async def get_file_content(
    scan_id: int,
    path: str,
    line_start: int = 1,
    line_end: int = 1,
    context: int = 40,
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    try:
        data = read_file_with_context(
            Path(scan.project_path),
            path,
            line_start,
            line_end,
            context_lines=min(context, 120),
        )
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return FileContentOut(**data)


@router.get("/scans/{scan_id}/files/locate", response_model=list[CodeLocationOut])
async def locate_file(
    scan_id: int,
    q: str,
    file_hint: str | None = None,
    limit: int = 8,
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    hits = locate_text_in_project(
        Path(scan.project_path),
        q,
        file_hint=file_hint,
        limit=min(limit, 20),
    )
    return [CodeLocationOut(**h) for h in hits]


@router.get("/scans/{scan_id}/stats", response_model=ScanStats)
async def scan_stats(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanStats(**await get_scan_stats(db, scan_id))


@router.get("/scans/{scan_id}/score", response_model=ScanScoreOut)
async def scan_score(
    scan_id: int,
    refresh: bool = Query(False, description="Force recompute and rewrite cached score"),
    db: AsyncSession = Depends(get_db),
):
    """Return security score; uses cache unless refresh=1 or cache is empty."""
    from app.services.score_service import get_or_compute_scan_score

    result = await get_or_compute_scan_score(db, scan_id, refresh=refresh)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return ScanScoreOut(**result)


@router.get("/scans/{scan_id}/codeql-flow-graph", response_model=CodeqlFlowGraphOut)
async def codeql_flow_graph(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    rows = (
        await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.tool == "codeql",
                Finding.category == FindingCategory.SAST,
            )
        )
    ).scalars().all()

    payload = [{"metadata_json": f.metadata_json} for f in rows]
    graph = build_project_codeql_flow_graph(payload, Path(scan.project_path))
    return CodeqlFlowGraphOut(**graph)


@router.get("/scans/{scan_id}/events", response_model=list[ScanEventOut])
async def scan_events(scan_id: int, limit: int = 200, db: AsyncSession = Depends(get_db)):
    limit = max(1, min(limit, 1000))
    stmt = (
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_id)
        .order_by(ScanEvent.id.desc())
        .limit(limit)
    )
    events = (await db.execute(stmt)).scalars().all()
    events = list(reversed(events))
    return [
        ScanEventOut(
            id=e.id,
            scan_id=e.scan_id,
            level=e.level,
            phase=e.phase,
            tool=e.tool,
            file_path=e.file_path,
            message=e.message,
            created_at=dt_iso(e.created_at) or "",
        )
        for e in events
    ]


@router.post("/scans/upload", response_model=ScanSummary)
async def upload_scan(
    file: UploadFile = File(...),
    name: str | None = Form(None),
    project_id: int | None = Form(None),
    scan_languages: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(400, "No file provided")

    settings.uploads_dir.mkdir(parents=True, exist_ok=True)
    temp_path = None
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", dir=settings.uploads_dir) as tmp:
        temp_path = Path(tmp.name)
        total = 0
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > settings.max_upload_bytes:
                temp_path.unlink(missing_ok=True)
                raise HTTPException(413, "上传文件超过大小限制")
            tmp.write(chunk)

    langs = normalize_scan_languages(scan_languages) if scan_languages else None
    try:
        scan = await create_upload_scan(
            db,
            temp_path,
            name,
            project_id=project_id,
            scan_languages=langs if project_id is None else None,
        )
    except DuplicateProjectNameError as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    finally:
        temp_path.unlink(missing_ok=True)

    return await _scan_summary_with_db(db, scan)


@router.post("/scans/gitlab", response_model=ScanSummary)
async def gitlab_scan(
    body: ScanCreateGitLab,
    db: AsyncSession = Depends(get_db),
):
    token = (body.access_token or "").strip() or (settings.gitlab_access_token or "").strip()
    if not token:
        raise HTTPException(
            400,
            "未提供 GitLab Access Token。请在系统设置中配置，或在本次创建时填写。",
        )
    branch = (body.branch or "").strip() or (settings.gitlab_default_branch or "main")
    try:
        scan = await create_gitlab_scan(
            db,
            body.project_url,
            branch,
            token,
            body.name,
            project_id=body.project_id,
            notify_emails=body.notify_emails,
            report_severities=body.report_severities,
            scan_languages=body.scan_languages if body.project_id is None else None,
        )
    except (DuplicateGitUrlError, DuplicateProjectNameError) as exc:
        raise HTTPException(status_code=409, detail=duplicate_project_http_detail(exc)) from exc
    except WebhookValidationError as exc:
        raise HTTPException(exc.http_status, exc.message) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return await _scan_summary_with_db(db, scan)


@router.post("/scans/{scan_id}/start", response_model=ScanSummary)
async def start_scan(scan_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    try:
        await start_scan_task(scan_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    # Reload after start_scan_task (separate session) committed.
    db.expire_all()
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    summary = await _scan_summary_with_db(db, scan)

    # Start pipeline on the event loop (same mechanism as Jenkins webhook).
    from app.services.scan_runtime import launch_sast_pipeline

    launch_sast_pipeline(scan_id)
    return summary


@router.post("/scans/{scan_id}/cancel", response_model=LlmAuditCancelResponse)
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    if scan.status == ScanStatus.LLM_AUDITING:
        request_llm_audit_cancel(scan_id)
        cancel_scan_pipeline(scan_id)
        request_sast_deep_cancel(scan_id)
        paused = await force_pause_scan(scan_id, reason="用户已暂停 LLM 端点审计")
        if paused:
            await db.refresh(scan)
            return LlmAuditCancelResponse(status="paused", message="扫描已暂停")
        scan.progress_message = "正在暂停 LLM 端点审计…"
        await db.commit()
        return LlmAuditCancelResponse(
            status="cancelling",
            message="已请求暂停，将在当前 Controller 审计完成后停止",
        )

    if scan.status in (ScanStatus.SCANNING, ScanStatus.ANALYZING):
        request_sast_deep_cancel(scan_id)
        was_active = cancel_scan_pipeline(scan_id)
        if not was_active:
            paused = await force_pause_scan(scan_id)
            if paused:
                await db.refresh(scan)
                return LlmAuditCancelResponse(status="paused", message="扫描已暂停")
        scan.progress_message = "正在暂停…"
        await db.commit()
        return LlmAuditCancelResponse(
            status="cancelling" if was_active else "paused",
            message=(
                "已请求暂停，将在当前步骤完成后停止并保存已有结果"
                if was_active
                else "扫描已暂停"
            ),
        )

    raise HTTPException(400, "当前没有进行中的扫描可暂停")


@router.post("/scans/{scan_id}/llm-audit")
async def llm_audit_scan(
    scan_id: int,
    body: LlmAuditRequest,
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not is_llm_configured():
        raise HTTPException(400, "请先在系统设置中配置 LLM API Key")

    kind = scan.scan_kind
    kind_value = kind.value if hasattr(kind, "value") else str(kind or "")
    verify_only = kind_value == ScanKind.RETEST.value and bool(scan.parent_scan_id)

    scan.status = ScanStatus.LLM_AUDITING
    scan.progress = 15 if verify_only else 80
    scan.progress_message = (
        "核实上次 LLM 发现是否已修复（不重新发现漏洞）..."
        if verify_only
        else "LLM 端点驱动审计排队中..."
    )
    scan.error_message = None
    await db.commit()

    from app.services.scan_runtime import launch_llm_audit_pipeline

    categories = body.categories or None
    launch_llm_audit_pipeline(scan_id, categories)
    return {
        "status": "started",
        "mode": "verify" if verify_only else "discover",
        "categories": [c.value for c in categories] if categories else ["auto"],
    }


@router.post("/scans/{scan_id}/llm-audit/cancel", response_model=LlmAuditCancelResponse)
async def cancel_llm_audit_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.LLM_AUDITING:
        raise HTTPException(400, "当前没有进行中的 LLM 端点审计")
    request_llm_audit_cancel(scan_id)
    scan.progress_message = "正在暂停 LLM 端点审计…"
    await db.commit()
    return LlmAuditCancelResponse(
        status="cancelling",
        message="已请求暂停，将在当前 Controller 审计完成后停止",
    )


@router.get("/scans/{scan_id}/llm-audit/journal", response_model=list[LlmAuditJournalEntry])
async def get_llm_audit_journal(scan_id: int, limit: int = 300, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    limit = max(1, min(limit, 500))
    rows = (
        await db.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id, ScanEvent.phase == LLM_AUDIT_PHASE)
            .order_by(ScanEvent.id.asc())
            .limit(limit)
        )
    ).scalars().all()
    out: list[LlmAuditJournalEntry] = []
    for row in rows:
        payload = parse_journal_message(row.message) or {}
        out.append(
            LlmAuditJournalEntry(
                id=row.id,
                type=str(payload.get("type") or row.tool or "event"),
                level=row.level,
                created_at=dt_iso(row.created_at) or "",
                file_path=row.file_path,
                title=str(payload.get("title") or ""),
                payload=payload,
            )
        )
    return out


@router.get("/scans/{scan_id}/llm-audit/status")
async def get_llm_audit_status(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "status": scan.status.value,
        "progress": scan.progress,
        "progress_message": scan.progress_message,
        "cancelling": is_llm_audit_cancel_requested(scan_id) or is_scan_cancel_requested(scan_id),
    }


@router.get("/scans/{scan_id}/llm-diagnosis", response_model=LlmDiagnosisOut)
async def get_llm_diagnosis(scan_id: int, db: AsyncSession = Depends(get_db)):
    try:
        out = await explain_llm_no_findings(db, scan_id)
    except ValueError:
        raise HTTPException(404, "Scan not found")
    return LlmDiagnosisOut(**out)


@router.post("/scans/{scan_id}/analyze", response_model=AnalyzeResult)
async def analyze_scan(scan_id: int, body: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not is_llm_configured():
        raise HTTPException(400, "请先在系统设置中配置 LLM API Key")

    result = await analyze_scan_findings(
        db, scan_id, body.finding_ids, body.max_findings, force=body.force
    )
    if (
        result["analyzed"] == 0
        and not body.finding_ids
        and not body.force
        and result["already_audited"] > 0
    ):
        result = await analyze_scan_findings(
            db, scan_id, body.finding_ids, body.max_findings, force=True
        )
        if result["analyzed"] > 0:
            result["message"] = f"已重新审计 {result['analyzed']} 条并更新中文描述。"
    return result


@router.post("/scans/{scan_id}/sast-deep-audit", response_model=AnalyzeResult)
async def sast_deep_audit_scan(
    scan_id: int,
    body: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not is_llm_configured():
        raise HTTPException(400, "请先在系统设置中配置 LLM API Key")
    if scan.status in (ScanStatus.SCANNING, ScanStatus.ANALYZING, ScanStatus.LLM_AUDITING):
        raise HTTPException(400, "当前有任务进行中，请稍后再试或先暂停")

    max_findings = max(1, min(int(body.max_findings or 12), 30))
    force = bool(body.force)
    preview = await preview_sast_deep_start(db, scan_id, body.finding_ids, max_findings, force)
    if not preview.get("ok"):
        if preview.get("suggest_force") and not force:
            preview = await preview_sast_deep_start(db, scan_id, body.finding_ids, max_findings, True)
            force = True
        if not preview.get("ok"):
            return AnalyzeResult(
                analyzed=0,
                pending=int(preview.get("pending") or 0),
                already_audited=int(preview.get("already_audited") or 0),
                message=str(preview.get("message") or "无待研判项"),
                started=False,
            )

    scan.status = ScanStatus.ANALYZING
    scan.progress = 1
    scan.progress_message = preview.get("message") or "SAST 深度研判已启动…"
    scan.error_message = None
    await db.commit()

    from app.services.scan_runtime import launch_sast_deep_pipeline

    launch_sast_deep_pipeline(scan_id, body.finding_ids, max_findings, force)
    return AnalyzeResult(
        analyzed=0,
        pending=int(preview.get("pending") or 0),
        already_audited=int(preview.get("already_audited") or 0),
        message=str(preview.get("message") or "已在后台启动深度研判"),
        started=True,
    )


@router.get("/scans/{scan_id}/sast-deep-audit/progress")
async def sast_deep_audit_progress(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    prog = get_sast_deep_progress(scan_id)
    if (
        not prog
        and scan.status == ScanStatus.ANALYZING
        and scan.progress_message
        and "深度研判" in scan.progress_message
    ):
        prog = {
            "status": "running",
            "message": scan.progress_message,
            "percent": scan.progress or 1,
            "tasks": [],
            "total": 0,
            "done": 0,
        }
    elif not prog and scan.status == ScanStatus.COMPLETED and scan.progress_message:
        if "深度研判" in scan.progress_message and "中断" in scan.progress_message:
            prog = {
                "status": "failed",
                "message": scan.progress_message,
                "percent": scan.progress or 0,
                "tasks": [],
                "total": 0,
                "done": 0,
            }
    return {
        "scan_status": scan.status.value,
        "scan_progress": scan.progress,
        "scan_progress_message": scan.progress_message,
        "cancelling": is_sast_deep_cancel_requested(scan_id) or is_scan_cancel_requested(scan_id),
        "job": prog,
    }


def _chat_action_intent(text: str) -> str | None:
    t = text.lower()
    if "可利用性研判" in t:
        return "sast_deep_audit" if "深度" in t or "数据流" in t else "fp_audit"
    if "数据流" in t or "深度研判" in t:
        return "sast_deep_audit"
    if "误报" in t:
        return "fp_audit"
    if "llm" in t and "复审" in t:
        return "llm_review"
    if "llm" in t and ("深度审计" in t or "代码审计" in t or "端点审计" in t or "端点驱动" in t):
        return "llm_audit"
    if "重新扫描" in t or "重扫" in t or "清空并重置" in t or "清空重置" in t:
        return "rerun"
    return None


def _llm_audit_focus_categories(text: str) -> list[FindingCategory] | None:
    t = text.lower()
    wants_auth = any(k in t for k in ("越权", "idor", "权限", "授权", "鉴权", "access control", "authorization"))
    wants_biz = any(k in t for k in ("业务逻辑", "业务流程", "流程", "竞态", "幂等", "状态机", "支付逻辑"))
    categories: list[FindingCategory] = []
    if wants_auth:
        categories.append(FindingCategory.AUTHORIZATION)
    if wants_biz:
        categories.append(FindingCategory.BUSINESS_LOGIC)
    return categories or None


def _severity_score(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 100,
        Severity.HIGH: 80,
        Severity.MEDIUM: 55,
        Severity.LOW: 30,
        Severity.INFO: 10,
        Severity.UNKNOWN: 20,
    }.get(sev, 20)


def _confidence_label(val: float | None) -> str:
    if val is None:
        return "medium"
    if val >= 0.8:
        return "high"
    if val >= 0.55:
        return "medium"
    return "low"


def _looks_like_auth_gap(f: Finding) -> bool:
    text = " ".join(
        [
            f.rule_id or "",
            f.message or "",
            f.message_zh or "",
            f.file_path or "",
            f.metadata_json or "",
        ]
    ).lower()
    keys = ("auth", "permission", "role", "owner", "idor", "access", "authorize", "admin", "user_id")
    return f.category == FindingCategory.AUTHORIZATION or any(k in text for k in keys)


def _looks_like_biz_gap(f: Finding) -> bool:
    text = " ".join(
        [
            f.rule_id or "",
            f.message or "",
            f.message_zh or "",
            f.file_path or "",
            f.metadata_json or "",
        ]
    ).lower()
    keys = ("order", "pay", "amount", "coupon", "refund", "workflow", "state", "race", "idempot", "inventory")
    return f.category == FindingCategory.BUSINESS_LOGIC or any(k in text for k in keys)


def _task_item_from_finding(f: Finding, idx: int, mode: str, score_boost: int = 0) -> dict:
    sev = _severity_score(f.severity)
    conf = int(((f.ai_confidence if f.ai_confidence is not None else 0.6) * 100))
    verdict_bonus = 0
    if f.ai_verdict == AiVerdict.REAL_VULN:
        verdict_bonus = 8
    elif f.ai_verdict == AiVerdict.FALSE_POSITIVE:
        verdict_bonus = -12
    review_bonus = 0
    if f.review_status == ReviewStatus.CONFIRMED:
        review_bonus = 10
    elif f.review_status in (ReviewStatus.FALSE_POSITIVE, ReviewStatus.FIXED):
        review_bonus = -20
    score = int(min(100, max(0, 0.55 * sev + 0.25 * conf + verdict_bonus + review_bonus + score_boost)))
    risk_type = "authorization_gap" if mode == "auth_gap_hunt" else "business_logic_gap"
    if mode == "prioritize":
        risk_type = "priority_risk"
    snippet = (f.code_snippet or "").strip()
    loc = f"{to_repo_relative_path(f.file_path)}:{f.line_start}"
    return {
        "id": f"candidate-{idx}",
        "title": (f.message_zh or f.message or "疑似风险点")[:120],
        "priority_score": score,
        "confidence": _confidence_label(f.ai_confidence),
        "score_breakdown": {
            "severity": sev,
            "ai_confidence": conf,
            "verdict_bonus": verdict_bonus,
            "review_bonus": review_bonus,
            "mode_boost": score_boost,
        },
        "finding_id": f.id,
        "category": f.category.value,
        "risk_type": risk_type,
        "impact": "可能导致敏感数据泄露、权限提升或业务资产损失",
        "attack_path": loc,
        "evidence": [
            {
                "type": "finding",
                "ref": f"finding#{f.id}",
                "snippet": None,
            },
            {
                "type": "code",
                "ref": loc,
                "snippet": snippet[:240] if snippet else None,
            },
        ],
        "recommendation": "优先复核鉴权/流程校验并补充单元测试与负向用例",
        "actions": ["mark_confirmed", "mark_false_positive", "mark_fixed"],
    }


@router.post("/scans/{scan_id}/agent-tasks", response_model=AgentTaskResponse)
async def run_agent_task(scan_id: int, body: AgentTaskRequest, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    base_stmt = select(Finding).where(Finding.scan_id == scan_id)
    if body.scope.categories:
        base_stmt = base_stmt.where(Finding.category.in_(body.scope.categories))
    findings = (await db.execute(base_stmt)).scalars().all()
    if body.scope.file_globs:
        globs = [g.strip() for g in body.scope.file_globs if g and g.strip()]
        if globs:
            findings = [f for f in findings if any(fnmatch.fnmatch(f.file_path or "", g) for g in globs)]
    if body.scope.modules:
        mods = [m.strip().lower() for m in body.scope.modules if m and m.strip()]
        if mods:
            def _hit(f: Finding) -> bool:
                hay = " ".join([f.file_path or "", f.message or "", f.message_zh or ""]).lower()
                return any(m in hay for m in mods)
            findings = [f for f in findings if _hit(f)]
    max_items = max(1, min(body.scope.max_items, 50))

    if body.mode == "auth_gap_hunt":
        candidates = [f for f in findings if _looks_like_auth_gap(f)]
        candidates.sort(key=lambda x: (_severity_score(x.severity), x.id), reverse=True)
        chosen = candidates[:max_items]
        items = [_task_item_from_finding(f, i + 1, body.mode, score_boost=8) for i, f in enumerate(chosen)]
        summary = f"发现 {len(items)} 个疑似越权补盲点（从 {len(findings)} 条发现中筛选）。"
    elif body.mode == "biz_gap_hunt":
        candidates = [f for f in findings if _looks_like_biz_gap(f)]
        candidates.sort(key=lambda x: (_severity_score(x.severity), x.id), reverse=True)
        chosen = candidates[:max_items]
        items = [_task_item_from_finding(f, i + 1, body.mode, score_boost=6) for i, f in enumerate(chosen)]
        summary = f"发现 {len(items)} 个疑似业务流程补盲点（从 {len(findings)} 条发现中筛选）。"
    else:
        top_n = max(1, min(body.options.top_n, 30))
        ranked = sorted(findings, key=lambda x: (_severity_score(x.severity), x.ai_confidence or 0.5, x.id), reverse=True)
        chosen = ranked[:top_n]
        items = [_task_item_from_finding(f, i + 1, body.mode) for i, f in enumerate(chosen)]
        summary = f"已输出优先级 Top {len(items)} 漏洞建议。"

    refs: list[str] = []
    for it in items:
        for ev in it["evidence"]:
            refs.append(ev["ref"])

    return AgentTaskResponse(
        mode=body.mode,
        summary=summary,
        items=items,
        next_actions=[
            "打开高优先级条目逐条复核",
            "将已处置条目标记为误报或已修复，并补充复现用例",
            "按模块触发 targeted 深度审计",
        ],
        evidence_refs=refs[:30],
        metrics={"items": len(items), "findings_scanned": len(findings)},
    )


@router.get("/scans/{scan_id}/agent-chat/history", response_model=list[AgentChatMessageOut])
async def agent_chat_history(scan_id: int, limit: int = 30, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    rows = await list_chat_messages(db, scan_id, limit=limit)
    return [AgentChatMessageOut(**m) for m in rows]


@router.get("/scans/{scan_id}/agent-chat/actions", response_model=list[AgentActionOut])
async def agent_chat_actions(scan_id: int, limit: int = 12, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    rows = await list_action_events(db, scan_id, limit=limit)
    return [AgentActionOut(**m) for m in rows]


@router.post("/scans/{scan_id}/agent-chat", response_model=AgentChatResponse)
async def agent_chat(
    scan_id: int,
    body: AgentChatRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    user_text = body.message.strip()
    await append_chat_event(db, scan_id, "user", user_text)

    action = _chat_action_intent(user_text)
    action_result: str | None = None

    if action == "fp_audit":
        result = await analyze_scan_findings(db, scan_id, None, 50, force=False)
        action_result = result.get("message")
    elif action == "sast_deep_audit":
        if scan.status in (ScanStatus.SCANNING, ScanStatus.ANALYZING, ScanStatus.LLM_AUDITING):
            action_result = "当前有任务进行中，请稍后再试或先暂停。"
        else:
            preview = await preview_sast_deep_start(db, scan_id, None, 12, False)
            force = False
            if not preview.get("ok") and preview.get("suggest_force"):
                preview = await preview_sast_deep_start(db, scan_id, None, 12, True)
                force = True
            if not preview.get("ok"):
                action_result = str(preview.get("message") or "无待研判项")
            else:
                scan.status = ScanStatus.ANALYZING
                scan.progress = 1
                scan.progress_message = preview.get("message") or "SAST 深度研判已启动…"
                await db.commit()
                from app.services.scan_runtime import launch_sast_deep_pipeline

                launch_sast_deep_pipeline(scan_id, None, 12, force)
                action_result = str(preview.get("message") or "已在后台启动深度研判")
    elif action == "llm_review":
        result = await review_llm_scan_findings(db, scan_id, None, 50, force=False)
        action_result = result.get("message")
    elif action == "llm_audit":
        if not is_llm_configured():
            action_result = "请先在系统设置中配置 LLM API Key。"
        else:
            categories = _llm_audit_focus_categories(user_text)
            scan.status = ScanStatus.LLM_AUDITING
            scan.progress = max(scan.progress, 80)
            scan.progress_message = "LLM 端点驱动审计排队中..."
            await db.commit()
            from app.services.scan_runtime import launch_llm_audit_pipeline

            launch_llm_audit_pipeline(scan_id, categories)
            if categories == [FindingCategory.AUTHORIZATION]:
                action_result = "已提交 LLM 端点审计任务，当前侧重点：越权 / 访问控制。"
            elif categories == [FindingCategory.BUSINESS_LOGIC]:
                action_result = "已提交 LLM 端点审计任务，当前侧重点：业务逻辑 / 流程风险。"
            elif categories:
                action_result = "已提交 LLM 端点审计任务，已按你的描述设置审计侧重点。"
            else:
                action_result = "已提交 LLM 端点审计任务，采用自主迭代模式（Origin/Goal），不预设漏洞类型。"
    elif action == "rerun":
        await reset_scan_for_rerun(db, scan)
        action_result = "已清空并重置为等待扫描状态，请点击「开始 SAST 扫描」手动开启；若只想重跑静态分析并保留 LLM 发现，请用「重新跑 SAST」。"

    if action:
        await append_action_event(db, scan_id, action, action_result)

    reply = await answer_scan_chat(
        db,
        scan_id,
        user_text,
        max_history=body.max_history,
        action_result=action_result,
    )
    await append_chat_event(db, scan_id, "assistant", reply)
    messages = await list_chat_messages(db, scan_id, limit=max(body.max_history, 20))
    action_history = await list_action_events(db, scan_id, limit=12)
    return AgentChatResponse(
        reply=reply,
        action=action,
        action_result=action_result,
        messages=[AgentChatMessageOut(**m) for m in messages],
        action_history=[AgentActionOut(**m) for m in action_history],
    )


@router.post("/scans/{scan_id}/llm-review", response_model=AnalyzeResult)
async def llm_review_scan(scan_id: int, body: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not is_llm_configured():
        raise HTTPException(400, "请先在系统设置中配置 LLM API Key")

    result = await review_llm_scan_findings(
        db, scan_id, body.finding_ids, body.max_findings, force=body.force
    )
    if (
        result["analyzed"] == 0
        and not body.finding_ids
        and not body.force
        and result["already_audited"] > 0
    ):
        result = await review_llm_scan_findings(
            db, scan_id, body.finding_ids, body.max_findings, force=True
        )
        if result["analyzed"] > 0:
            result["message"] = f"已重新复审 {result['analyzed']} 条 LLM 发现。"
    return result


@router.post("/scans/{scan_id}/rerun", response_model=ScanSummary)
async def rerun_scan(scan_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    await reset_scan_for_rerun(db, scan)
    await db.refresh(scan)
    return await _scan_summary_with_db(db, scan)


@router.delete("/scans/{scan_id}")
async def remove_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    ok = await delete_scan(db, scan_id)
    if not ok:
        raise HTTPException(404, "Scan not found")
    return {"deleted": True}
