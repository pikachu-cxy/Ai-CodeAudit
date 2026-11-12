from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import (
    AiVerdict,
    ExternalReviewStatus,
    FindingCategory,
    RetestMethod,
    RetestStrategy,
    RetestVerdict,
    ReviewStatus,
    ScanKind,
    ScanSource,
    ScanStatus,
    Severity,
    dt_iso,
)
from app.services.feishu_service import build_external_review_link
from app.services.owasp_classifier import classify_finding, classify_owasp
from app.services.scanners.common import to_repo_relative_path


def _coerce_repo_relative_path(value):
    if value is None or value == "":
        return value
    return to_repo_relative_path(str(value))


class ScanCreateUpload(BaseModel):
    name: str | None = None
    project_id: int | None = None
    notify_emails: list[str] | None = None
    # 邮件报告范围：只把这些严重级别写进扫描完成邮件；留空/省略 = 全量（旧行为）。
    report_severities: list[str] | None = None


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int = 0
    username: str
    role: str = "user"
    auth_enabled: bool = True


class UserOut(BaseModel):
    username: str
    role: str = "user"
    auth_enabled: bool = True


class AuthConfigOut(BaseModel):
    auth_enabled: bool
    username_hint: str | None = None
    sso_enabled: bool = False
    sso_login_url: str | None = None


class ScanCreateGitLab(BaseModel):
    name: str | None = None
    project_url: str = Field(..., description="完整 GitLab 项目地址，如 https://gitlab.com/group/project.git")
    branch: str = "main"
    # Optional: falls back to settings.gitlab_access_token when empty.
    access_token: str | None = None
    project_id: int | None = None
    notify_emails: list[str] | None = None
    # 邮件报告范围：只把这些严重级别写进扫描完成邮件；留空/省略 = 全量（旧行为）。
    report_severities: list[str] | None = None
    # Optional multi-select; empty/omit = auto language detection.
    scan_languages: list[str] | None = None


class WebhookScanRequest(BaseModel):
    """Jenkins / CI trigger: match or auto-create project by GitLab URL."""

    project_url: str = Field(..., description="GitLab 仓库 HTTP 地址，如 https://gitlab.example.com/group/app.git")
    branch: str | None = None
    name: str | None = None
    notify_emails: list[str] | None = None
    notify_email: str | None = None
    send_html_report: bool = True
    # 邮件报告范围：只把这些严重级别写进扫描完成邮件；留空/省略 = 全量（旧行为）。
    report_severities: list[str] | None = None
    # Optional body token (prefer X-Webhook-Token header).
    token: str | None = None


class WebhookScanResponse(BaseModel):
    ok: bool = True
    created_project: bool = False
    project_id: int
    scan_id: int
    branch: str
    status: str


class ScannerCoverageOut(BaseModel):
    id: str
    name: str
    status: str  # ran | skipped | failed | not_run
    findings: int = 0
    reason: str | None = None
    version: str | None = None
    detail: dict | None = None


class CapabilityCoverageOut(BaseModel):
    id: str
    label: str
    status: str  # checked | not_checked | partial
    sources: list[str] = []
    note: str | None = None
    rule_count: int | None = None


class OwaspCategoryCoverageOut(BaseModel):
    id: str
    label: str
    status: str  # checked | not_checked | partial
    sources: list[str] = []
    note: str | None = None
    rule_count: int | None = None


class LlmFocusCoverageOut(BaseModel):
    id: str
    label: str
    status: str  # audited | configured | not_run | skipped
    note: str | None = None


class LlmAuditCoverageOut(BaseModel):
    ran: bool = False
    status: str = "not_run"  # completed | cancelled | running | not_run
    focus_areas: list[LlmFocusCoverageOut] = []


class SemgrepRuleEvidenceOut(BaseModel):
    source: str | None = None
    configs: list[str] = []
    total_rules: int = 0
    by_subtype: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    sample_rules_by_subtype: dict[str, list[str]] = {}
    sample_rules_by_owasp: dict[str, list[str]] = {}
    inventory_error: str | None = None
    resolved_at: str | None = None
    project_languages: list[str] = []
    filtered: bool = False
    unfiltered_total_rules: int | None = None


class ScanCoverageOut(BaseModel):
    scanners: list[ScannerCoverageOut] = []
    capabilities: list[CapabilityCoverageOut] = []
    semgrep_configs: list[str] = []
    sast_checked: bool = False
    owasp_categories: list[OwaspCategoryCoverageOut] = []
    llm_audit: LlmAuditCoverageOut | None = None
    semgrep_rule_evidence: SemgrepRuleEvidenceOut | None = None


class DetectedLanguageOut(BaseModel):
    id: str
    label: str
    file_count: int = 0
    primary: bool = False


class ScanSummary(BaseModel):
    id: int
    project_id: int | None = None
    parent_scan_id: int | None = None
    scan_kind: ScanKind = ScanKind.BASELINE
    version_label: str | None = None
    name: str
    source: ScanSource
    status: ScanStatus
    source_url: str | None
    branch: str | None
    notify_emails: list[str] | None = None
    progress: int
    progress_message: str | None
    total_findings: int
    security_score: int | None = None
    semgrep_version: str | None
    scanner_summary: str | None = None
    scan_coverage: ScanCoverageOut | None = None
    detected_languages: list[DetectedLanguageOut] = []
    error_message: str | None
    notes: str | None = None
    created_at: str
    updated_at: str | None = None
    completed_at: str | None
    archived_at: str | None = None

    model_config = {"from_attributes": True}


class ScanUpdateRequest(BaseModel):
    name: str | None = None
    notes: str | None = None


class ProjectSummary(BaseModel):
    id: int
    name: str
    notes: str | None = None
    source_type: ScanSource
    source_url: str | None = None
    default_branch: str | None = None
    scan_languages: list[str] | None = None
    detected_languages: list[DetectedLanguageOut] = []
    archived_at: str | None = None
    created_at: str
    updated_at: str | None = None
    scan_count: int = 0
    latest_scan: ScanSummary | None = None

    model_config = {"from_attributes": True}


class ProjectDetail(ProjectSummary):
    scans: list[ScanSummary] = []


class ProjectUpdateRequest(BaseModel):
    name: str | None = None
    notes: str | None = None
    # Pass [] to clear and restore auto detection; omit to leave unchanged.
    scan_languages: list[str] | None = None


class ProjectWhitelistEntryOut(BaseModel):
    """项目白名单 / 误报库条目。status: whitelist=手动加白，false_positive=误报。"""

    id: int
    project_id: int
    status: str
    reason: str
    rule_id: str | None = None
    file_path: str | None = None
    fingerprint_strict: str
    fingerprint_relaxed: str | None = None
    source_scan_id: int | None = None
    source_finding_id: int | None = None
    created_by: str | None = None
    created_at: str | None = None
    expires_at: str | None = None


class ProjectWhitelistCreate(BaseModel):
    finding_id: int
    reason: str = Field(..., min_length=1, max_length=1000)


class ProjectCreateGitLabScan(BaseModel):
    name: str | None = None
    project_url: str | None = None
    branch: str | None = None
    access_token: str | None = None
    notify_emails: list[str] | None = None
    # 邮件报告范围：只把这些严重级别写进扫描完成邮件；留空/省略 = 全量（旧行为）。
    report_severities: list[str] | None = None
    scan_languages: list[str] | None = None


class RetestRequest(BaseModel):
    branch: str | None = None
    access_token: str | None = None
    name: str | None = None
    auto_start: bool = False
    strategy: RetestStrategy = RetestStrategy.TARGETED
    # Kept for API compatibility; default queue already includes all non-FP findings.
    include_unreviewed_high: bool = False
    # When set, only these baseline finding IDs are verified (exact match; FP included).
    finding_ids: list[int] | None = None


class FindingOut(BaseModel):
    id: int
    scan_id: int
    rule_id: str
    check_id: str | None
    severity: Severity
    message: str
    message_zh: str | None = None
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str | None
    metadata_json: str | None
    tool: str
    category: FindingCategory
    ai_verdict: AiVerdict
    ai_reason: str | None
    ai_confidence: float | None
    review_status: ReviewStatus = ReviewStatus.UNREVIEWED
    review_note: str | None = None
    reviewed_at: str | None = None
    external_status: ExternalReviewStatus = ExternalReviewStatus.UNREVIEWED
    external_note: str | None = None
    external_updated_at: str | None = None
    external_updated_by: str | None = None
    external_review_token_active: bool = False
    external_review_expires_at: str | None = None
    external_review_url: str | None = None
    owasp_id: str | None = None
    owasp_name: str | None = None
    vuln_subtype: str | None = None
    vuln_subtype_name: str | None = None

    @field_validator("file_path", mode="before")
    @classmethod
    def coerce_file_path(cls, value):
        return _coerce_repo_relative_path(value)

    @field_validator("owasp_id", "owasp_name", "vuln_subtype", "vuln_subtype_name", mode="before")
    @classmethod
    def coerce_owasp(cls, value):
        if value is None or value == "":
            return None
        return str(value)

    @field_validator("review_status", mode="before")
    @classmethod
    def coerce_review_status(cls, value):
        if value is None or value == "":
            return ReviewStatus.UNREVIEWED
        return value

    @field_validator("reviewed_at", mode="before")
    @classmethod
    def coerce_reviewed_at(cls, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return dt_iso(value)
        return str(value)

    @field_validator("external_updated_at", "external_review_expires_at", mode="before")
    @classmethod
    def coerce_external_dt(cls, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return dt_iso(value)
        return str(value)

    @model_validator(mode="before")
    @classmethod
    def enrich_owasp(cls, data):
        if isinstance(data, dict):
            token = data.get("external_review_token")
            revoked = data.get("external_review_revoked_at")
            if token and not revoked:
                data = {
                    **data,
                    "external_review_token_active": True,
                    "external_review_url": build_external_review_link(str(token)),
                }
            if not data.get("owasp_id") or not data.get("vuln_subtype"):
                cls_fields = classify_finding(
                    rule_id=data.get("rule_id", ""),
                    message=data.get("message", ""),
                    metadata_json=data.get("metadata_json"),
                    tool=data.get("tool", ""),
                    category=(
                        data["category"].value
                        if hasattr(data.get("category"), "value")
                        else data.get("category")
                    ),
                )
                if not data.get("owasp_id"):
                    data = {**data, "owasp_id": cls_fields["owasp_id"], "owasp_name": cls_fields["owasp_name"]}
                if not data.get("vuln_subtype"):
                    data = {
                        **data,
                        "vuln_subtype": cls_fields["vuln_subtype"],
                        "vuln_subtype_name": cls_fields["vuln_subtype_name"],
                    }
            return data
        if hasattr(data, "rule_id"):
            if getattr(data, "external_review_token", None) and not getattr(data, "external_review_revoked_at", None):
                data.external_review_token_active = True
                data.external_review_url = build_external_review_link(str(data.external_review_token))
            needs = (
                not getattr(data, "owasp_id", None)
                or not getattr(data, "vuln_subtype", None)
            )
            if needs:
                cls = classify_finding(
                    rule_id=data.rule_id,
                    message=data.message,
                    metadata_json=data.metadata_json,
                    tool=data.tool,
                    category=data.category.value if hasattr(data.category, "value") else data.category,
                )
                if not getattr(data, "owasp_id", None):
                    data.owasp_id = cls["owasp_id"]
                    data.owasp_name = cls["owasp_name"]
                if not getattr(data, "vuln_subtype", None):
                    data.vuln_subtype = cls["vuln_subtype"]
                    data.vuln_subtype_name = cls["vuln_subtype_name"]
        return data

    model_config = {"from_attributes": True}


class RetestVerificationOut(BaseModel):
    id: int
    scan_id: int
    baseline_scan_id: int
    baseline_finding_id: int
    verdict: RetestVerdict
    method: RetestMethod
    evidence_json: str | None = None
    created_at: str
    baseline_finding: FindingOut | None = None
    current_finding_id: int | None = None

    model_config = {"from_attributes": True}


class RetestResultsSummary(BaseModel):
    scan_id: int
    baseline_scan_id: int
    queue_size: int
    fixed_count: int
    still_present_count: int
    inconclusive_count: int
    skipped_count: int
    message: str | None = None
    items: list[RetestVerificationOut] = []


class ScanDiffFindingItem(BaseModel):
    fingerprint: str
    status: str  # fixed | regressed | new | unchanged
    current: FindingOut | None = None
    baseline: FindingOut | None = None


class ScanDiffSummary(BaseModel):
    scan_id: int
    baseline_scan_id: int
    fixed_count: int
    regressed_count: int
    new_count: int
    unchanged_count: int
    status_changed_count: int
    items: list[ScanDiffFindingItem] = []


class FindingReviewUpdate(BaseModel):
    review_status: ReviewStatus
    review_note: str | None = None
    generate_poc: bool = False

    @model_validator(mode="after")
    def require_fp_note(self):
        if self.review_status == ReviewStatus.FALSE_POSITIVE and not (self.review_note or "").strip():
            raise ValueError("标记误报必须填写原因")
        return self


class ExternalReviewLinkRequest(BaseModel):
    expires_hours: int = 72


class ExternalReviewLinkOut(BaseModel):
    ok: bool = True
    url: str
    token_active: bool
    expires_at: str | None = None


class ExternalReviewSubmitRequest(BaseModel):
    status: ExternalReviewStatus
    note: str | None = Field(default=None, max_length=4000)
    actor: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def require_note_for_false_positive(self):
        if self.status == ExternalReviewStatus.FALSE_POSITIVE and not (self.note or "").strip():
            raise ValueError("标记误报必须填写说明")
        return self


class ExternalReviewCodeContext(BaseModel):
    relative_path: str
    content: str
    line_start: int
    line_end: int
    highlight_start: int
    highlight_end: int

    @field_validator("relative_path", mode="before")
    @classmethod
    def coerce_relative_path(cls, value):
        return _coerce_repo_relative_path(value)


class ExternalReviewOut(BaseModel):
    finding_id: int
    title: str
    message: str
    message_zh: str | None = None
    severity: Severity
    file_path: str
    relative_path: str
    line_start: int
    line_end: int
    rule_id: str
    code_snippet: str | None = None
    ai_reason: str | None = None
    category: FindingCategory
    tool: str
    owasp_id: str | None = None
    owasp_name: str | None = None
    vuln_subtype: str | None = None
    vuln_subtype_name: str | None = None
    review_status: ReviewStatus
    external_status: ExternalReviewStatus
    external_note: str | None = None
    external_updated_at: str | None = None
    external_updated_by: str | None = None
    token_active: bool
    expires_at: str | None = None
    code_context: ExternalReviewCodeContext | None = None

    @field_validator("file_path", "relative_path", mode="before")
    @classmethod
    def coerce_paths(cls, value):
        return _coerce_repo_relative_path(value)


class ExternalReviewSubmitResult(BaseModel):
    ok: bool = True
    status: ExternalReviewStatus
    message: str


class ProjectReviewLinkRequest(BaseModel):
    expires_hours: int = 168


class ProjectReviewLinkOut(BaseModel):
    ok: bool = True
    url: str
    token_active: bool
    expires_at: str | None = None


class ProjectReviewFindingListItem(BaseModel):
    id: int
    title: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    category: FindingCategory
    tool: str
    external_status: ExternalReviewStatus
    owasp_id: str | None = None
    owasp_name: str | None = None
    vuln_subtype: str | None = None
    vuln_subtype_name: str | None = None

    @field_validator("file_path", mode="before")
    @classmethod
    def coerce_file_path(cls, value):
        return _coerce_repo_relative_path(value)


class ProjectReviewOut(BaseModel):
    scan_id: int
    project_name: str
    token_active: bool
    expires_at: str | None = None
    total_findings: int
    findings: list[ProjectReviewFindingListItem]


class PocGenerateRequest(BaseModel):
    force: bool = False


class PocResult(BaseModel):
    generated: bool
    cached: bool = False
    message: str
    poc: dict | None = None


class PocHttpRequest(BaseModel):
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    poc_content: str | None = None


class PocExecuteResult(BaseModel):
    ok: bool
    status_code: int | None = None
    elapsed_ms: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    truncated: bool = False
    final_url: str | None = None
    error: str | None = None


class FileContentOut(BaseModel):
    file_path: str
    relative_path: str
    content: str
    line_start: int
    line_end: int
    total_lines: int
    highlight_start: int
    highlight_end: int

    @field_validator("file_path", "relative_path", mode="before")
    @classmethod
    def coerce_paths(cls, value):
        return _coerce_repo_relative_path(value)


class CodeLocationOut(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    matched_text: str | None = None
    confidence: float | None = None
    strategy: str | None = None
    language_matched: bool | None = None

    @field_validator("file_path", mode="before")
    @classmethod
    def coerce_file_path(cls, value):
        return _coerce_repo_relative_path(value)


class FindingPageOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingOut]


class ScanDetail(ScanSummary):
    findings: list[FindingOut] = []


class ScanEventOut(BaseModel):
    id: int
    scan_id: int
    level: str
    phase: str | None
    tool: str | None
    file_path: str | None
    message: str
    created_at: str

    model_config = {"from_attributes": True}


class ScanStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_verdict: dict[str, int]
    by_tool: dict[str, int]
    by_category: dict[str, int]
    by_review: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_subtype: dict[str, int] = {}
    by_owasp_subtype: dict[str, dict[str, int]] = {}
    top_rules: list[dict[str, int | str]]
    security_score: int | None = None


class ScoreDeductionDetail(BaseModel):
    severity: str
    count: int
    weight: int
    deduction: int


class ScanScoreOut(BaseModel):
    scan_id: int
    project_id: int | None = None
    score: int
    max_score: int = 100
    by_severity: dict[str, int]
    counted_findings: int
    excluded_findings: int
    weights: dict[str, int]
    has_critical: bool
    deduction: int = 0
    deduction_detail: list[ScoreDeductionDetail] = []
    exclude_ai_fp: bool = True
    status: str
    completed_at: str | None = None
    branch: str | None = None
    source_url: str | None = None


class CodeqlFlowGraphOut(BaseModel):
    codeql_path_total: int = 0
    node_count: int = 0
    edge_count: int = 0
    path_summaries: list[str] = []
    hub_nodes: list[str] = []
    top_edges: list[str] = []


class ScannerInfoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str
    category: str
    install_hint: str
    available: bool
    enabled: bool
    supported_languages: list[str] = []
    setup_hint: str | None = None
    requires_build: bool = False
    availability_reason: str | None = None


class SettingsOut(BaseModel):
    llm_provider: str
    llm_api_base: str
    llm_model: str
    llm_model_fp: str
    llm_model_deep: str
    llm_model_agent: str
    llm_provider_fp: str
    llm_provider_deep: str
    llm_provider_agent: str
    llm_enabled: bool
    llm_configured: bool
    llm_timeout: int
    semgrep_config: str
    semgrep_timeout: int
    codeql_query_suite: str
    codeql_build_mode: str
    codeql_java_build_command: str
    codeql_timeout: int
    codeql_db_timeout: int
    llm_code_audit_enabled: bool
    llm_audit_max_files: int = 25
    llm_audit_file_max_chars: int = 6000
    llm_audit_max_tokens: int = 8192
    llm_endpoint_audit_max_controllers: int = 40
    llm_endpoint_max_related_files: int = 4
    llm_endpoint_audit_max_iterations: int = 30
    llm_endpoint_audit_max_domains: int = 3
    llm_endpoint_origin_sample_per_domain: int = 5
    llm_agent_max_tool_rounds: int = 10
    llm_audit_profile: str = "balanced"
    llm_audit_require_stronger_evidence: bool = False
    llm_audit_enable_broader_hypotheses: bool = False
    llm_audit_focus_areas: list[str] = ["authz", "business_logic", "ai_prompt"]
    # Feishu/Lark notification (best-effort)
    feishu_webhook_url: str = ""
    feishu_at_user_ids: list[str] = []
    feishu_notify_min_severity: str = "HIGH"
    feishu_configured: bool = False
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_tls: bool = True
    email_from: str = ""
    smtp_password_configured: bool = False
    # Used to build deep-link URLs inside notifications.
    frontend_base_url: str = ""
    # GitLab integration defaults (token is write-only from UI when updating).
    gitlab_default_url: str = "https://gitlab.com"
    gitlab_default_branch: str = "main"
    gitlab_access_token_configured: bool = False
    gitlab_tls_verify: bool = True
    # Jenkins / CI inbound webhook (write-only when updating).
    webhook_token_configured: bool = False
    enabled_scanners: list[str]
    exclude_test_paths: bool = True
    scanners: list[ScannerInfoOut] = []
    # Database storage (MySQL for production; SQLite for local dev).
    database_backend: str = "sqlite"
    database_url: str = ""
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "ai_audit"
    mysql_database: str = "ai_audit_dev"
    mysql_charset: str = "utf8mb4"
    mysql_password_configured: bool = False
    database_restart_required: bool = False
    database_switched: bool = False
    # Authentication / token expiry
    auth_token_expire_hours: float = 12
    auth_refresh_token_expire_days: int = 7
    # Security score weights (deduct per finding from 100)
    score_weight_critical: int = 25
    score_weight_high: int = 10
    score_weight_medium: int = 3
    score_weight_low: int = 1
    score_weight_info: int = 0
    score_weight_unknown: int = 0
    score_exclude_ai_fp: bool = True
    # Populated only after PUT /settings when score rules changed and scores were recomputed.
    scores_recalculated: int | None = None


class SettingsUpdate(BaseModel):
    llm_provider: str | None = None
    llm_api_base: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_model_fp: str | None = None
    llm_model_deep: str | None = None
    llm_model_agent: str | None = None
    llm_provider_fp: str | None = None
    llm_provider_deep: str | None = None
    llm_provider_agent: str | None = None
    llm_enabled: bool | None = None
    llm_timeout: int | None = None
    semgrep_config: str | None = None
    codeql_query_suite: str | None = None
    codeql_build_mode: str | None = None
    codeql_java_build_command: str | None = None
    codeql_timeout: int | None = None
    codeql_db_timeout: int | None = None
    llm_code_audit_enabled: bool | None = None
    llm_audit_max_files: int | None = None
    llm_audit_file_max_chars: int | None = None
    llm_audit_max_tokens: int | None = None
    llm_endpoint_audit_max_controllers: int | None = None
    llm_endpoint_max_related_files: int | None = None
    llm_endpoint_audit_max_iterations: int | None = None
    llm_endpoint_audit_max_domains: int | None = None
    llm_endpoint_origin_sample_per_domain: int | None = None
    llm_agent_max_tool_rounds: int | None = None
    llm_audit_profile: str | None = None
    llm_audit_require_stronger_evidence: bool | None = None
    llm_audit_enable_broader_hypotheses: bool | None = None
    llm_audit_focus_areas: list[str] | None = None
    semgrep_timeout: int | None = None
    feishu_webhook_url: str | None = None
    feishu_at_user_ids: list[str] | None = None
    feishu_notify_min_severity: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_tls: bool | None = None
    email_from: str | None = None
    frontend_base_url: str | None = None
    gitlab_default_url: str | None = None
    gitlab_access_token: str | None = None
    gitlab_default_branch: str | None = None
    gitlab_tls_verify: bool | None = None
    webhook_token: str | None = None
    enabled_scanners: list[str] | None = None
    exclude_test_paths: bool | None = None
    database_backend: str | None = None
    database_url: str | None = None
    mysql_host: str | None = None
    mysql_port: int | None = None
    mysql_user: str | None = None
    mysql_password: str | None = None
    mysql_database: str | None = None
    mysql_charset: str | None = None
    auth_token_expire_hours: float | None = None
    auth_refresh_token_expire_days: int | None = None
    score_weight_critical: int | None = None
    score_weight_high: int | None = None
    score_weight_medium: int | None = None
    score_weight_low: int | None = None
    score_weight_info: int | None = None
    score_weight_unknown: int | None = None
    score_exclude_ai_fp: bool | None = None


class DatabaseTestRequest(BaseModel):
    database_backend: str | None = None
    database_url: str | None = None
    mysql_host: str | None = None
    mysql_port: int | None = None
    mysql_user: str | None = None
    mysql_password: str | None = None
    mysql_database: str | None = None
    mysql_charset: str | None = None


class DatabaseTestResult(BaseModel):
    ok: bool
    message: str


class CheckSourceUrlOut(BaseModel):
    duplicate: bool
    normalized_url: str | None = None
    project: ProjectSummary | None = None


class CheckProjectNameOut(BaseModel):
    duplicate: bool
    project: ProjectSummary | None = None


class AnalyzeRequest(BaseModel):
    finding_ids: list[int] | None = None
    max_findings: int = 50
    force: bool = False


class AnalyzeResult(BaseModel):
    analyzed: int
    pending: int
    already_audited: int
    message: str
    started: bool = False


class AgentChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    max_history: int = 12


class AgentChatMessageOut(BaseModel):
    role: str
    content: str
    created_at: str


class AgentActionOut(BaseModel):
    action: str
    result: str | None = None
    created_at: str


class AgentChatResponse(BaseModel):
    reply: str
    action: str | None = None
    action_result: str | None = None
    messages: list[AgentChatMessageOut] = []
    action_history: list[AgentActionOut] = []


class AgentTaskScope(BaseModel):
    categories: list[FindingCategory] = []
    file_globs: list[str] = []
    modules: list[str] = []
    max_items: int = 20


class AgentTaskOptions(BaseModel):
    top_n: int = 10
    include_code_snippet: bool = True
    allow_auto_actions: bool = False


class AgentTaskRequest(BaseModel):
    mode: str = Field(..., pattern="^(auth_gap_hunt|biz_gap_hunt|prioritize)$")
    scope: AgentTaskScope = Field(default_factory=AgentTaskScope)
    options: AgentTaskOptions = Field(default_factory=AgentTaskOptions)


class AgentTaskEvidence(BaseModel):
    type: str
    ref: str
    snippet: str | None = None


class AgentTaskItem(BaseModel):
    id: str
    title: str
    priority_score: int
    confidence: str
    finding_id: int | None = None
    category: str
    risk_type: str
    impact: str
    attack_path: str
    evidence: list[AgentTaskEvidence] = []
    recommendation: str
    actions: list[str] = []
    score_breakdown: dict[str, int] = {}


class AgentTaskResponse(BaseModel):
    ok: bool = True
    mode: str
    summary: str
    items: list[AgentTaskItem] = []
    next_actions: list[str] = []
    evidence_refs: list[str] = []
    metrics: dict[str, int] = {}


class LlmTestResult(BaseModel):
    ok: bool
    message: str
    model: str | None = None
    api_base: str | None = None
    provider: str | None = None
    latency_ms: int | None = None


class FeishuTestRequest(BaseModel):
    feishu_webhook_url: str | None = None
    feishu_at_user_ids: list[str] | None = None
    frontend_base_url: str | None = None


class FeishuTestResult(BaseModel):
    ok: bool
    message: str


class EmailTestRequest(BaseModel):
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_tls: bool | None = None
    email_from: str | None = None
    to_email: str | None = None


class EmailTestResult(BaseModel):
    ok: bool
    message: str


class GitLabTestRequest(BaseModel):
    project_url: str | None = None
    branch: str | None = None
    access_token: str | None = None


class GitLabTestResult(BaseModel):
    ok: bool
    code: str | None = None
    http_status: int | None = None
    message: str


class LlmAuditJournalEntry(BaseModel):
    id: int
    type: str
    level: str
    created_at: str
    file_path: str | None = None
    title: str = ""
    payload: dict = {}


class LlmAuditCancelResponse(BaseModel):
    status: str
    message: str


class LlmDiagnosisEvidenceOut(BaseModel):
    phase: str
    level: str
    message: str
    created_at: str


class LlmDiagnosisOut(BaseModel):
    scan_id: int
    code: str
    summary: str
    llm_findings: int
    llm_enabled: bool
    llm_code_audit_enabled: bool
    llm_configured: bool
    evidence: list[LlmDiagnosisEvidenceOut]
    suggestions: list[str]


class LlmAuditRequest(BaseModel):
    categories: list[FindingCategory] = Field(
        default_factory=list,
        description="可选侧重点：business_logic / authorization；为空时由 LLM 自主发挥",
    )


class ReportFilters(BaseModel):
    """结构化筛选条件；与列表页筛选语义保持一致。"""

    severity: list[str] | None = None
    owasp: list[str] | None = None
    source: list[str] | None = None
    tool: list[str] | None = None
    category: list[str] | None = None
    ai_verdict: list[str] | None = None
    review_status: list[str] | None = None
    external_status: list[str] | None = None
    subtype: list[str] | None = None
    keyword: str | None = None


class ReportInclude(BaseModel):
    """报告内容开关。"""

    snippet: bool = True
    poc: bool = False
    ai_reason: bool = True
    false_positive: bool = False
    retest: bool = True
    remediation: bool = True


class ReportSpec(BaseModel):
    """报告生成请求。finding_ids 优先级高于 filters；两者都为空时等价于全量。"""

    title: str | None = Field(default=None, max_length=200)
    finding_ids: list[int] | None = None
    filters: ReportFilters | None = None
    include: ReportInclude = Field(default_factory=ReportInclude)
    group_by: Literal["severity", "owasp", "file", "tool", "none"] = "severity"
    sort: Literal["severity", "file", "owasp", "id"] = "severity"


class ReportPreviewOut(BaseModel):
    """生成前的实时预览：条数 + 分布，用于确认口径是否与预期一致。"""

    scope: Literal["all", "selected", "filtered"]
    title: str
    total: int
    scan_total: int
    pdf_max_findings: int
    by_severity: dict[str, int]
    by_owasp: dict[str, int]
    by_source: dict[str, int]
    by_tool: dict[str, int]
