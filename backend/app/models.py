import enum
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def dt_iso(value: datetime | None) -> str | None:
    """Serialize datetimes as UTC ISO-8601. Naive values are treated as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat()


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    CLONING = "cloning"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    LLM_AUDITING = "llm_auditing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanSource(str, enum.Enum):
    UPLOAD = "upload"
    GITLAB = "gitlab"
    LOCAL = "local"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class AiVerdict(str, enum.Enum):
    PENDING = "pending"
    REAL_VULN = "real_vuln"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"
    SKIPPED = "skipped"


class ReviewStatus(str, enum.Enum):
    UNREVIEWED = "unreviewed"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class ExternalReviewStatus(str, enum.Enum):
    UNREVIEWED = "unreviewed"
    VULN_EXISTS = "vuln_exists"
    FALSE_POSITIVE = "false_positive"
    FIXED_CLAIMED = "fixed_claimed"


class FindingCategory(str, enum.Enum):
    SAST = "sast"
    BUSINESS_LOGIC = "business_logic"
    AUTHORIZATION = "authorization"


class ScanKind(str, enum.Enum):
    BASELINE = "baseline"
    RETEST = "retest"
    AD_HOC = "ad_hoc"


class RetestStrategy(str, enum.Enum):
    TARGETED = "targeted"
    FULL = "full"


class RetestVerdict(str, enum.Enum):
    FIXED = "fixed"
    STILL_PRESENT = "still_present"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class RetestMethod(str, enum.Enum):
    PATTERN = "pattern"
    SEMGREP_RULE = "semgrep_rule"
    DEP_EXPLOIT = "dep_exploit"
    LLM = "llm"
    MANUAL = "manual"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_type: Mapped[ScanSource] = mapped_column(
        Enum(
            ScanSource,
            values_callable=lambda obj: [e.value for e in obj],
            native_enum=False,
            validate_strings=True,
        ),
        default=ScanSource.UPLOAD,
    )
    source_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    default_branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scan_languages_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    scans: Mapped[List["ScanTask"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="desc(ScanTask.created_at)",
    )


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    parent_scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_kind: Mapped[ScanKind] = mapped_column(
        Enum(
            ScanKind,
            values_callable=lambda obj: [e.value for e in obj],
            native_enum=False,
            validate_strings=True,
        ),
        default=ScanKind.BASELINE,
    )
    version_label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    retest_strategy: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    retest_options_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    source: Mapped[ScanSource] = mapped_column(Enum(ScanSource))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    project_path: Mapped[str] = mapped_column(String(1024))
    source_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notify_emails_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    progress_message: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    semgrep_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scanner_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    security_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    score_breakdown_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    project_review_token: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, unique=True, index=True)
    project_review_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    project_review_revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped[Optional["Project"]] = relationship(back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    events: Mapped[List["ScanEvent"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    retest_verifications: Mapped[List["RetestVerification"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        foreign_keys="RetestVerification.scan_id",
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_tool", "scan_id", "tool"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(512))
    check_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.UNKNOWN)
    message: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str] = mapped_column(String(1024))
    line_start: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool: Mapped[str] = mapped_column(String(64), default="semgrep")
    category: Mapped[FindingCategory] = mapped_column(Enum(FindingCategory), default=FindingCategory.SAST)
    ai_verdict: Mapped[AiVerdict] = mapped_column(Enum(AiVerdict), default=AiVerdict.PENDING)
    ai_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    message_zh: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    review_status: Mapped[ReviewStatus] = mapped_column(
        Enum(ReviewStatus), default=ReviewStatus.UNREVIEWED
    )
    review_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    external_status: Mapped[ExternalReviewStatus] = mapped_column(
        Enum(
            ExternalReviewStatus,
            values_callable=lambda obj: [e.value for e in obj],
            native_enum=False,
            validate_strings=True,
        ),
        default=ExternalReviewStatus.UNREVIEWED,
    )
    external_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    external_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    external_updated_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    external_review_token: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    external_review_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    external_review_revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    owasp_id: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    owasp_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    vuln_subtype: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    vuln_subtype_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    scan: Mapped["ScanTask"] = relationship(back_populates="findings")


class ProjectSuppression(Base):
    __tablename__ = "project_suppressions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint_strict: Mapped[str] = mapped_column(String(1024), index=True)
    fingerprint_relaxed: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True, index=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="false_positive")
    reason: Mapped[str] = mapped_column(Text)
    source_scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_tasks.id", ondelete="SET NULL"), nullable=True)
    source_finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RetestVerification(Base):
    __tablename__ = "retest_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    baseline_scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    baseline_finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    verdict: Mapped[str] = mapped_column(String(32))
    method: Mapped[str] = mapped_column(String(32))
    evidence_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped["ScanTask"] = relationship(back_populates="retest_verifications", foreign_keys=[scan_id])
    baseline_finding: Mapped["Finding"] = relationship(foreign_keys=[baseline_finding_id])


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(16), default="info")
    phase: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tool: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped["ScanTask"] = relationship(back_populates="events")


class SystemSetting(Base):
    __tablename__ = "system_settings"

    setting_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    setting_value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    local_refresh_token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), index=True)
    sso_refresh_token: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="user")
    expire_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ============ Phase 2: platform management (configuration only) ============


class AgentDefinition(Base):
    """Agent configuration records. No scheduler consumes these rows yet."""

    __tablename__ = "agent_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32), default="worker")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # One of: default | fp | deep | agent -> maps to llm_model* settings.
    model_task: Mapped[str] = mapped_column(String(32), default="agent")
    model_override: Mapped[str] = mapped_column(String(128), default="")
    system_prompt: Mapped[str] = mapped_column(Text, default="")
    max_tool_rounds: Mapped[int] = mapped_column(Integer, default=10)
    max_files: Mapped[int] = mapped_column(Integer, default=16)
    max_tokens: Mapped[int] = mapped_column(Integer, default=8192)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class McpServer(Base):
    """Registered MCP server descriptors. Credentials are never persisted.

    `last_test_*` columns are written only by a real connection probe.
    """

    __tablename__ = "mcp_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    transport: Mapped[str] = mapped_column(String(16), default="http")
    endpoint: Mapped[str] = mapped_column(String(512), default="")
    command: Mapped[str] = mapped_column(String(512), default="")
    args_json: Mapped[str] = mapped_column(Text, default="[]")
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=5)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_test_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_test_ok: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    last_test_message: Mapped[str] = mapped_column(Text, default="")
    last_test_latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class PlatformAuditLog(Base):
    """Append-only trail of platform-management mutations."""

    __tablename__ = "platform_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(100), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
