import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv, set_key
from pydantic_settings import BaseSettings, SettingsConfigDict

# Standalone backend repo: package root == project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_ROOT = PROJECT_ROOT
ENV_FILE = Path(os.getenv("AI_AUDIT_ENV_FILE") or (PROJECT_ROOT / ".env"))
load_dotenv(ENV_FILE)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ENV_FILE), env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AI Code Security Audit"
    debug: bool = False

    # Keep mutable data outside frontend/backend code trees.
    # Docker can override with DATA_DIR=/data.
    data_dir: Path = Path(os.getenv("DATA_DIR") or (PROJECT_ROOT / "data"))
    uploads_dir: Path = data_dir / "uploads"
    repos_dir: Path = data_dir / "repos"
    db_path: Path = data_dir / "audit.db"

    # Database: sqlite (local default) or mysql (production).
    database_backend: str = "sqlite"
    database_url: str = ""
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "ai_audit"
    mysql_password: str = ""
    mysql_database: str = "ai_audit_dev"
    mysql_charset: str = "utf8mb4"

    # LLM provider: openai (OpenAI-compatible API via API Key)
    llm_provider: str = "openai"
    llm_api_base: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    # Per-task model overrides (empty = use llm_model)
    llm_model_fp: str = ""
    llm_model_deep: str = ""
    llm_model_agent: str = ""
    # Per-task provider overrides (legacy; mapped to openai)
    llm_provider_fp: str = ""
    llm_provider_deep: str = ""
    llm_provider_agent: str = ""
    # Opt-in: auto-run SAST false-positive audit after scan (manual button always available)
    llm_enabled: bool = False

    # Opt-in: auto-run LLM endpoint audit after SAST (Jenkins/webhook included; toolbar still available)
    llm_code_audit_enabled: bool = False
    llm_audit_max_files: int = 25
    llm_audit_file_max_chars: int = 6000
    llm_audit_max_tokens: int = 8192
    # Endpoint-driven LLM audit (independent of SAST)
    llm_endpoint_audit_max_controllers: int = 40  # per-domain controller slice cap
    llm_endpoint_max_related_files: int = 4
    llm_endpoint_audit_max_iterations: int = 30  # total Goal safety budget across domains
    llm_endpoint_audit_max_domains: int = 3  # Top-N risk domains for Goal batches
    llm_endpoint_origin_sample_per_domain: int = 5  # sample endpoints in Understand summary
    llm_agent_max_tool_rounds: int = 10
    # Audit behavior profile: stable | balanced | broad
    llm_audit_profile: str = "balanced"
    llm_audit_require_stronger_evidence: bool = False
    llm_audit_enable_broader_hypotheses: bool = False
    # User-selected LLM audit focus areas (priority, not exclusive)
    llm_audit_focus_areas: list[str] = ["authz", "business_logic", "ai_prompt"]

    # Scanners
    semgrep_config: str = "auto"
    semgrep_timeout: int = 1800
    codeql_query_suite: str = "codeql/java-queries:codeql-suites/java-security-and-quality.qls"
    codeql_build_mode: str = "autobuild"
    codeql_java_build_command: str = ""
    codeql_timeout: int = 1200
    codeql_db_timeout: int = 900
    scanner_timeout: int = 120
    llm_timeout: int = 60
    # Optional absolute path to osv-scanner.exe (WinGet installs often miss stale PATH)
    osv_scanner_path: str = ""
    # Recover stale scans stuck in active states (e.g. after server restart)
    scan_stale_minutes: int = 5
    enabled_scanners: list[str] = [
        "semgrep",
        "codeql",
        "bandit",
        "gitleaks",
        "npm_audit",
        "pip_audit",
        "dep_exploit",
    ]
    # Skip test / fixture / mock source paths in SAST + LLM discovery (new scans only)
    exclude_test_paths: bool = True

    # Server
    app_port: int = 8787
    app_host: str = "127.0.0.1"

    # Feishu (Lark) notification (best-effort via Incoming Webhook)
    feishu_webhook_url: str = ""
    # Mention targets in Feishu webhook text. Format is Feishu user_id, e.g. "ou_xxx".
    feishu_at_user_ids: list[str] = []
    # Minimum severity to notify.
    feishu_notify_min_severity: str = "HIGH"
    # Frontend origin for deep-link. Default uses backend origin.
    frontend_base_url: str = ""

    # PDF 报告渲染引擎：
    #   "auto"       —— 优先 WeasyPrint，不可用时回退到无头浏览器（默认）
    #   "weasyprint" —— 只用 WeasyPrint
    #   "chrome"     —— 只用无头浏览器
    pdf_engine: str = "auto"
    # 无头浏览器可执行文件路径。留空则按 PATH 与常见安装位置自动探测。
    # Windows 上通常无需配置（自动找到 Chrome/Edge）。
    pdf_chrome_path: str = ""
    # 无头浏览器渲染 PDF 的超时时间（秒）。
    pdf_chrome_timeout: int = 180

    # Security score: deduct weight per finding from 100 (floor 0).
    score_weight_critical: int = 25
    score_weight_high: int = 10
    score_weight_medium: int = 3
    score_weight_low: int = 1
    score_weight_info: int = 0
    score_weight_unknown: int = 0
    score_exclude_ai_fp: bool = True

    # SMTP / email notification
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_tls: bool = True
    email_from: str = ""

    # GitLab
    gitlab_default_url: str = "https://gitlab.com"
    gitlab_access_token: str = ""
    gitlab_default_branch: str = "main"
    gitlab_tls_verify: bool = True

    # Inbound CI / Jenkins webhook (shared secret; not per-project)
    webhook_token: str = ""

    # Public temporary links (for read-only single finding view).
    # Token is signed and expires quickly to reduce leak risk.
    public_link_secret: str = ""
    public_link_ttl_seconds: int = 6 * 3600

    # Authentication
    auth_enabled: bool = True
    auth_username: str = "admin"
    # No usable credentials are shipped in source.  Production must provide
    # both values through the environment (or the service refuses to start).
    auth_password: str = ""
    auth_secret_key: str = ""
    auth_token_expire_hours: int = 12
    auth_refresh_token_expire_days: int = 7
    max_upload_bytes: int = 50 * 1024 * 1024

    # SSO integration (OAuth2 authorization code flow)
    sso_enabled: bool = False
    sso_base_url: str = ""
    sso_client_id: str = ""
    sso_client_secret: str = ""
    sso_redirect_uri: str = ""

    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://localhost:8080",
        "http://localhost:8787",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8787",
    ]


settings = Settings()


def validate_security_config(cfg: Settings | None = None) -> None:
    """Fail closed when authentication is enabled without real credentials."""
    cfg = cfg or settings
    if not cfg.auth_enabled:
        return
    password = (cfg.auth_password or "").strip()
    secret = (cfg.auth_secret_key or "").strip()
    if not password:
        raise RuntimeError("AUTH_PASSWORD must be configured when AUTH_ENABLED=true")
    if len(secret) < 32:
        raise RuntimeError("AUTH_SECRET_KEY must be at least 32 characters when AUTH_ENABLED=true")
    if "*" in (cfg.cors_origins or []):
        raise RuntimeError("CORS_ORIGINS must not contain '*' when credentials are enabled")

MYSQL_CHARSETS = ("utf8mb4", "utf8")


def normalize_mysql_charset(value: str | None) -> str:
    charset = (value or "utf8mb4").strip().lower().replace("-", "")
    if charset == "utf8mb3":
        return "utf8"
    if charset in MYSQL_CHARSETS:
        return charset
    return "utf8mb4"


def build_database_url(cfg: Settings | None = None) -> str:
    """Build SQLAlchemy async URL for the configured database backend."""
    cfg = cfg or settings
    explicit = (cfg.database_url or "").strip()
    if explicit:
        return explicit
    backend = (cfg.database_backend or "sqlite").strip().lower()
    if backend == "mysql":
        from urllib.parse import quote_plus

        user = quote_plus(cfg.mysql_user or "")
        password = quote_plus(cfg.mysql_password or "")
        host = (cfg.mysql_host or "127.0.0.1").strip()
        port = int(cfg.mysql_port or 3306)
        database = (cfg.mysql_database or "ai_audit_dev").strip()
        charset = normalize_mysql_charset(cfg.mysql_charset)
        return f"mysql+asyncmy://{user}:{password}@{host}:{port}/{database}?charset={charset}"
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{cfg.db_path.as_posix()}"


def database_backend_name(cfg: Settings | None = None) -> str:
    cfg = cfg or settings
    if (cfg.database_url or "").strip():
        url = cfg.database_url.lower()
        if url.startswith("mysql"):
            return "mysql"
        if url.startswith("sqlite"):
            return "sqlite"
    return (cfg.database_backend or "sqlite").strip().lower()


def persist_runtime_settings(pairs: dict[str, Any]) -> None:
    """
    Persist selected runtime settings to backend/.env,
    so values survive service restarts.
    """
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not ENV_FILE.exists():
        ENV_FILE.touch()

    for key, value in pairs.items():
        if value is None:
            continue
        if isinstance(value, bool):
            text = "true" if value else "false"
        elif isinstance(value, list):
            text = json.dumps(value, ensure_ascii=False)
        else:
            text = str(value)
        set_key(str(ENV_FILE), key, text)
