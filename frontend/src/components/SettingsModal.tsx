import { useEffect, useRef, useState } from "react";
import { ErrorState, LoadingState } from "../shared/ui";
import { createPortal } from "react-dom";
import { ApiError, api, type ScannerInfo, type Settings } from "../api";
import { LLM_AUDIT_FOCUS_OPTIONS, normalizeFocusAreas } from "../lib/llmAuditFocus";
import { Settings as SettingsIcon } from "./ui";
import { AuditSkillManager } from "./AuditSkills";

function generateWebhookToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

interface Props {
  open: boolean;
  onClose: () => void;
  onSaved?: () => void;
  /** Render inline inside a routed page instead of a portal modal. */
  embedded?: boolean;
  /** Restrict visible sections (used to split settings across System / LLM / Skills pages). */
  sections?: SettingsSection[];
  initialSection?: SettingsSection;
  title?: string;
  /** `categories` = routed System Management shell; `modal` = legacy popup. */
  layout?: "modal" | "categories";
}

export type SettingsSection =
  | "sast-scanners"
  | "sast-semgrep"
  | "sast-codeql"
  | "llm-api"
  | "llm-models"
  | "llm-auto"
  | "audit-strategy"
  | "audit-skills"
  | "audit-endpoint"
  | "audit-advanced"
  | "notify-feishu"
  | "notify-email"
  | "gitlab"
  | "database"
  | "auth-token"
  | "score-rules";

export const MENU_GROUPS: { id: string; label: string; items: { id: SettingsSection; label: string }[] }[] = [
  {
    id: "sast",
    label: "SAST 工具",
    items: [
      { id: "sast-scanners", label: "扫描器启用" },
      { id: "sast-semgrep", label: "Semgrep" },
      { id: "sast-codeql", label: "CodeQL" },
    ],
  },
  {
    id: "llm",
    label: "LLM 配置",
    items: [
      { id: "llm-api", label: "API 连接" },
      { id: "llm-models", label: "任务模型" },
      { id: "llm-auto", label: "扫描自动化" },
    ],
  },
  {
    id: "audit",
    label: "LLM 深度审计",
    items: [
      { id: "audit-strategy", label: "审计风格与关注重点" },
      { id: "audit-skills", label: "Skill 管理" },
      { id: "audit-endpoint", label: "端点驱动" },
      { id: "audit-advanced", label: "高级参数" },
    ],
  },
  {
    id: "integration",
    label: "集成",
    items: [
      { id: "database", label: "数据存储" },
      { id: "auth-token", label: "Token 有效期" },
      { id: "score-rules", label: "安全打分" },
      { id: "gitlab", label: "GitLab" },
      { id: "notify-feishu", label: "飞书通知" },
      { id: "notify-email", label: "邮件报告" },
    ],
  },
];

const CATEGORY_LABELS: Record<string, string> = {
  sast: "静态分析",
  secrets: "密钥泄露",
  sca: "依赖漏洞",
};

export const SECTION_TITLES: Record<SettingsSection, string> = {
  "sast-scanners": "扫描器启用",
  "sast-semgrep": "Semgrep 配置",
  "sast-codeql": "CodeQL 配置",
  "llm-api": "LLM API 连接",
  "llm-models": "按任务配置模型",
  "llm-auto": "扫描后自动化",
  "audit-strategy": "审计风格与关注重点",
  "audit-skills": "审计 Skill 管理",
  "audit-endpoint": "端点驱动审计",
  "audit-advanced": "LLM 审计高级参数",
  gitlab: "GitLab 接入",
  database: "数据存储",
  "notify-feishu": "飞书通知",
  "notify-email": "邮件报告 (SMTP)",
  "auth-token": "Token 有效期",
  "score-rules": "安全打分规则",
};

/**
 * System Management information architecture.
 *
 * The backend exposes one flat PATCH endpoint (PUT /api/settings: only non-null
 * fields are applied), so `fields` is a pure client-side compatibility layer:
 * saving a category submits only that category's keys. No backend protocol
 * change is required, and no legacy setting is dropped.
 *
 * LLM API/model sections live on /llm, `audit-skills` lives on /skills.
 */
export interface SystemCategory {
  id: string;
  label: string;
  description: string;
  sections: SettingsSection[];
  fields: string[];
}

export const SYSTEM_CATEGORIES: SystemCategory[] = [
  {
    id: "scanners",
    label: "扫描器管理",
    description: "SAST 扫描器的启用状态、安装状态与工具参数。启用不等于已安装。",
    sections: ["sast-scanners", "sast-semgrep", "sast-codeql"],
    fields: [
      "semgrep_config", "semgrep_timeout", "codeql_query_suite", "codeql_build_mode",
      "codeql_java_build_command", "codeql_timeout", "codeql_db_timeout",
      "enabled_scanners", "exclude_test_paths",
    ],
  },
  {
    id: "audit-policy",
    label: "审计策略",
    description: "审计风格、证据严格度、关注重点与 LLM 审计输入预算。",
    sections: ["audit-strategy"],
    fields: [
      "llm_audit_profile", "llm_audit_require_stronger_evidence",
      "llm_audit_enable_broader_hypotheses", "llm_audit_focus_areas",
      "llm_audit_max_files", "llm_audit_file_max_chars", "llm_audit_max_tokens",
    ],
  },
  {
    id: "automation",
    label: "扫描自动化",
    description: "扫描完成后自动触发 LLM 深度审计等自动化行为。",
    sections: ["llm-auto"],
    fields: ["llm_code_audit_enabled", "llm_enabled"],
  },
  {
    id: "integrations",
    label: "集成配置",
    description: "GitLab 接入、Webhook、飞书与邮件通知等外部服务。",
    sections: ["gitlab", "notify-feishu", "notify-email"],
    fields: [
      "gitlab_default_url", "gitlab_default_branch", "gitlab_tls_verify",
      "gitlab_access_token", "webhook_token", "feishu_webhook_url",
      "feishu_at_user_ids", "feishu_notify_min_severity", "frontend_base_url",
      "smtp_host", "smtp_port", "smtp_user", "smtp_tls", "smtp_password",
      "email_from",
    ],
  },
  {
    id: "storage",
    label: "数据存储",
    description: "数据库后端与连接参数。切换后端不会自动迁移旧库数据。",
    sections: ["database"],
    fields: [
      "database_backend", "database_url", "mysql_host", "mysql_port",
      "mysql_user", "mysql_password", "mysql_database", "mysql_charset",
    ],
  },
  {
    id: "scoring",
    label: "安全评分",
    description: "漏洞级别权重与 AI 误报排除规则；保存后后端会重算历史扫描分数。",
    sections: ["score-rules"],
    fields: [
      "score_weight_critical", "score_weight_high", "score_weight_medium",
      "score_weight_low", "score_weight_info", "score_weight_unknown",
      "score_exclude_ai_fp",
    ],
  },
  {
    id: "security",
    label: "系统安全",
    description: "访问令牌与刷新令牌有效期，影响全局会话。",
    sections: ["auth-token"],
    fields: ["auth_token_expire_hours", "auth_refresh_token_expire_days"],
  },
  {
    id: "advanced",
    label: "高级设置",
    description: "端点驱动审计与 Agent 工具轮次等进阶参数。Agent 专属 Prompt 请到「Agent 配置」维护。",
    sections: ["audit-endpoint", "audit-advanced"],
    fields: [
      "llm_endpoint_audit_max_controllers", "llm_endpoint_max_related_files",
      "llm_endpoint_audit_max_iterations", "llm_endpoint_audit_max_domains",
      "llm_endpoint_origin_sample_per_domain", "llm_agent_max_tool_rounds",
    ],
  },
];

export const SYSTEM_SECTIONS: SettingsSection[] = SYSTEM_CATEGORIES.flatMap((c) => c.sections);

export function SettingsModal({
  open,
  onClose,
  onSaved,
  embedded = false,
  sections,
  initialSection,
  title = "平台配置",
  layout = "modal",
}: Props) {
  const categoriesMode = layout === "categories";
  const [activeCategory, setActiveCategory] = useState<string>(SYSTEM_CATEGORIES[0].id);
  const [reloadTick, setReloadTick] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const baselineRef = useRef<string>("");
  const visibleGroups = MENU_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !sections || sections.includes(item.id)),
  })).filter((group) => group.items.length > 0);
  const [active, setActive] = useState<SettingsSection>(
    initialSection ?? sections?.[0] ?? "sast-scanners",
  );
  const [form, setForm] = useState({
    llm_api_base: "",
    llm_api_key: "",
    llm_model: "",
    llm_model_fp: "",
    llm_model_deep: "",
    llm_model_agent: "",
    llm_enabled: false,
    llm_code_audit_enabled: false,
    llm_timeout: 60,
    llm_audit_max_files: 25,
    llm_audit_file_max_chars: 6000,
    llm_audit_max_tokens: 8192,
    llm_endpoint_audit_max_controllers: 40,
    llm_endpoint_max_related_files: 4,
    llm_endpoint_audit_max_iterations: 12,
    llm_endpoint_audit_max_domains: 3,
    llm_endpoint_origin_sample_per_domain: 5,
    llm_agent_max_tool_rounds: 10,
    llm_audit_profile: "balanced" as "stable" | "balanced" | "broad",
    llm_audit_require_stronger_evidence: false,
    llm_audit_enable_broader_hypotheses: false,
    llm_audit_focus_areas: [] as string[],
    semgrep_config: "auto",
    semgrep_timeout: 1800,
    codeql_query_suite: "",
    codeql_build_mode: "autobuild",
    codeql_java_build_command: "",
    codeql_timeout: 1200,
    codeql_db_timeout: 900,
    enabled_scanners: [] as string[],
    exclude_test_paths: true,
    feishu_webhook_url: "",
    feishu_at_user_ids: [] as string[],
    feishu_notify_min_severity: "HIGH",
    smtp_host: "",
    smtp_port: 465,
    smtp_user: "",
    smtp_password: "",
    smtp_tls: true,
    email_from: "",
    smtp_test_to: "",
    frontend_base_url: "",
    gitlab_default_url: "https://gitlab.com",
    gitlab_access_token: "",
    gitlab_default_branch: "main",
    gitlab_tls_verify: true,
    gitlab_test_project_url: "",
    webhook_token: "",
    database_backend: "sqlite" as "sqlite" | "mysql",
    database_url: "",
    mysql_host: "127.0.0.1",
    mysql_port: 3306,
    mysql_user: "ai_audit",
    mysql_password: "",
    mysql_database: "ai_audit_dev",
    mysql_charset: "utf8mb4" as "utf8mb4" | "utf8",
    auth_token_expire_hours: 12,
    auth_refresh_token_expire_days: 7,
    score_weight_critical: 25,
    score_weight_high: 10,
    score_weight_medium: 3,
    score_weight_low: 1,
    score_weight_info: 0,
    score_weight_unknown: 0,
    score_exclude_ai_fp: true,
  });
  const dirty = loaded && JSON.stringify(form) !== baselineRef.current;
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [scannersLoading, setScannersLoading] = useState(false);
  const [scannersLoadError, setScannersLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testingLlm, setTestingLlm] = useState(false);
  const [llmTestResult, setLlmTestResult] = useState<{ ok: boolean; message: string; latency_ms?: number } | null>(null);
  const [testingFeishu, setTestingFeishu] = useState(false);
  const [feishuTestResult, setFeishuTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [testingEmail, setTestingEmail] = useState(false);
  const [emailTestResult, setEmailTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [testingGitlab, setTestingGitlab] = useState(false);
  const [gitlabTestResult, setGitlabTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [feishuConfigured, setFeishuConfigured] = useState(false);
  const [gitlabTokenConfigured, setGitlabTokenConfigured] = useState(false);
  const [webhookTokenConfigured, setWebhookTokenConfigured] = useState(false);
  const [mysqlPasswordConfigured, setMysqlPasswordConfigured] = useState(false);
  const [smtpPasswordConfigured, setSmtpPasswordConfigured] = useState(false);
  const [testingDatabase, setTestingDatabase] = useState(false);
  const [databaseTestResult, setDatabaseTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  const applyAuditProfilePreset = (profile: "stable" | "balanced" | "broad") => {
    setForm((prev) => {
      if (profile === "stable") {
        return {
          ...prev,
          llm_audit_profile: profile,
          llm_audit_require_stronger_evidence: true,
          llm_audit_enable_broader_hypotheses: false,
          llm_endpoint_audit_max_domains: 2,
          llm_endpoint_audit_max_iterations: 18,
          llm_endpoint_audit_max_controllers: 24,
          llm_endpoint_max_related_files: 3,
          llm_agent_max_tool_rounds: 8,
        };
      }
      if (profile === "broad") {
        return {
          ...prev,
          llm_audit_profile: profile,
          llm_audit_require_stronger_evidence: false,
          llm_audit_enable_broader_hypotheses: true,
          llm_endpoint_audit_max_domains: 5,
          llm_endpoint_audit_max_iterations: 45,
          llm_endpoint_audit_max_controllers: 60,
          llm_endpoint_max_related_files: 6,
          llm_agent_max_tool_rounds: 16,
        };
      }
      return {
        ...prev,
        llm_audit_profile: profile,
        llm_audit_require_stronger_evidence: false,
        llm_audit_enable_broader_hypotheses: false,
        llm_endpoint_audit_max_domains: 3,
        llm_endpoint_audit_max_iterations: 30,
        llm_endpoint_audit_max_controllers: 40,
        llm_endpoint_max_related_files: 4,
        llm_agent_max_tool_rounds: 10,
      };
    });
  };
  const [buildId, setBuildId] = useState("unknown");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (open || embedded) {
      setScannersLoading(true);
      setScannersLoadError(null);
      api
        .getSettings()
        .then(async (s) => {
          let scannerList: ScannerInfo[] = [];
          try {
            scannerList = await api.listScanners();
          } catch (e) {
            setScannersLoadError(String(e));
          }

          const list = s.scanners?.length ? s.scanners : scannerList;
          const rawProfile = (s as Settings & { llm_audit_profile?: string }).llm_audit_profile;
          if (rawProfile === undefined) {
            setMessage("当前后端未提供审计档位配置，请重启后端服务（uvicorn）后再保存设置。");
          }
          const nextForm: typeof form = {
            llm_api_base: s.llm_api_base,
            llm_api_key: "",
            llm_model: s.llm_model,
            llm_model_fp: s.llm_model_fp || "",
            llm_model_deep: s.llm_model_deep || "",
            llm_model_agent: s.llm_model_agent || "",
            llm_enabled: s.llm_enabled,
            llm_code_audit_enabled: s.llm_code_audit_enabled,
            llm_timeout: s.llm_timeout ?? 60,
            llm_audit_max_files: s.llm_audit_max_files ?? 25,
            llm_audit_file_max_chars: s.llm_audit_file_max_chars ?? 6000,
            llm_audit_max_tokens: s.llm_audit_max_tokens ?? 8192,
            llm_endpoint_audit_max_controllers: s.llm_endpoint_audit_max_controllers ?? 40,
            llm_endpoint_max_related_files: s.llm_endpoint_max_related_files ?? 4,
            llm_endpoint_audit_max_iterations: s.llm_endpoint_audit_max_iterations ?? 12,
            llm_endpoint_audit_max_domains: s.llm_endpoint_audit_max_domains ?? 3,
            llm_endpoint_origin_sample_per_domain: s.llm_endpoint_origin_sample_per_domain ?? 5,
            llm_agent_max_tool_rounds: s.llm_agent_max_tool_rounds ?? 10,
            llm_audit_profile:
              s.llm_audit_profile === "stable" ||
              s.llm_audit_profile === "balanced" ||
              s.llm_audit_profile === "broad"
                ? s.llm_audit_profile
                : "balanced",
            llm_audit_require_stronger_evidence: Boolean(s.llm_audit_require_stronger_evidence),
            llm_audit_enable_broader_hypotheses: Boolean(s.llm_audit_enable_broader_hypotheses),
            llm_audit_focus_areas: normalizeFocusAreas(s.llm_audit_focus_areas),
            semgrep_config: s.semgrep_config,
            semgrep_timeout: s.semgrep_timeout ?? 1800,
            codeql_query_suite: s.codeql_query_suite,
            codeql_build_mode: s.codeql_build_mode,
            codeql_java_build_command: s.codeql_java_build_command,
            codeql_timeout: s.codeql_timeout,
            codeql_db_timeout: s.codeql_db_timeout,
            feishu_webhook_url: s.feishu_webhook_url ?? "",
            feishu_at_user_ids: s.feishu_at_user_ids ?? [],
            feishu_notify_min_severity: s.feishu_notify_min_severity ?? "HIGH",
            smtp_host: s.smtp_host ?? "",
            smtp_port: s.smtp_port ?? 465,
            smtp_user: s.smtp_user ?? "",
            smtp_password: "",
            smtp_tls: s.smtp_tls ?? true,
            email_from: s.email_from ?? "",
            smtp_test_to: "",
            frontend_base_url:
              s.frontend_base_url ||
              (typeof window !== "undefined" ? window.location.origin : ""),
            gitlab_default_url: s.gitlab_default_url || "https://gitlab.com",
            gitlab_access_token: "",
            gitlab_default_branch: s.gitlab_default_branch || "main",
            gitlab_tls_verify: s.gitlab_tls_verify ?? true,
            gitlab_test_project_url: "",
            webhook_token: "",
            database_backend:
              s.database_backend === "mysql" || s.database_backend === "sqlite"
                ? s.database_backend
                : "sqlite",
            database_url: s.database_url || "",
            mysql_host: s.mysql_host || "127.0.0.1",
            mysql_port: s.mysql_port ?? 3306,
            mysql_user: s.mysql_user || "ai_audit",
            mysql_password: "",
            mysql_database: s.mysql_database || "ai_audit_dev",
            mysql_charset: s.mysql_charset === "utf8" ? "utf8" : "utf8mb4",
            enabled_scanners: s.enabled_scanners?.length ? s.enabled_scanners : list.map((x) => x.id),
            exclude_test_paths: s.exclude_test_paths ?? true,
            auth_token_expire_hours: s.auth_token_expire_hours ?? 12,
            auth_refresh_token_expire_days: s.auth_refresh_token_expire_days ?? 7,
            score_weight_critical: s.score_weight_critical ?? 25,
            score_weight_high: s.score_weight_high ?? 10,
            score_weight_medium: s.score_weight_medium ?? 3,
            score_weight_low: s.score_weight_low ?? 1,
            score_weight_info: s.score_weight_info ?? 0,
            score_weight_unknown: s.score_weight_unknown ?? 0,
            score_exclude_ai_fp: s.score_exclude_ai_fp ?? true,
          };
          setForm(nextForm);
          baselineRef.current = JSON.stringify(nextForm);
          setLoaded(true);
          setLoadFailed(false);
          setFeishuConfigured(Boolean(s.feishu_configured || (s.feishu_webhook_url || "").trim()));
          setGitlabTokenConfigured(Boolean(s.gitlab_access_token_configured));
          setWebhookTokenConfigured(Boolean(s.webhook_token_configured));
          setMysqlPasswordConfigured(Boolean(s.mysql_password_configured));
          setSmtpPasswordConfigured(Boolean(s.smtp_password_configured));
          setScanners(list);
          if (list.length === 0) {
            setScannersLoadError((prev) => prev || "后端未返回扫描器列表");
          }
        })
        .catch((e) => {
          setLoadFailed(true);
          if (e instanceof ApiError && e.status === 403) {
            setMessage("无权限访问系统设置（需要管理员角色）");
            if (!embedded && !categoriesMode) onClose();
            return;
          }
          setMessage(`加载设置失败: ${e}`);
        })
        .finally(() => setScannersLoading(false));
      api
        .getBuildInfo()
        .then((info) => setBuildId(info.build_id || "unknown"))
        .catch(() => setBuildId("unknown"));
    }
  }, [open, embedded, categoriesMode, reloadTick]);

  // Hooks must never live inside a conditional branch (see 2026-11-11 white-screen notes).
  useEffect(() => {
    if (!categoriesMode || !dirty) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [categoriesMode, dirty]);

  if (!open && !embedded) return null;

  const toggleScanner = (id: string) => {
    setForm((prev) => ({
      ...prev,
      enabled_scanners: prev.enabled_scanners.includes(id)
        ? prev.enabled_scanners.filter((s) => s !== id)
        : [...prev.enabled_scanners, id],
    }));
  };

  const testDatabase = async () => {
    setTestingDatabase(true);
    setDatabaseTestResult(null);
    try {
      const r = await api.testDatabase({
        database_backend: form.database_backend,
        database_url: form.database_url || undefined,
        mysql_host: form.mysql_host,
        mysql_port: form.mysql_port,
        mysql_user: form.mysql_user,
        mysql_database: form.mysql_database,
        mysql_charset: form.mysql_charset,
        ...(form.mysql_password ? { mysql_password: form.mysql_password } : {}),
      });
      setDatabaseTestResult(r);
    } catch (e) {
      setDatabaseTestResult({ ok: false, message: String(e) });
    } finally {
      setTestingDatabase(false);
    }
  };

  const testFeishu = async () => {
    setTestingFeishu(true);
    setFeishuTestResult(null);
    try {
      const r = await api.testFeishu({
        feishu_webhook_url: form.feishu_webhook_url,
        feishu_at_user_ids: form.feishu_at_user_ids,
        frontend_base_url: form.frontend_base_url,
      });
      setFeishuTestResult(r);
      setFeishuConfigured(Boolean(form.feishu_webhook_url.trim()) && r.ok);
    } catch (e) {
      setFeishuTestResult({ ok: false, message: String(e) });
    } finally {
      setTestingFeishu(false);
    }
  };

  const testEmail = async () => {
    setTestingEmail(true);
    setEmailTestResult(null);
    try {
      const r = await api.testEmail({
        smtp_host: form.smtp_host || undefined,
        smtp_port: form.smtp_port,
        smtp_user: form.smtp_user || undefined,
        smtp_tls: form.smtp_tls,
        email_from: form.email_from || undefined,
        to_email: form.smtp_test_to.trim() || undefined,
        ...(form.smtp_password ? { smtp_password: form.smtp_password } : {}),
      });
      setEmailTestResult(r);
    } catch (e) {
      const msg =
        e instanceof DOMException && e.name === "AbortError"
          ? "发送超时（35s）。请检查 SMTP 主机、端口与 TLS：465 用 SSL，587 用 STARTTLS。"
          : String(e);
      setEmailTestResult({ ok: false, message: msg });
    } finally {
      setTestingEmail(false);
    }
  };

  const testGitlab = async () => {
    setTestingGitlab(true);
    setGitlabTestResult(null);
    const projectUrl = form.gitlab_test_project_url.trim();
    if (!projectUrl) {
      setGitlabTestResult({ ok: false, message: "请填写要测试的 GitLab 仓库 URL" });
      setTestingGitlab(false);
      return;
    }
    try {
      const r = await api.testGitlab({
        project_url: projectUrl,
        branch: form.gitlab_default_branch || "main",
        ...(form.gitlab_access_token ? { access_token: form.gitlab_access_token } : {}),
      });
      setGitlabTestResult(r);
    } catch (e) {
      setGitlabTestResult({ ok: false, message: String(e) });
    } finally {
      setTestingGitlab(false);
    }
  };

  const testLlm = async () => {
    setTestingLlm(true);
    setLlmTestResult(null);
    try {
      await api.updateSettings({
        llm_provider: "openai",
        llm_api_base: form.llm_api_base,
        llm_model: form.llm_model,
        llm_model_fp: form.llm_model_fp,
        llm_model_deep: form.llm_model_deep,
        llm_model_agent: form.llm_model_agent,
        llm_timeout: form.llm_timeout,
        ...(form.llm_api_key ? { llm_api_key: form.llm_api_key } : {}),
      });
      const r = await api.testLlm();
      setLlmTestResult(r);
    } catch (e) {
      setLlmTestResult({ ok: false, message: String(e) });
    } finally {
      setTestingLlm(false);
    }
  };

  const save = async (categoryId?: string) => {
    setSaving(true);
    setMessage("");
    try {
      const scopedCategory = categoriesMode
        ? SYSTEM_CATEGORIES.find((c) => c.id === (categoryId ?? activeCategory))
        : null;
      const scoreOnly = !scopedCategory && active === "score-rules";
      const body: Record<string, unknown> = scoreOnly
        ? {
            score_weight_critical: form.score_weight_critical,
            score_weight_high: form.score_weight_high,
            score_weight_medium: form.score_weight_medium,
            score_weight_low: form.score_weight_low,
            score_weight_info: form.score_weight_info,
            score_weight_unknown: form.score_weight_unknown,
            score_exclude_ai_fp: form.score_exclude_ai_fp,
          }
        : {
            llm_provider: "openai",
            llm_api_base: form.llm_api_base,
            llm_model: form.llm_model,
            llm_model_fp: form.llm_model_fp,
            llm_model_deep: form.llm_model_deep,
            llm_model_agent: form.llm_model_agent,
            llm_provider_fp: "",
            llm_provider_deep: "",
            llm_provider_agent: "",
            llm_enabled: form.llm_enabled,
            llm_code_audit_enabled: form.llm_code_audit_enabled,
            llm_timeout: form.llm_timeout,
            llm_audit_max_files: form.llm_audit_max_files,
            llm_audit_file_max_chars: form.llm_audit_file_max_chars,
            llm_audit_max_tokens: form.llm_audit_max_tokens,
            llm_endpoint_audit_max_controllers: form.llm_endpoint_audit_max_controllers,
            llm_endpoint_max_related_files: form.llm_endpoint_max_related_files,
            llm_endpoint_audit_max_iterations: form.llm_endpoint_audit_max_iterations,
            llm_endpoint_audit_max_domains: form.llm_endpoint_audit_max_domains,
            llm_endpoint_origin_sample_per_domain: form.llm_endpoint_origin_sample_per_domain,
            llm_agent_max_tool_rounds: form.llm_agent_max_tool_rounds,
            llm_audit_profile: form.llm_audit_profile,
            llm_audit_require_stronger_evidence: form.llm_audit_require_stronger_evidence,
            llm_audit_enable_broader_hypotheses: form.llm_audit_enable_broader_hypotheses,
            llm_audit_focus_areas: normalizeFocusAreas(form.llm_audit_focus_areas),
            semgrep_config: form.semgrep_config,
            semgrep_timeout: form.semgrep_timeout,
            codeql_query_suite: form.codeql_query_suite,
            codeql_build_mode: form.codeql_build_mode,
            codeql_java_build_command: form.codeql_java_build_command,
            codeql_timeout: form.codeql_timeout,
            codeql_db_timeout: form.codeql_db_timeout,
            enabled_scanners: form.enabled_scanners,
            exclude_test_paths: form.exclude_test_paths,
            feishu_webhook_url: form.feishu_webhook_url,
            feishu_at_user_ids: form.feishu_at_user_ids,
            feishu_notify_min_severity: form.feishu_notify_min_severity,
            smtp_host: form.smtp_host,
            smtp_port: form.smtp_port,
            smtp_user: form.smtp_user,
            smtp_tls: form.smtp_tls,
            email_from: form.email_from,
            frontend_base_url: form.frontend_base_url,
            gitlab_default_url: form.gitlab_default_url,
            gitlab_default_branch: form.gitlab_default_branch,
            gitlab_tls_verify: form.gitlab_tls_verify,
            database_backend: form.database_backend,
            database_url: form.database_url,
            mysql_host: form.mysql_host,
            mysql_port: form.mysql_port,
            mysql_user: form.mysql_user,
            mysql_database: form.mysql_database,
            mysql_charset: form.mysql_charset,
            auth_token_expire_hours: form.auth_token_expire_hours,
            auth_refresh_token_expire_days: form.auth_refresh_token_expire_days,
            score_weight_critical: form.score_weight_critical,
            score_weight_high: form.score_weight_high,
            score_weight_medium: form.score_weight_medium,
            score_weight_low: form.score_weight_low,
            score_weight_info: form.score_weight_info,
            score_weight_unknown: form.score_weight_unknown,
            score_exclude_ai_fp: form.score_exclude_ai_fp,
          };
      if (!scoreOnly) {
        if (form.llm_api_key) body.llm_api_key = form.llm_api_key;
        if (form.gitlab_access_token.trim()) body.gitlab_access_token = form.gitlab_access_token.trim();
        if (form.webhook_token.trim()) body.webhook_token = form.webhook_token.trim();
        if (form.mysql_password.trim()) body.mysql_password = form.mysql_password.trim();
        if (form.smtp_password.trim()) body.smtp_password = form.smtp_password.trim();
      }
      const payload = scopedCategory
        ? (Object.fromEntries(
            Object.entries(body).filter(([key]) => scopedCategory.fields.includes(key)),
          ) as Parameters<typeof api.updateSettings>[0])
        : (body as Parameters<typeof api.updateSettings>[0]);
      const saved = await api.updateSettings(payload);
      if (scopedCategory) {
        baselineRef.current = JSON.stringify(form);
        const dbHint = saved.database_switched
          ? " 数据库已切换并立即生效（旧库数据不会自动迁移）。"
          : "";
        const scoreHint = saved.scores_recalculated != null
          ? ` 已按新规则重算 ${saved.scores_recalculated} 个扫描分数。`
          : "";
        setMessage(`${scopedCategory.label}已保存。${dbHint}${scoreHint}`);
        onSaved?.();
        return;
      }
      if (!scoreOnly) {
        const savedProfile = saved.llm_audit_profile;
        if (body.llm_audit_profile && !savedProfile) {
          setMessage(
            "审计档位未保存成功：当前后端未返回 llm_audit_profile，请重启后端服务（uvicorn）后重试。"
          );
          return;
        }
        if (savedProfile && savedProfile !== body.llm_audit_profile) {
          setMessage(
            `审计档位保存异常：期望 ${body.llm_audit_profile}，后端返回 ${savedProfile}。请刷新后重试。`
          );
          return;
        }
        if (!Array.isArray(saved.llm_audit_focus_areas)) {
          setMessage(
            "审计关注重点未保存成功：当前后端未返回 llm_audit_focus_areas，请重启后端服务后重试。"
          );
          return;
        }
        const wantedFocus = normalizeFocusAreas(body.llm_audit_focus_areas as string[]);
        const savedFocus = normalizeFocusAreas(saved.llm_audit_focus_areas);
        if (wantedFocus.join(",") !== savedFocus.join(",")) {
          setMessage(
            `审计关注重点保存异常：期望 [${wantedFocus.join(", ")}]，后端返回 [${savedFocus.join(", ")}]。请刷新后重试。`
          );
          return;
        }
        setForm((prev) => ({
          ...prev,
          llm_audit_profile: savedProfile || prev.llm_audit_profile,
          llm_audit_require_stronger_evidence: Boolean(saved.llm_audit_require_stronger_evidence),
          llm_audit_enable_broader_hypotheses: Boolean(saved.llm_audit_enable_broader_hypotheses),
          llm_audit_focus_areas: savedFocus,
          score_weight_critical: saved.score_weight_critical ?? prev.score_weight_critical,
          score_weight_high: saved.score_weight_high ?? prev.score_weight_high,
          score_weight_medium: saved.score_weight_medium ?? prev.score_weight_medium,
          score_weight_low: saved.score_weight_low ?? prev.score_weight_low,
          score_weight_info: saved.score_weight_info ?? prev.score_weight_info,
          score_weight_unknown: saved.score_weight_unknown ?? prev.score_weight_unknown,
          score_exclude_ai_fp: saved.score_exclude_ai_fp ?? prev.score_exclude_ai_fp,
        }));
        setFeishuConfigured(Boolean(form.feishu_webhook_url.trim()));
        if (form.gitlab_access_token.trim()) {
          setGitlabTokenConfigured(true);
          setForm((prev) => ({ ...prev, gitlab_access_token: "" }));
        }
        if (form.webhook_token.trim()) {
          setWebhookTokenConfigured(true);
          setForm((prev) => ({ ...prev, webhook_token: "" }));
        }
        if (form.mysql_password.trim()) {
          setMysqlPasswordConfigured(true);
          setForm((prev) => ({ ...prev, mysql_password: "" }));
        }
      } else {
        setForm((prev) => ({
          ...prev,
          score_weight_critical: saved.score_weight_critical ?? prev.score_weight_critical,
          score_weight_high: saved.score_weight_high ?? prev.score_weight_high,
          score_weight_medium: saved.score_weight_medium ?? prev.score_weight_medium,
          score_weight_low: saved.score_weight_low ?? prev.score_weight_low,
          score_weight_info: saved.score_weight_info ?? prev.score_weight_info,
          score_weight_unknown: saved.score_weight_unknown ?? prev.score_weight_unknown,
          score_exclude_ai_fp: saved.score_exclude_ai_fp ?? prev.score_exclude_ai_fp,
        }));
      }
      const feishuHint =
        !scoreOnly && form.feishu_webhook_url.trim()
          ? "（飞书 Webhook 已保存，可点「发送测试通知」验证）"
          : "";
      const dbHint = saved.database_switched
        ? " 数据库已切换并立即生效（旧库数据不会自动迁移）。"
        : "";
      const scoreHint =
        saved.scores_recalculated != null
          ? ` 已按新规则重算 ${saved.scores_recalculated} 个扫描分数。`
          : "";
      setMessage(`保存成功${feishuHint}${dbHint}${scoreHint}`);
      onSaved?.();
      if (scoreOnly || saved.scores_recalculated != null) {
        onClose();
      } else {
        setTimeout(onClose, saved.database_switched ? 1600 : 800);
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        setMessage("无权限保存系统设置（需要管理员角色）");
        onClose();
      } else {
        setMessage(String(e));
      }
    } finally {
      setSaving(false);
    }
  };

  const renderContent = (section: SettingsSection = active) => {
    switch (section) {
      case "sast-scanners":
        return (
          <div className="space-y-2">
            {scannersLoading && (
              <p className="text-sm text-slate-400 p-3 rounded-lg border border-surface-border bg-black/20">
                扫描工具列表加载中...
              </p>
            )}
            {!scannersLoading && scanners.length === 0 && (
              <p className="text-sm text-warning p-3 rounded-lg border border-warning/30 bg-warning/10">
                扫描工具列表加载失败：{scannersLoadError || "请刷新页面或重启服务后重试。"}
              </p>
            )}
            {scanners.map((s) => (
              <label
                key={s.id}
                className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                  form.enabled_scanners.includes(s.id)
                    ? "border-accent/50 bg-accent/10"
                    : "border-surface-border hover:border-surface-border/80"
                } ${!s.available ? "opacity-70" : ""}`}
              >
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={form.enabled_scanners.includes(s.id)}
                  onChange={() => toggleScanner(s.id)}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-sm">{s.name}</span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-surface text-slate-400">
                      {CATEGORY_LABELS[s.category] || s.category}
                    </span>
                    {s.supported_languages?.length > 0 && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300">
                        {s.supported_languages.join(", ")}
                      </span>
                    )}
                    {s.requires_build && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-white/5 text-slate-200">
                        requires build
                      </span>
                    )}
                    {s.available ? (
                      <span className="text-xs text-success">已安装</span>
                    ) : (
                      <span className="text-xs text-warning">未安装</span>
                    )}
                    {!s.available && form.enabled_scanners.includes(s.id) && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-warning/15 text-warning border border-warning/30">
                        已启用但未安装 · 该扫描器不会正常运行
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">{s.description}</p>
                  {s.setup_hint && <p className="text-xs text-slate-500 mt-1">{s.setup_hint}</p>}
                  {s.availability_reason && (
                    <p className="text-xs text-warning mt-1">{s.availability_reason}</p>
                  )}
                  {(!s.available || s.availability_reason) && s.install_hint && (
                    <p className="text-xs text-slate-600 mt-1 font-mono">{s.install_hint}</p>
                  )}
                </div>
              </label>
            ))}
            <label
              className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                form.exclude_test_paths
                  ? "border-accent/50 bg-accent/10"
                  : "border-surface-border hover:border-surface-border/80"
              }`}
            >
              <input
                type="checkbox"
                className="mt-1"
                checked={form.exclude_test_paths}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, exclude_test_paths: e.target.checked }))
                }
              />
              <div className="flex-1 min-w-0">
                <span className="font-medium text-sm">排除测试代码路径</span>
                <p className="text-xs text-slate-500 mt-0.5">
                  过滤 test/tests/src/test 及常见 *.test.* / *Test.java 等路径；仅影响新扫描，不删除历史发现。
                </p>
              </div>
            </label>
          </div>
        );

      case "sast-semgrep":
        return (
          <div className="space-y-4">
            <p className="text-xs text-slate-500">
              填写 <code className="text-slate-400">auto</code> 时会叠加{" "}
              <code className="text-slate-400">p/security-audit</code>、{" "}
              <code className="text-slate-400">p/owasp-top-ten</code> 及主语言规则包。
              不会调用 Semgrep 云端 auto（需开启 metrics，内网/关闭上报时会失败）。
            </p>
            <label className="text-sm text-slate-400 block">
              规则集
              <input
                className="input mt-1"
                value={form.semgrep_config}
                onChange={(e) => setForm({ ...form, semgrep_config: e.target.value })}
                placeholder="auto / p/security-audit / p/java"
              />
            </label>
            <label className="text-sm text-slate-400 block">
              扫描超时（秒）
              <input
                className="input mt-1"
                type="number"
                min={60}
                value={form.semgrep_timeout}
                onChange={(e) => setForm({ ...form, semgrep_timeout: Number(e.target.value || 1800) })}
              />
            </label>
          </div>
        );

      case "sast-codeql":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              CodeQL 适合 Java 深度数据流分析，需本机安装 CodeQL CLI、JDK 及 Maven/Gradle。
              autobuild/manual 建库失败时会自动降级为 none（无编译），尽量产出结果并标注精度下降。
            </p>
            <label className="text-sm text-slate-400 block">
              Query Suite
              <input
                className="input mt-1 font-mono text-xs"
                value={form.codeql_query_suite}
                onChange={(e) => setForm({ ...form, codeql_query_suite: e.target.value })}
                placeholder="codeql/java-queries:codeql-suites/java-security-and-quality.qls"
              />
            </label>
            <label className="text-sm text-slate-400 block">
              Build Mode
              <select
                className="input mt-1"
                value={form.codeql_build_mode}
                onChange={(e) => setForm({ ...form, codeql_build_mode: e.target.value })}
              >
                <option value="autobuild">autobuild（推荐，失败自动降级 none）</option>
                <option value="manual">manual</option>
                <option value="none">none（无编译）</option>
              </select>
            </label>
            <label className="text-sm text-slate-400 block">
              Java Build Command（manual 模式）
              <input
                className="input mt-1 font-mono text-xs"
                value={form.codeql_java_build_command}
                onChange={(e) => setForm({ ...form, codeql_java_build_command: e.target.value })}
                placeholder="mvn -DskipTests compile"
              />
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="text-sm text-slate-400 block">
                建库超时（秒）
                <input
                  className="input mt-1"
                  type="number"
                  min={60}
                  value={form.codeql_db_timeout}
                  onChange={(e) => setForm({ ...form, codeql_db_timeout: Number(e.target.value || 0) })}
                />
              </label>
              <label className="text-sm text-slate-400 block">
                分析超时（秒）
                <input
                  className="input mt-1"
                  type="number"
                  min={60}
                  value={form.codeql_timeout}
                  onChange={(e) => setForm({ ...form, codeql_timeout: Number(e.target.value || 0) })}
                />
              </label>
            </div>
          </div>
        );

      case "llm-api":
        return (
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              通过 OpenAI 兼容 API 调用大模型（DeepSeek、OpenAI、通义等）。
            </p>
            <input
              className="input"
              value={form.llm_api_base}
              onChange={(e) => setForm({ ...form, llm_api_base: e.target.value })}
              placeholder="https://api.deepseek.com 或 https://api.openai.com/v1"
            />
            <input
              className="input font-mono"
              type="password"
              value={form.llm_api_key}
              onChange={(e) => setForm({ ...form, llm_api_key: e.target.value })}
              placeholder="API Key（留空则不修改）"
            />
            <label className="text-sm text-slate-400 block">
              API 超时（秒）
              <input
                className="input mt-1"
                type="number"
                min={30}
                value={form.llm_timeout}
                onChange={(e) => setForm({ ...form, llm_timeout: Number(e.target.value || 60) })}
              />
            </label>
            <div className="flex items-center gap-2 flex-wrap pt-1">
              <button
                type="button"
                className="btn-ghost border border-surface-border"
                onClick={testLlm}
                disabled={testingLlm}
              >
                {testingLlm ? "测试中..." : "测试 LLM 连接"}
              </button>
              {llmTestResult && (
                <span className={`text-xs ${llmTestResult.ok ? "text-success" : "text-danger"}`}>
                  {llmTestResult.message}
                  {llmTestResult.latency_ms != null && ` (${llmTestResult.latency_ms}ms)`}
                </span>
              )}
            </div>
          </div>
        );

      case "llm-models":
        return (
          <div className="space-y-3">
            <label className="text-sm text-slate-400 block">
              默认模型
              <span className="text-slate-600 ml-1">（翻译、PoC、连接测试等）</span>
              <input
                className="input mt-1 font-mono text-xs"
                value={form.llm_model}
                onChange={(e) => setForm({ ...form, llm_model: e.target.value })}
                placeholder="gpt-4o-mini"
              />
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <label className="text-sm text-slate-400 block">
                误报审计模型
                <input
                  className="input mt-1 font-mono text-xs"
                  value={form.llm_model_fp}
                  onChange={(e) => setForm({ ...form, llm_model_fp: e.target.value })}
                  placeholder="留空=默认"
                />
              </label>
              <label className="text-sm text-slate-400 block">
                端点深度审计模型
                <input
                  className="input mt-1 font-mono text-xs"
                  value={form.llm_model_deep}
                  onChange={(e) => setForm({ ...form, llm_model_deep: e.target.value })}
                  placeholder="留空=默认"
                />
              </label>
              <label className="text-sm text-slate-400 block">
                Agent 对话模型
                <input
                  className="input mt-1 font-mono text-xs"
                  value={form.llm_model_agent}
                  onChange={(e) => setForm({ ...form, llm_model_agent: e.target.value })}
                  placeholder="留空=默认"
                />
              </label>
            </div>
          </div>
        );

      case "llm-auto":
        return (
          <div className="space-y-4">
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.llm_enabled}
                onChange={(e) => setForm({ ...form, llm_enabled: e.target.checked })}
              />
              <span>
                扫描完成后自动进行 <strong className="font-normal text-slate-300">SAST 误报审计</strong>
              </span>
            </label>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.llm_code_audit_enabled}
                onChange={(e) => setForm({ ...form, llm_code_audit_enabled: e.target.checked })}
              />
              <span>
                扫描完成后自动进行 <strong className="font-normal text-slate-300">LLM 端点审计</strong>
                （含 Jenkins / webhook 触发的任务）
                <span className="mt-1 block text-xs text-slate-500">
                  需已配置 LLM API Key。耗时较长，适合夜间或主干；不建议每条 MR 默认打开。工具栏按钮仍可手动补跑。
                </span>
              </span>
            </label>
          </div>
        );

      case "audit-skills":
        return <AuditSkillManager />;

      case "audit-strategy":
        return (
          <div className="space-y-4">
            <p className="text-xs text-slate-500">
              控制 LLM 审计风格：稳定性优先更容易复现结果，扩展性优先覆盖更多模块但结果波动更大。
            </p>
            <label className="text-sm text-slate-400 block">
              审计档位
              <select
                className="input mt-1"
                value={form.llm_audit_profile}
                onChange={(e) => applyAuditProfilePreset(e.target.value as "stable" | "balanced" | "broad")}
              >
                <option value="stable">稳定性优先（结果更易复现）</option>
                <option value="balanced">平衡模式（默认推荐）</option>
                <option value="broad">扩展性优先（覆盖更多模块）</option>
              </select>
              <span className="text-xs text-slate-600 mt-1 block">
                切换档位会自动填充推荐参数（域数/轮次/追认轮次等），你仍可在后续页签手动微调。
              </span>
            </label>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.llm_audit_require_stronger_evidence}
                onChange={(e) =>
                  setForm({ ...form, llm_audit_require_stronger_evidence: e.target.checked })
                }
              />
              <span>
                要求更强证据才入库（缺少关键证据时优先 candidate/uncertain）
              </span>
            </label>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.llm_audit_enable_broader_hypotheses}
                onChange={(e) =>
                  setForm({ ...form, llm_audit_enable_broader_hypotheses: e.target.checked })
                }
              />
              <span>
                启用更广假设探索（补盲更多模块，适合找漏报）
              </span>
            </label>

            <div className="space-y-2 pt-2 border-t border-surface-border/60">
              <div>
                <p className="text-sm text-slate-300">审计关注重点</p>
                <p className="text-xs text-slate-500 mt-0.5">
                  勾选项会提高调查优先级与预检索预算；可不选（完全由模型自主）。未勾选方向若证据极强仍可能报告。
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {LLM_AUDIT_FOCUS_OPTIONS.map((opt) => {
                  const checked = form.llm_audit_focus_areas.includes(opt.id);
                  return (
                    <label
                      key={opt.id}
                      className={`flex items-start gap-2 text-sm rounded-lg border px-3 py-2 cursor-pointer transition-colors ${
                        checked
                          ? "border-cyan-500/40 bg-cyan-500/10"
                          : "border-surface-border/70 bg-black/20 hover:border-slate-500/50"
                      }`}
                    >
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={checked}
                        onChange={() => {
                          setForm((prev) => {
                            const next = new Set(prev.llm_audit_focus_areas);
                            if (next.has(opt.id)) next.delete(opt.id);
                            else next.add(opt.id);
                            return {
                              ...prev,
                              llm_audit_focus_areas: LLM_AUDIT_FOCUS_OPTIONS.map((o) => o.id).filter((id) =>
                                next.has(id)
                              ),
                            };
                          });
                        }}
                      />
                      <span>
                        <span className="text-slate-200">{opt.label}</span>
                        <span className="block text-xs text-slate-500 mt-0.5">{opt.hint}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          </div>
        );

      case "audit-endpoint":
        return (
          <div className="space-y-4">
            <p className="text-xs text-slate-500">
              超大项目：先用轻量 Origin 做业务理解，再按风险选出 Top-N 业务域分批 Goal 验证。验证阶段由 LLM 自主 finish；下方为安全上限与分域参数。
            </p>
            <label className="text-sm text-slate-400 block">
              验证阶段安全上限（轮次，跨域合计）
              <input
                className="input mt-1"
                type="number"
                min={5}
                max={80}
                value={form.llm_endpoint_audit_max_iterations}
                onChange={(e) =>
                  setForm({
                    ...form,
                    llm_endpoint_audit_max_iterations: Number(e.target.value || 30),
                  })
                }
              />
              <span className="text-xs text-slate-600 mt-1 block">
                非固定轮次。会按选中业务域均分；LLM 验证充分后会 action=finish 提前结束。建议 20–40。
              </span>
            </label>
            <label className="text-sm text-slate-400 block">
              分批审计业务域上限（Top-N）
              <input
                className="input mt-1"
                type="number"
                min={1}
                max={10}
                value={form.llm_endpoint_audit_max_domains}
                onChange={(e) =>
                  setForm({
                    ...form,
                    llm_endpoint_audit_max_domains: Number(e.target.value || 3),
                  })
                }
              />
              <span className="text-xs text-slate-600 mt-1 block">
                Understand 后按敏感度与调查优先级选出域；默认 3。增大可覆盖更多域但耗时更长。
              </span>
            </label>
            <label className="text-sm text-slate-400 block">
              每域 Controller 切片上限
              <input
                className="input mt-1"
                type="number"
                min={1}
                max={200}
                value={form.llm_endpoint_audit_max_controllers}
                onChange={(e) =>
                  setForm({
                    ...form,
                    llm_endpoint_audit_max_controllers: Number(e.target.value || 40),
                  })
                }
              />
              <span className="text-xs text-slate-600 mt-1 block">
                仅限制单个业务域 Goal 时注入的 Controller 数量（非全仓）。大型项目可调高。
              </span>
            </label>
            <label className="text-sm text-slate-400 block">
              Origin 每域样例端点数
              <input
                className="input mt-1"
                type="number"
                min={1}
                max={20}
                value={form.llm_endpoint_origin_sample_per_domain}
                onChange={(e) =>
                  setForm({
                    ...form,
                    llm_endpoint_origin_sample_per_domain: Number(e.target.value || 5),
                  })
                }
              />
              <span className="text-xs text-slate-600 mt-1 block">
                业务理解阶段每个域附带的样例端点数量（默认 3–5）。
              </span>
            </label>
            <label className="text-sm text-slate-400 block">
              每个 Controller 附带 Service 文件数
              <input
                className="input mt-1"
                type="number"
                min={0}
                max={20}
                value={form.llm_endpoint_max_related_files}
                onChange={(e) =>
                  setForm({
                    ...form,
                    llm_endpoint_max_related_files: Number(e.target.value || 4),
                  })
                }
              />
            </label>
          </div>
        );

      case "audit-advanced":
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="text-sm text-slate-400 block">
                单文件最大字符数
                <input
                  className="input mt-1"
                  type="number"
                  min={1000}
                  value={form.llm_audit_file_max_chars}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      llm_audit_file_max_chars: Number(e.target.value || 6000),
                    })
                  }
                />
              </label>
              <label className="text-sm text-slate-400 block">
                LLM 最大输出 Token
                <input
                  className="input mt-1"
                  type="number"
                  min={1024}
                  value={form.llm_audit_max_tokens}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      llm_audit_max_tokens: Number(e.target.value || 8192),
                    })
                  }
                />
              </label>
            </div>
            <label className="text-sm text-slate-400 block">
              文件抽检上限（遗留模式，端点审计为主）
              <input
                className="input mt-1"
                type="number"
                min={1}
                value={form.llm_audit_max_files}
                onChange={(e) =>
                  setForm({
                    ...form,
                    llm_audit_max_files: Number(e.target.value || 25),
                  })
                }
              />
            </label>
          </div>
        );

      case "database":
        return (
          <div className="space-y-4">
            <div className="text-sm p-3 rounded-lg border border-surface-border bg-black/20 text-slate-300">
              本地开发建议使用 SQLite 或独立库 <code className="text-slate-400">ai_audit_dev</code>；
              生产使用 MySQL 库 <code className="text-slate-400">ai_audit_prod</code>。保存后会立即切换连接，无需重启。
              Schema 变更见仓库 <code className="text-slate-400">migrations/</code>。旧库中的项目与扫描不会自动迁入新库。
            </div>
            <label className="text-sm text-slate-400 block">
              存储后端
              <select
                className="input mt-1"
                value={form.database_backend}
                onChange={(e) =>
                  setForm({
                    ...form,
                    database_backend: e.target.value as "sqlite" | "mysql",
                  })
                }
              >
                <option value="sqlite">SQLite（本地默认）</option>
                <option value="mysql">MySQL（生产推荐）</option>
              </select>
            </label>
            {form.database_backend === "mysql" ? (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <label className="text-sm text-slate-400 block">
                    主机
                    <input
                      className="input mt-1"
                      value={form.mysql_host}
                      onChange={(e) => setForm({ ...form, mysql_host: e.target.value })}
                    />
                  </label>
                  <label className="text-sm text-slate-400 block">
                    端口
                    <input
                      className="input mt-1"
                      type="number"
                      value={form.mysql_port}
                      onChange={(e) => setForm({ ...form, mysql_port: Number(e.target.value) || 3306 })}
                    />
                  </label>
                  <label className="text-sm text-slate-400 block">
                    用户名
                    <input
                      className="input mt-1"
                      value={form.mysql_user}
                      onChange={(e) => setForm({ ...form, mysql_user: e.target.value })}
                    />
                  </label>
                  <label className="text-sm text-slate-400 block">
                    数据库名
                    <input
                      className="input mt-1"
                      value={form.mysql_database}
                      onChange={(e) => setForm({ ...form, mysql_database: e.target.value })}
                      placeholder="ai_audit_dev / ai_audit_prod"
                    />
                  </label>
                  <label className="text-sm text-slate-400 block">
                    连接字符集
                    <select
                      className="input mt-1"
                      value={form.mysql_charset}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          mysql_charset: e.target.value as "utf8mb4" | "utf8",
                        })
                      }
                    >
                      <option value="utf8mb4">utf8mb4（推荐，支持 emoji）</option>
                      <option value="utf8">utf8（兼容旧库）</option>
                    </select>
                    <p className="text-[11px] text-slate-500 mt-1">
                      这是客户端连接字符集，改不了库本身。库仍是 utf8 时选 utf8 更稳妥；选 utf8mb4 也不能让旧库存 emoji。
                    </p>
                  </label>
                </div>
                <label className="text-sm text-slate-400 block">
                  密码{mysqlPasswordConfigured ? "（留空则保持已保存的密码）" : ""}
                  <input
                    className="input mt-1 font-mono"
                    type="password"
                    value={form.mysql_password}
                    onChange={(e) => setForm({ ...form, mysql_password: e.target.value })}
                    placeholder={mysqlPasswordConfigured ? "••••••••（已配置）" : ""}
                  />
                </label>
              </>
            ) : (
              <p className="text-xs text-slate-500">
                SQLite 文件位于 backend 数据目录下的 <code className="text-slate-400">audit.db</code>（由 DATA_DIR 决定）。
              </p>
            )}
            <label className="text-sm text-slate-400 block">
              完整连接 URL（可选，优先级高于上方分项）
              <input
                className="input mt-1 font-mono text-xs"
                value={form.database_url}
                onChange={(e) => setForm({ ...form, database_url: e.target.value })}
                placeholder="mysql+asyncmy://user:pass@host:3306/db"
              />
            </label>
            <div className="flex items-center gap-3">
              <button type="button" className="btn-ghost" disabled={testingDatabase} onClick={testDatabase}>
                {testingDatabase ? "测试中..." : "测试连接"}
              </button>
              {databaseTestResult && (
                <span className={`text-xs ${databaseTestResult.ok ? "text-success" : "text-warning"}`}>
                  {databaseTestResult.message}
                </span>
              )}
            </div>
          </div>
        );

      case "auth-token":
        return (
          <div className="space-y-4">
            <div className="text-sm p-3 rounded-lg border border-surface-border bg-black/20 text-slate-300">
              控制用户登录后的会话有效期。Access Token 到期后前端会自动静默续期，
              直到 Refresh Token 过期才需要重新登录。修改后立即生效，无需重启服务。
            </div>
            <label className="text-sm text-slate-400 block">
              Access Token 有效期（小时）
              <input
                className="input mt-1"
                type="number"
                min={0.5}
                max={168}
                step={0.5}
                value={form.auth_token_expire_hours}
                onChange={(e) =>
                  setForm({ ...form, auth_token_expire_hours: Number(e.target.value || 12) })
                }
              />
              <p className="text-[11px] text-slate-500 mt-1">
                默认 12 小时。到期后自动静默刷新，用户无感知。范围 0.5 ~ 168 小时。
              </p>
            </label>
            <label className="text-sm text-slate-400 block">
              Refresh Token 有效期（天）
              <input
                className="input mt-1"
                type="number"
                min={1}
                max={365}
                value={form.auth_refresh_token_expire_days}
                onChange={(e) =>
                  setForm({ ...form, auth_refresh_token_expire_days: Number(e.target.value || 7) })
                }
              />
              <p className="text-[11px] text-slate-500 mt-1">
                默认 7 天。过期后用户需重新通过 SSO 或密码登录。范围 1 ~ 365 天。
              </p>
            </label>
          </div>
        );

      case "score-rules":
        return (
          <div className="space-y-4">
            <div className="text-sm p-3 rounded-lg border border-surface-border bg-black/20 text-slate-300 space-y-1">
              <p>
                安全分 = <span className="font-mono text-cyan-300">max(0, 100 − Σ(数量 × 权重))</span>
              </p>
              <p className="text-xs text-slate-500">
                仅提供分数与明细；发版门禁（阈值、时效、是否阻断）由各团队 CI/发版流程自行判断。
                修改权重后，查询分数接口会按新规则即时重算。
              </p>
            </div>
            {(
              [
                ["score_weight_critical", "Critical 每条扣分", 25],
                ["score_weight_high", "High 每条扣分", 10],
                ["score_weight_medium", "Medium 每条扣分", 3],
                ["score_weight_low", "Low 每条扣分", 1],
                ["score_weight_info", "Info 每条扣分", 0],
                ["score_weight_unknown", "Unknown 每条扣分", 0],
              ] as const
            ).map(([key, label, fallback]) => (
              <label key={key} className="text-sm text-slate-400 block">
                {label}
                <input
                  className="input mt-1"
                  type="number"
                  min={0}
                  max={100}
                  value={form[key]}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      [key]: Math.max(0, Math.min(100, Number(e.target.value || fallback))),
                    })
                  }
                />
              </label>
            ))}
            <label
              className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                form.score_exclude_ai_fp
                  ? "border-accent/50 bg-accent/10"
                  : "border-surface-border hover:border-surface-border/80"
              }`}
            >
              <input
                type="checkbox"
                className="mt-1"
                checked={form.score_exclude_ai_fp}
                onChange={(e) =>
                  setForm((prev) => ({ ...prev, score_exclude_ai_fp: e.target.checked }))
                }
              />
              <div className="flex-1 min-w-0">
                <span className="font-medium text-sm">排除 AI 误报</span>
                <p className="text-xs text-slate-500 mt-0.5">
                  开启后，AI 判定为 false_positive 的发现不计入扣分；人工误报始终排除。
                </p>
              </div>
            </label>
          </div>
        );

      case "gitlab":
        return (
          <div className="space-y-4">
            <div
              className={`text-sm p-3 rounded-lg border ${
                gitlabTokenConfigured
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-warning/40 bg-warning/10 text-warning"
              }`}
            >
              {gitlabTokenConfigured
                ? "GitLab Token 已配置。新建扫描时可留空 Token，将使用此处默认值。"
                : "尚未配置 GitLab Token。保存后，新建 GitLab 扫描可直接使用，无需每次填写。"}
            </div>
            <p className="text-xs text-slate-500">
              Token 需要 <code className="text-slate-400">read_repository</code> 权限。仅保存在本机{" "}
              <code className="text-slate-400">.env</code>（仓库根目录），不会随代码提交。
            </p>
            <label className="text-sm text-slate-400 block">
              默认 GitLab 地址
              <input
                className="input mt-1"
                value={form.gitlab_default_url}
                onChange={(e) => setForm({ ...form, gitlab_default_url: e.target.value })}
                placeholder="https://gitlab.example.com"
              />
            </label>
            <label className="text-sm text-slate-400 block">
              Access Token{gitlabTokenConfigured ? "（留空则保持已保存的 Token）" : ""}
              <input
                className="input mt-1 font-mono"
                type="password"
                value={form.gitlab_access_token}
                onChange={(e) => setForm({ ...form, gitlab_access_token: e.target.value })}
                placeholder={gitlabTokenConfigured ? "••••••••（已配置）" : "粘贴 GitLab Access Token"}
              />
            </label>
            <label className="text-sm text-slate-400 block">
              默认分支
              <input
                className="input mt-1"
                value={form.gitlab_default_branch}
                onChange={(e) => setForm({ ...form, gitlab_default_branch: e.target.value })}
                placeholder="main"
              />
            </label>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.gitlab_tls_verify}
                onChange={(e) => setForm({ ...form, gitlab_tls_verify: e.target.checked })}
              />
              <span>校验证书（TLS Verify）。内网自签证书可关闭。</span>
            </label>
            <label className="text-sm text-slate-400 block">
              测试仓库 URL
              <input
                className="input mt-1"
                value={form.gitlab_test_project_url}
                onChange={(e) => setForm({ ...form, gitlab_test_project_url: e.target.value })}
                placeholder="https://gitlab.example.com/group/project.git"
              />
            </label>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="btn-ghost"
                disabled={testingGitlab || !form.gitlab_test_project_url.trim()}
                onClick={testGitlab}
              >
                {testingGitlab ? "测试中..." : "测试 GitLab 连通性"}
              </button>
              {gitlabTestResult && (
                <span className={`text-xs ${gitlabTestResult.ok ? "text-success" : "text-warning"}`}>
                  {gitlabTestResult.message}
                </span>
              )}
            </div>
            <div className="border-t border-surface-border pt-4 space-y-3">
              <div
                className={`text-sm p-3 rounded-lg border ${
                  webhookTokenConfigured
                    ? "border-success/40 bg-success/10 text-success"
                    : "border-warning/40 bg-warning/10 text-warning"
                }`}
              >
                {webhookTokenConfigured
                  ? "Jenkins / CI Webhook Token 已配置。可用 POST /api/webhooks/scan 触发扫描。"
                  : "尚未配置 Webhook Token。Jenkins 调用前请先保存一串随机密钥。"}
              </div>
              <p className="text-xs text-slate-500">
                请求头使用 <code className="text-slate-400">X-Webhook-Token</code>。按{" "}
                <code className="text-slate-400">project_url</code> 自动匹配或创建项目，无需预先登记每个仓库。
              </p>
              <label className="text-sm text-slate-400 block">
                Webhook Token{webhookTokenConfigured ? "（留空则保持已保存的 Token）" : ""}
                <input
                  className="input mt-1 font-mono"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  value={form.webhook_token}
                  onChange={(e) => setForm({ ...form, webhook_token: e.target.value })}
                  placeholder={webhookTokenConfigured ? "••••••••（已配置）" : "点「随机生成」或自行填写"}
                />
              </label>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="btn-ghost border border-surface-border text-sm"
                  onClick={() => {
                    const token = generateWebhookToken();
                    setForm({ ...form, webhook_token: token });
                    setMessage("已生成新 Token，请复制到 Jenkins 后点「保存」。未保存前旧 Token 仍有效。");
                  }}
                >
                  随机生成
                </button>
                <button
                  type="button"
                  className="btn-ghost border border-surface-border text-sm"
                  disabled={!form.webhook_token.trim()}
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(form.webhook_token.trim());
                      setMessage("已复制 Token，请粘贴到 Jenkins Credentials。");
                    } catch {
                      setMessage("复制失败，请手动选中输入框中的 Token。");
                    }
                  }}
                >
                  复制
                </button>
              </div>
              <p className="text-xs text-slate-500">
                Token 由本系统生成，不是 Jenkins 下发。生成后须点「保存」，并把同一串配进 Jenkins 的{" "}
                <code className="text-slate-400">X-Webhook-Token</code>。
              </p>
            </div>
          </div>
        );

      case "notify-email":
        return (
          <div className="space-y-4">
            <div
              className={`text-sm p-3 rounded-lg border ${
                smtpPasswordConfigured && form.smtp_host.trim() && form.email_from.trim()
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-warning/40 bg-warning/10 text-warning"
              }`}
            >
              {smtpPasswordConfigured && form.smtp_host.trim() && form.email_from.trim()
                ? "SMTP 已配置。扫描完成且填写收件人时将发送 HTML 漏洞汇总报告。"
                : "SMTP 未完整配置。请填写服务器、发件地址与密码后保存。"}
            </div>
            <p className="text-xs text-slate-500">
              扫描完成时向 Webhook / 新建扫描中填写的邮箱发送 HTML 报告。多收件人请用逗号分隔。
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="text-sm text-slate-400 block">
                SMTP 主机
                <input
                  className="input mt-1"
                  value={form.smtp_host}
                  onChange={(e) => setForm({ ...form, smtp_host: e.target.value })}
                  placeholder="smtp.example.com"
                />
              </label>
              <label className="text-sm text-slate-400 block">
                端口
                <input
                  className="input mt-1"
                  type="number"
                  value={form.smtp_port}
                  onChange={(e) =>
                    setForm({ ...form, smtp_port: Number(e.target.value) || 465 })
                  }
                />
              </label>
            </div>
            <label className="text-sm text-slate-400 block">
              用户名
              <input
                className="input mt-1"
                value={form.smtp_user}
                onChange={(e) => setForm({ ...form, smtp_user: e.target.value })}
                placeholder="可选"
              />
            </label>
            <label className="text-sm text-slate-400 block">
              密码{smtpPasswordConfigured ? "（留空则保持已保存的密码）" : ""}
              <input
                className="input mt-1 font-mono"
                type="password"
                value={form.smtp_password}
                onChange={(e) => setForm({ ...form, smtp_password: e.target.value })}
                placeholder={smtpPasswordConfigured ? "••••••••（已配置）" : ""}
              />
            </label>
            <label className="text-sm text-slate-400 block">
              发件地址 (From)
              <input
                className="input mt-1"
                value={form.email_from}
                onChange={(e) => setForm({ ...form, email_from: e.target.value })}
                placeholder="audit@example.com"
              />
            </label>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.smtp_tls}
                onChange={(e) => setForm({ ...form, smtp_tls: e.target.checked })}
              />
              <span>
                启用 TLS（465 端口：SSL；587 端口：STARTTLS，建议勾选）
              </span>
            </label>
            <p className="text-xs text-slate-600">
              常见配置：465 + 勾选 TLS；或 587 + 勾选 TLS。
              QQ 邮箱须在设置里开启 SMTP 并使用<strong className="text-slate-400">授权码</strong>（非 QQ 登录密码）。
            </p>
            <label className="text-sm text-slate-400 block">
              测试收件人
              <input
                className="input mt-1"
                value={form.smtp_test_to}
                onChange={(e) => setForm({ ...form, smtp_test_to: e.target.value })}
                placeholder="your@email.com"
              />
            </label>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="btn-ghost"
                disabled={testingEmail || !form.smtp_test_to.trim()}
                onClick={testEmail}
              >
                {testingEmail ? "发送中..." : "发送测试邮件"}
              </button>
              {emailTestResult && (
                <span className={`text-xs ${emailTestResult.ok ? "text-success" : "text-warning"}`}>
                  {emailTestResult.message}
                </span>
              )}
            </div>
          </div>
        );

      case "notify-feishu":
        return (
          <div className="space-y-4">
            <div
              className={`text-sm p-3 rounded-lg border ${
                feishuConfigured
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-warning/40 bg-warning/10 text-warning"
              }`}
            >
              {feishuConfigured
                ? "飞书通知已配置。扫描开始/结束会推送汇总；确认/高危漏洞变更时也会单条推送（需 Webhook 有效）。"
                : "飞书通知未配置。填写 Webhook 后点「保存」或「发送测试通知」。"}
            </div>
            <p className="text-xs text-slate-500">
              使用飞书群机器人 Incoming Webhook。可先只配 Webhook，不填 @ 用户也能在群里收到消息。
              安全人员初审后，把详情链接转发给研发即可。
            </p>
            <label className="text-sm text-slate-400 block">
              Webhook URL
              <input
                className="input mt-1"
                value={form.feishu_webhook_url}
                onChange={(e) =>
                  setForm({
                    ...form,
                    feishu_webhook_url: e.target.value,
                  })
                }
                placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."
              />
            </label>
            <label className="text-sm text-slate-400 block">
              @ 用户（每行一个 user_id）
              <textarea
                className="input mt-1 min-h-[110px]"
                value={form.feishu_at_user_ids.join("\n")}
                onChange={(e) =>
                  setForm({
                    ...form,
                    feishu_at_user_ids: e.target.value
                      .split(/\r?\n/)
                      .map((s) => s.trim())
                      .filter(Boolean),
                  })
                }
                placeholder={"ou_xxx\nou_yyy"}
              />
              <span className="text-xs text-slate-600 mt-1 block">
                可选。不填也能发群消息；需要 @ 人时再填飞书 user_id（如 ou_xxx）。
              </span>
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="text-sm text-slate-400 block">
                最低通知严重级别
                <select
                  className="input mt-1"
                  value={form.feishu_notify_min_severity}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      feishu_notify_min_severity: e.target.value,
                    })
                  }
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </select>
              </label>
              <label className="text-sm text-slate-400 block">
                前端地址（用于漏洞详情链接）
                <input
                  className="input mt-1"
                  value={form.frontend_base_url}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      frontend_base_url: e.target.value,
                    })
                  }
                  placeholder="http://localhost:8787"
                />
              </label>
            </div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="btn-ghost"
                disabled={testingFeishu || !form.feishu_webhook_url.trim()}
                onClick={testFeishu}
              >
                {testingFeishu ? "发送测试中..." : "发送测试通知"}
              </button>
              {feishuTestResult && (
                <span className={`text-xs ${feishuTestResult.ok ? "text-success" : "text-warning"}`}>
                  {feishuTestResult.message}
                </span>
              )}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  // 弹窗模式必须 portal 到 body（见 FalsePositiveNoteModal 的说明），
  // 否则会被 `.card` / `.audit-panel` 的 backdrop-filter 劫持定位。
  // 页面模式（embedded）直接返回内容，由 AppShell 的 MainContent 提供唯一滚动容器。
  if (categoriesMode) {
    const category = SYSTEM_CATEGORIES.find((c) => c.id === activeCategory) ?? SYSTEM_CATEGORIES[0];
    const switchCategory = (id: string) => {
      if (id === activeCategory) return;
      if (dirty && !window.confirm("当前分类有未保存的修改，切换后会丢失。确定离开吗？")) return;
      setMessage("");
      setActiveCategory(id);
    };
    return (
      <div className="flex h-full min-h-0 w-full">
        <nav className="w-56 shrink-0 border-r border-surface-border px-3 py-5" aria-label="设置分类">
          <p className="px-3 pb-3 text-[10px] font-mono uppercase tracking-wider text-slate-500">
            Settings / 分类
          </p>
          <div className="space-y-0.5">
            {SYSTEM_CATEGORIES.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => switchCategory(c.id)}
                className={`settings-nav-item flex w-full items-center gap-2 rounded px-3 py-2 text-left text-sm transition-colors ${
                  activeCategory === c.id ? "settings-nav-item-active" : ""
                }`}
              >
                <span className="truncate">{c.label}</span>
                {dirty && activeCategory === c.id && (
                  <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" title="有未保存的修改" />
                )}
              </button>
            ))}
          </div>
          <p className="mt-5 px-3 text-[11px] leading-relaxed text-slate-500">
            模型连接与任务模型在「LLM 设置」，审计技能包在「Skill 管理」，本页不再重复提供入口。
          </p>
        </nav>

        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="app-main-scroll min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <div className="mx-auto max-w-4xl space-y-5">
              <div>
                <h2 className="text-base font-semibold">{category.label}</h2>
                <p className="mt-1 text-xs text-slate-500">{category.description}</p>
              </div>
              {!loaded && !loadFailed && <LoadingState label="正在加载系统设置…" />}
              {loadFailed && (
                <ErrorState
                  message={message || "系统设置加载失败"}
                  onRetry={() => {
                    setLoadFailed(false);
                    setMessage("");
                    setReloadTick((v) => v + 1);
                  }}
                />
              )}
              {loaded && category.sections.map((id) => (
                <section key={id} className="card p-5">
                  <h3 className="mb-4 text-sm font-medium text-slate-200">{SECTION_TITLES[id]}</h3>
                  {renderContent(id)}
                </section>
              ))}
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-3 border-t border-surface-border px-6 py-3">
            <span className="text-xs text-slate-500">
              {dirty ? "● 有未保存的修改" : "● 已与服务端同步"}
            </span>
            {message && <span className="truncate text-xs text-accent-glow">{message}</span>}
            <button
              type="button"
              className="btn-primary ml-auto"
              disabled={saving || !loaded || loadFailed}
              onClick={() => void save(activeCategory)}
            >
              {saving ? "保存中…" : `保存${category.label}`}
            </button>
          </div>
        </div>
      </div>
    );
  }

  const shellClass = embedded
    ? "card w-full flex-1 min-h-0 flex flex-col overflow-hidden"
    : "card w-full max-w-4xl shadow-2xl max-h-[90vh] flex flex-col overflow-hidden";
  const shell = (
      <div className={shellClass}>
        <div className="flex items-center gap-2 px-6 pt-6 pb-4 border-b border-surface-border shrink-0">
          <SettingsIcon className="w-5 h-5 text-accent" />
          <h2 className="text-lg font-semibold">{embedded ? title : "系统设置"}</h2>
          <span className="text-xs text-slate-500 ml-auto">UI Build: {buildId}</span>
        </div>

        <div className="flex flex-1 min-h-0 overflow-hidden">
          <nav className="settings-nav w-52 shrink-0 border-r border-surface-border overflow-y-auto p-3 space-y-4">
            {visibleGroups.map((group) => (
              <div key={group.id}>
                <p className="settings-nav-group px-2 mb-1.5">{group.label}</p>
                <div className="space-y-0.5">
                  {group.items.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={`settings-nav-item w-full text-left px-2 py-1.5 rounded text-sm transition-colors ${
                        active === item.id ? "settings-nav-item-active" : ""
                      }`}
                      onClick={() => setActive(item.id)}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </nav>

          <div className="flex-1 overflow-y-auto p-6">
            <h3 className="text-sm font-medium text-slate-200 mb-4">{SECTION_TITLES[active]}</h3>
            {renderContent()}
          </div>
        </div>

        {message && <p className="px-6 pb-2 text-sm text-accent-glow shrink-0">{message}</p>}

        <div className="flex justify-end gap-2 px-6 py-4 border-t border-surface-border shrink-0">
          {!embedded && (
            <button className="btn-ghost" onClick={onClose}>
              取消
            </button>
          )}
          <button className="btn-primary" onClick={() => void save()} disabled={saving}>
            {saving ? "保存中..." : "保存"}
          </button>
        </div>
      </div>
  );

  if (embedded) {
    return <div className="settings-embedded flex min-h-0 flex-1 flex-col">{shell}</div>;
  }
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      {shell}
    </div>,
    document.body,
  );
}
