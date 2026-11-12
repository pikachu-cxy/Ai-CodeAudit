export type ScanStatus = "pending" | "cloning" | "scanning" | "analyzing" | "llm_auditing" | "completed" | "failed";
export type ScanSource = "upload" | "gitlab" | "local";
export type ScanKind = "baseline" | "retest" | "ad_hoc";
export type RetestStrategy = "targeted" | "full";
export type RetestVerdict = "fixed" | "still_present" | "inconclusive" | "skipped";
export type RetestMethod = "pattern" | "semgrep_rule" | "dep_exploit" | "llm" | "manual";
export type DiffStatus = "fixed" | "regressed" | "new" | "unchanged";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
export type AiVerdict = "pending" | "real_vuln" | "false_positive" | "uncertain" | "skipped";
export type ReviewStatus = "unreviewed" | "confirmed" | "false_positive" | "fixed";
export type ExternalReviewStatus = "unreviewed" | "vuln_exists" | "false_positive" | "fixed_claimed";
export type FindingCategory = "sast" | "business_logic" | "authorization";

export interface DetectedLanguage {
  id: string;
  label: string;
  file_count: number;
  primary: boolean;
}

export interface ScanSummary {
  id: number;
  project_id: number | null;
  parent_scan_id: number | null;
  scan_kind: ScanKind;
  version_label: string | null;
  name: string;
  source: ScanSource;
  status: ScanStatus;
  source_url: string | null;
  branch: string | null;
  notify_emails?: string[] | null;
  progress: number;
  progress_message: string | null;
  total_findings: number;
  security_score?: number | null;
  semgrep_version: string | null;
  scanner_summary: string | null;
  scan_coverage?: ScanCoverage | null;
  detected_languages?: DetectedLanguage[];
  error_message: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string | null;
  completed_at: string | null;
  archived_at: string | null;
}

export interface ScannerCoverage {
  id: string;
  name: string;
  status: "ran" | "skipped" | "failed" | "not_run";
  findings: number;
  reason?: string | null;
  version?: string | null;
  detail?: Record<string, unknown> | null;
}

export interface CapabilityCoverage {
  id: string;
  label: string;
  status: "checked" | "not_checked" | "partial";
  sources: string[];
  note?: string | null;
  rule_count?: number | null;
}

export interface OwaspCategoryCoverage {
  id: string;
  label: string;
  status: "checked" | "not_checked" | "partial";
  sources: string[];
  note?: string | null;
  rule_count?: number | null;
}

export interface LlmFocusCoverage {
  id: string;
  label: string;
  status: "audited" | "configured" | "not_run" | "skipped";
  note?: string | null;
}

export interface LlmAuditCoverage {
  ran: boolean;
  status: "completed" | "cancelled" | "running" | "not_run";
  focus_areas: LlmFocusCoverage[];
}

export interface SemgrepRuleEvidence {
  source?: string | null;
  configs: string[];
  total_rules: number;
  by_subtype: Record<string, number>;
  by_owasp: Record<string, number>;
  sample_rules_by_subtype?: Record<string, string[]>;
  sample_rules_by_owasp?: Record<string, string[]>;
  inventory_error?: string | null;
  resolved_at?: string | null;
  project_languages?: string[];
  filtered?: boolean;
  unfiltered_total_rules?: number | null;
}

export interface ScanCoverage {
  scanners: ScannerCoverage[];
  capabilities: CapabilityCoverage[];
  semgrep_configs: string[];
  sast_checked: boolean;
  owasp_categories?: OwaspCategoryCoverage[];
  llm_audit?: LlmAuditCoverage | null;
  semgrep_rule_evidence?: SemgrepRuleEvidence | null;
}

export interface ProjectSummary {
  id: number;
  name: string;
  notes: string | null;
  source_type: ScanSource;
  source_url: string | null;
  default_branch: string | null;
  /** User-selected scan scope; null/empty = auto detect. */
  scan_languages?: string[] | null;
  /** Languages observed in the latest scan (read-only). */
  detected_languages?: DetectedLanguage[];
  archived_at: string | null;
  created_at: string;
  updated_at: string | null;
  scan_count: number;
  latest_scan: ScanSummary | null;
}

export interface ProjectDetail extends ProjectSummary {
  scans: ScanSummary[];
}

/**
 * 项目白名单 / 误报库条目。
 * status: "whitelist" = 手动加白；"false_positive" = 误报（LLM 或人工标记）。
 * 命中后该项目后续扫描不再上报对应漏洞。
 */
export interface ProjectWhitelistEntry {
  id: number;
  project_id: number;
  status: string;
  reason: string;
  rule_id: string | null;
  file_path: string | null;
  fingerprint_strict: string;
  fingerprint_relaxed: string | null;
  source_scan_id: number | null;
  source_finding_id: number | null;
  created_by: string | null;
  created_at: string | null;
  expires_at: string | null;
}

export interface ScanDiffFindingItem {
  fingerprint: string;
  status: DiffStatus;
  current: Finding | null;
  baseline: Finding | null;
}

export interface RetestVerificationItem {
  id: number;
  scan_id: number;
  baseline_scan_id: number;
  baseline_finding_id: number;
  verdict: RetestVerdict;
  method: RetestMethod;
  evidence_json: string | null;
  created_at: string;
  baseline_finding: Finding | null;
  current_finding_id: number | null;
}

export interface RetestResultsSummary {
  scan_id: number;
  baseline_scan_id: number;
  queue_size: number;
  fixed_count: number;
  still_present_count: number;
  inconclusive_count: number;
  skipped_count: number;
  message: string | null;
  items: RetestVerificationItem[];
}

export interface ScanDiffSummary {
  scan_id: number;
  baseline_scan_id: number;
  fixed_count: number;
  regressed_count: number;
  new_count: number;
  unchanged_count: number;
  status_changed_count: number;
  items: ScanDiffFindingItem[];
}

export interface ListScansParams {
  q?: string;
  status?: ScanStatus;
  archived?: "false" | "true" | "all";
}

export interface ListProjectsParams {
  q?: string;
  archived?: "false" | "true" | "all";
}

export interface Finding {
  id: number;
  scan_id: number;
  rule_id: string;
  check_id: string | null;
  severity: Severity;
  message: string;
  message_zh?: string | null;
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet: string | null;
  metadata_json?: string | null;
  tool: string;
  category: FindingCategory;
  ai_verdict: AiVerdict;
  ai_reason: string | null;
  ai_confidence: number | null;
  review_status?: ReviewStatus;
  review_note?: string | null;
  reviewed_at?: string | null;
  external_status?: ExternalReviewStatus;
  external_note?: string | null;
  external_updated_at?: string | null;
  external_updated_by?: string | null;
  external_review_token_active?: boolean;
  external_review_expires_at?: string | null;
  external_review_url?: string | null;
  owasp_id?: string | null;
  owasp_name?: string | null;
  vuln_subtype?: string | null;
  vuln_subtype_name?: string | null;
}

export interface FileContent {
  file_path: string;
  relative_path: string;
  content: string;
  line_start: number;
  line_end: number;
  total_lines: number;
  highlight_start: number;
  highlight_end: number;
}

export interface CodeLocation {
  file_path: string;
  line_start: number;
  line_end: number;
  matched_text?: string | null;
  confidence?: number | null;
  strategy?: string | null;
  language_matched?: boolean | null;
}

export interface PocHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  poc_content?: string | null;
}

export interface VerificationPoc {
  generated_at?: string;
  updated_at?: string;
  poc_type?: string;
  title?: string;
  prerequisites?: string;
  steps?: string;
  poc_content?: string;
  expected_result?: string;
  safety_note?: string;
  http_request?: Partial<PocHttpRequest> | null;
}

export interface PocGenerateResult {
  generated: boolean;
  cached: boolean;
  message: string;
  poc?: VerificationPoc | null;
}

export interface PocExecuteResult {
  ok: boolean;
  status_code?: number | null;
  elapsed_ms: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  final_url?: string | null;
  error?: string | null;
}

export interface FindingPage {
  total: number;
  limit: number;
  offset: number;
  items: Finding[];
}

export interface ScanStats {
  total: number;
  by_severity: Record<string, number>;
  by_verdict: Record<string, number>;
  by_tool: Record<string, number>;
  by_category: Record<string, number>;
  by_review?: Record<string, number>;
  by_owasp?: Record<string, number>;
  by_subtype?: Record<string, number>;
  by_owasp_subtype?: Record<string, Record<string, number>>;
  top_rules: { rule_id: string; count: number }[];
  security_score?: number | null;
}

export interface ReportFilters {
  severity?: string[];
  owasp?: string[];
  source?: string[];
  tool?: string[];
  category?: string[];
  ai_verdict?: string[];
  review_status?: string[];
  external_status?: string[];
  subtype?: string[];
  keyword?: string;
}

export interface ReportInclude {
  snippet: boolean;
  poc: boolean;
  ai_reason: boolean;
  false_positive: boolean;
  retest: boolean;
  remediation: boolean;
}

export type ReportGroupBy = "severity" | "owasp" | "file" | "tool" | "none";
export type ReportSort = "severity" | "file" | "owasp" | "id";
export type ReportFormat = "html" | "html-download" | "pdf" | "md" | "json";

export interface ReportSpec {
  title?: string;
  /** 显式勾选的漏洞 ID，优先级高于 filters */
  finding_ids?: number[];
  filters?: ReportFilters;
  include?: Partial<ReportInclude>;
  group_by?: ReportGroupBy;
  sort?: ReportSort;
}

export interface ReportPreview {
  scope: "all" | "selected" | "filtered";
  title: string;
  total: number;
  scan_total: number;
  pdf_max_findings: number;
  by_severity: Record<string, number>;
  by_owasp: Record<string, number>;
  by_source: Record<string, number>;
  by_tool: Record<string, number>;
}

export interface ScoreDeductionDetail {
  severity: string;
  count: number;
  weight: number;
  deduction: number;
}

export interface ScanScore {
  scan_id: number;
  project_id: number | null;
  score: number;
  max_score: number;
  by_severity: Record<string, number>;
  counted_findings: number;
  excluded_findings: number;
  weights: Record<string, number>;
  has_critical: boolean;
  deduction: number;
  deduction_detail: ScoreDeductionDetail[];
  exclude_ai_fp: boolean;
  status: string;
  completed_at: string | null;
  branch: string | null;
  source_url: string | null;
}

export interface CodeqlFlowGraph {
  codeql_path_total: number;
  node_count: number;
  edge_count: number;
  path_summaries: string[];
  hub_nodes: string[];
  top_edges: string[];
}

export interface ScanEvent {
  id: number;
  scan_id: number;
  level: string;
  phase: string | null;
  tool: string | null;
  file_path: string | null;
  message: string;
  created_at: string;
}

export interface AgentChatMessage {
  role: "user" | "assistant";
  content: string;
  created_at: string;
}

export interface AgentAction {
  action: string;
  result?: string | null;
  created_at: string;
}

export interface AgentChatResponse {
  reply: string;
  action?: string | null;
  action_result?: string | null;
  messages: AgentChatMessage[];
  action_history?: AgentAction[];
}

export type AgentTaskMode = "auth_gap_hunt" | "biz_gap_hunt" | "prioritize";

export interface AgentTaskItem {
  id: string;
  title: string;
  priority_score: number;
  confidence: "high" | "medium" | "low" | string;
  finding_id?: number | null;
  category: string;
  risk_type: string;
  impact: string;
  attack_path: string;
  recommendation: string;
  score_breakdown?: Record<string, number>;
}

export interface AgentTaskResponse {
  ok: boolean;
  mode: AgentTaskMode;
  summary: string;
  items: AgentTaskItem[];
  next_actions: string[];
  evidence_refs: string[];
  metrics?: Record<string, number>;
}

export interface LlmAuditJournalEntry {
  id: number;
  type: string;
  level: string;
  created_at: string;
  file_path?: string | null;
  title: string;
  payload: Record<string, unknown>;
}

export interface Settings {
  llm_provider: string;
  llm_api_base: string;
  llm_model: string;
  llm_model_fp: string;
  llm_model_deep: string;
  llm_model_agent: string;
  llm_provider_fp: string;
  llm_provider_deep: string;
  llm_provider_agent: string;
  llm_enabled: boolean;
  llm_configured: boolean;
  llm_timeout: number;
  semgrep_config: string;
  codeql_query_suite: string;
  codeql_build_mode: string;
  codeql_java_build_command: string;
  codeql_timeout: number;
  codeql_db_timeout: number;
  llm_code_audit_enabled: boolean;
  llm_audit_max_files: number;
  llm_audit_file_max_chars: number;
  llm_audit_max_tokens: number;
  llm_endpoint_audit_max_controllers: number;
  llm_endpoint_max_related_files: number;
  llm_endpoint_audit_max_iterations: number;
  llm_endpoint_audit_max_domains: number;
  llm_endpoint_origin_sample_per_domain: number;
  llm_agent_max_tool_rounds: number;
  llm_audit_profile: "stable" | "balanced" | "broad";
  llm_audit_require_stronger_evidence: boolean;
  llm_audit_enable_broader_hypotheses: boolean;
  llm_audit_focus_areas: string[];
  semgrep_timeout: number;
  // Feishu/Lark notification (best-effort via Incoming Webhook)
  feishu_webhook_url: string;
  feishu_at_user_ids: string[];
  feishu_notify_min_severity: string;
  feishu_configured?: boolean;
  // Used to build deep-link URLs inside notifications.
  frontend_base_url: string;
  gitlab_default_url?: string;
  gitlab_default_branch?: string;
  gitlab_access_token_configured?: boolean;
  gitlab_tls_verify?: boolean;
  webhook_token_configured?: boolean;
  smtp_host?: string;
  smtp_port?: number;
  smtp_user?: string;
  smtp_tls?: boolean;
  email_from?: string;
  smtp_password_configured?: boolean;
  database_backend?: "sqlite" | "mysql";
  database_url?: string;
  mysql_host?: string;
  mysql_port?: number;
  mysql_user?: string;
  mysql_database?: string;
  mysql_charset?: string;
  mysql_password_configured?: boolean;
  database_restart_required?: boolean;
  database_switched?: boolean;
  auth_token_expire_hours?: number;
  auth_refresh_token_expire_days?: number;
  score_weight_critical?: number;
  score_weight_high?: number;
  score_weight_medium?: number;
  score_weight_low?: number;
  score_weight_info?: number;
  score_weight_unknown?: number;
  score_exclude_ai_fp?: boolean;
  scores_recalculated?: number | null;
  enabled_scanners: string[];
  exclude_test_paths: boolean;
  scanners: ScannerInfo[];
}

export interface CheckSourceUrlResult {
  duplicate: boolean;
  normalized_url?: string | null;
  project?: ProjectSummary | null;
}

export interface CheckProjectNameResult {
  duplicate: boolean;
  project?: ProjectSummary | null;
}

export interface DuplicateGitUrlDetail {
  code: string;
  message: string;
  project: { id: number; name: string; source_url?: string | null };
}

export class ApiError extends Error {
  status: number;
  detail?: unknown;

  constructor(message: string, status: number, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export interface AuthUser {
  username: string;
  role?: string;
  auth_enabled: boolean;
}

export interface AuthConfig {
  auth_enabled: boolean;
  username_hint?: string | null;
  sso_enabled?: boolean;
  sso_login_url?: string | null;
}

export type AuthRole = "admin" | "user";

export function normalizeAuthRole(role: string | null | undefined): AuthRole {
  return role === "admin" ? "admin" : "user";
}

const TOKEN_KEY = "audit_auth_token";
const REFRESH_KEY = "audit_refresh_token";
const EXPIRES_KEY = "audit_token_expires_at";

let authToken: string | null =
  typeof sessionStorage !== "undefined" ? sessionStorage.getItem(TOKEN_KEY) : null;
let refreshToken: string | null =
  typeof sessionStorage !== "undefined" ? sessionStorage.getItem(REFRESH_KEY) : null;

let onUnauthorized: (() => void) | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | null = null;
let refreshing: Promise<boolean> | null = null;

export function getAuthToken(): string | null {
  return authToken;
}

export function setAuthToken(token: string | null) {
  authToken = token;
  if (typeof sessionStorage !== "undefined") {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  }
}

export function getRefreshToken(): string | null {
  return refreshToken;
}

export function setRefreshToken(token: string | null) {
  refreshToken = token;
  if (typeof sessionStorage !== "undefined") {
    if (token) sessionStorage.setItem(REFRESH_KEY, token);
    else sessionStorage.removeItem(REFRESH_KEY);
  }
}

export function setTokenExpiresAt(epochSeconds: number) {
  if (typeof sessionStorage !== "undefined") {
    sessionStorage.setItem(EXPIRES_KEY, String(epochSeconds));
  }
}

function getTokenExpiresAt(): number {
  if (typeof sessionStorage === "undefined") return 0;
  return Number(sessionStorage.getItem(EXPIRES_KEY) || "0");
}

export function clearAllTokens() {
  setAuthToken(null);
  setRefreshToken(null);
  if (refreshTimer) { clearTimeout(refreshTimer); refreshTimer = null; }
  if (typeof sessionStorage !== "undefined") sessionStorage.removeItem(EXPIRES_KEY);
}

export async function refreshAuth(): Promise<boolean> {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    const rt = refreshToken;
    if (!rt) return false;
    try {
      const res = await fetch(`${candidateBases()[0]}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!res.ok) return false;
      const data = await res.json();
      setAuthToken(data.access_token);
      setRefreshToken(data.refresh_token);
      if (data.expires_in) {
        setTokenExpiresAt(Math.floor(Date.now() / 1000) + data.expires_in);
      }
      scheduleRefresh(data.expires_in);
      return true;
    } catch {
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

export function scheduleRefresh(expiresInSeconds?: number) {
  if (refreshTimer) { clearTimeout(refreshTimer); refreshTimer = null; }
  const expiresAt = expiresInSeconds
    ? Math.floor(Date.now() / 1000) + expiresInSeconds
    : getTokenExpiresAt();
  if (!expiresAt || !refreshToken) return;
  const refreshAt = (expiresAt - 60) * 1000;
  const delay = refreshAt - Date.now();
  if (delay <= 0) {
    refreshAuth();
    return;
  }
  refreshTimer = setTimeout(() => { refreshAuth(); }, delay);
}

export function setOnUnauthorized(fn: () => void) {
  onUnauthorized = fn;
}

function parseErrorDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => (typeof d === "object" && d && "msg" in d ? String(d.msg) : String(d))).join("; ");
  }
  if (detail && typeof detail === "object" && "message" in detail) {
    const msg = (detail as { message?: unknown }).message;
    if (typeof msg === "string" && msg.trim()) return msg;
  }
  return "请求失败";
}

export interface ScannerInfo {
  id: string;
  name: string;
  description: string;
  category: string;
  install_hint: string;
  available: boolean;
  enabled: boolean;
  supported_languages: string[];
  setup_hint?: string | null;
  requires_build: boolean;
  availability_reason?: string | null;
}

export interface BuildInfo {
  build_id: string;
  ui: string;
}

export interface ExternalReviewLinkOut {
  ok: boolean;
  url: string;
  token_active: boolean;
  expires_at?: string | null;
}

export interface ProjectReviewFindingListItem {
  id: number;
  title: string;
  severity: Severity;
  file_path: string;
  line_start: number;
  line_end: number;
  category: FindingCategory;
  tool: string;
  external_status: ExternalReviewStatus;
  owasp_id?: string | null;
  owasp_name?: string | null;
  vuln_subtype?: string | null;
  vuln_subtype_name?: string | null;
}

export interface ProjectReviewOut {
  scan_id: number;
  project_name: string;
  token_active: boolean;
  expires_at?: string | null;
  total_findings: number;
  findings: ProjectReviewFindingListItem[];
}

export interface ExternalReviewCodeContext {
  relative_path: string;
  content: string;
  line_start: number;
  line_end: number;
  highlight_start: number;
  highlight_end: number;
}

export interface ExternalReviewOut {
  finding_id: number;
  title: string;
  message: string;
  message_zh?: string | null;
  severity: Severity;
  file_path: string;
  relative_path: string;
  line_start: number;
  line_end: number;
  rule_id: string;
  code_snippet?: string | null;
  ai_reason?: string | null;
  category: FindingCategory;
  tool: string;
  owasp_id?: string | null;
  owasp_name?: string | null;
  vuln_subtype?: string | null;
  vuln_subtype_name?: string | null;
  review_status: ReviewStatus;
  external_status: ExternalReviewStatus;
  external_note?: string | null;
  external_updated_at?: string | null;
  external_updated_by?: string | null;
  token_active: boolean;
  expires_at?: string | null;
  code_context?: ExternalReviewCodeContext | null;
}

const BASE = "/api";

/** When set (see .env.development), all API calls go to local backend only. */
const CONFIGURED_API_BASE = (import.meta.env.VITE_API_BASE as string | undefined)?.replace(/\/$/, "") || "";

// NOTE: production (container) builds always use the same-origin /api reverse proxy.
// Only the Vite dev server keeps direct-backend fallbacks; see candidateBases() below.

function isViteDevServer() {
  return typeof window !== "undefined" && window.location.port === "5173";
}

function localBackendBases(): string[] {
  return ["http://127.0.0.1:8787/api", "http://localhost:8787/api"];
}

function candidateBases() {
  const bases: string[] = [];
  if (CONFIGURED_API_BASE) {
    bases.push(CONFIGURED_API_BASE);
  }
  // Vite dev server only: keep direct uvicorn fallbacks while the backend reloads.
  // Container / production builds MUST use the same-origin /api reverse proxy.
  // Probing a hardcoded 127.0.0.1:8787 from the browser breaks one-port deployment.
  if (isViteDevServer()) {
    bases.push(...localBackendBases());
  }
  bases.push(BASE);
  return [...new Set(bases.filter(Boolean))];
}

const NETWORK_RETRY_DELAY_MS = 600;

function isTransientNetworkError(err: unknown): boolean {
  return err instanceof TypeError;
}

async function request<T>(path: string, options?: RequestInit & { skipAuth?: boolean }): Promise<T> {
  let lastErr: unknown = null;

  for (const base of candidateBases()) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const headers = new Headers(options?.headers);
        if (!options?.skipAuth && authToken) {
          headers.set("Authorization", `Bearer ${authToken}`);
        }
        const method = (options?.method || "GET").toUpperCase();
        const body = options?.body;
        if (
          body &&
          typeof body === "string" &&
          !headers.has("Content-Type") &&
          method !== "GET" &&
          method !== "HEAD"
        ) {
          headers.set("Content-Type", "application/json");
        }
        const res = await fetch(`${base}${path}`, { ...options, headers });
        if (res.status === 401 && !options?.skipAuth) {
          const ok = await refreshAuth();
          if (ok) {
            headers.set("Authorization", `Bearer ${authToken}`);
            const retryRes = await fetch(`${base}${path}`, { ...options, headers });
            if (retryRes.ok) {
              if (retryRes.status === 204) return undefined as T;
              const retryText = await retryRes.text();
              if (!retryText) return undefined as T;
              try { return JSON.parse(retryText) as T; } catch { /* fall through */ }
            }
          }
          clearAllTokens();
          onUnauthorized?.();
          throw new Error("未登录或登录已过期，请重新登录");
        }
        if (!res.ok) {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          throw new ApiError(parseErrorDetail(err.detail) || res.statusText, res.status, err.detail);
        }
        if (res.status === 204) {
          return undefined as T;
        }
        const text = await res.text();
        if (!text) {
          return undefined as T;
        }
        const contentType = (res.headers.get("content-type") || "").toLowerCase();
        if (!contentType.includes("application/json")) {
          const trimmed = text.trim();
          if (trimmed.startsWith("<")) {
            throw new Error("接口返回了页面内容（HTML），可能是服务重启中或前端缓存未刷新。请刷新页面后重试。");
          }
        }
        try {
          return JSON.parse(text) as T;
        } catch {
          const preview = text.slice(0, 120).replace(/\s+/g, " ");
          throw new Error(`接口返回的不是有效 JSON：${preview}`);
        }
      } catch (e) {
        lastErr = e;
        if (isTransientNetworkError(e) && attempt === 0) {
          await new Promise((resolve) => setTimeout(resolve, NETWORK_RETRY_DELAY_MS));
          continue;
        }
        if (!isTransientNetworkError(e)) {
          throw e;
        }
        break;
      }
    }
  }

  if (lastErr instanceof Error) {
    throw new Error(
      `无法连接后端服务（${lastErr.message}）。请确认后端已启动（优先 8787 端口），或执行 scripts/dev.ps1 重启后端。`
    );
  }
  throw new Error("无法连接后端服务，请确认后端已启动（优先 8787 端口）。");
}

async function fetchHtml(path: string): Promise<string> {
  let lastErr: unknown = null;
  for (const base of candidateBases()) {
    try {
      const headers = new Headers();
      if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
      headers.set("Accept", "text/html");
      const res = await fetch(`${base}${path}`, { headers });
      if (res.status === 401) {
        setAuthToken(null);
        onUnauthorized?.();
        throw new Error("未登录或登录已过期，请重新登录");
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new ApiError(parseErrorDetail(err.detail) || res.statusText, res.status, err.detail);
      }
      return await res.text();
    } catch (e) {
      lastErr = e;
      if (!(e instanceof TypeError)) throw e;
    }
  }
  if (lastErr instanceof Error) throw lastErr;
  throw new Error("无法连接后端服务");
}

async function fetchBlob(path: string): Promise<{ blob: Blob; filename: string | null }> {
  let lastErr: unknown = null;
  for (const base of candidateBases()) {
    try {
      const headers = new Headers();
      if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
      const res = await fetch(`${base}${path}`, { headers });
      if (res.status === 401) {
        setAuthToken(null);
        onUnauthorized?.();
        throw new Error("未登录或登录已过期，请重新登录");
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new ApiError(parseErrorDetail(err.detail) || res.statusText, res.status, err.detail);
      }
      const dispo = res.headers.get("content-disposition") || "";
      const m = dispo.match(/filename="([^"]+)"/i);
      return { blob: await res.blob(), filename: m?.[1] || null };
    } catch (e) {
      lastErr = e;
      if (!(e instanceof TypeError)) throw e;
    }
  }
  if (lastErr instanceof Error) throw lastErr;
  throw new Error("无法连接后端服务");
}

function triggerBlobDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener noreferrer";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/**
 * POST 版本的 fetchHtml：报告范围可能包含数百个 finding_id，
 * 必须走请求体而非 query，否则 URL 会超长。
 */
async function postHtml(path: string, body: unknown): Promise<string> {
  let lastErr: unknown = null;
  for (const base of candidateBases()) {
    try {
      const headers = new Headers();
      if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
      headers.set("Accept", "text/html");
      headers.set("Content-Type", "application/json");
      const res = await fetch(`${base}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body ?? {}),
      });
      if (res.status === 401) {
        setAuthToken(null);
        onUnauthorized?.();
        throw new Error("未登录或登录已过期，请重新登录");
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new ApiError(parseErrorDetail(err.detail) || res.statusText, res.status, err.detail);
      }
      return await res.text();
    } catch (e) {
      lastErr = e;
      if (!(e instanceof TypeError)) throw e;
    }
  }
  if (lastErr instanceof Error) throw lastErr;
  throw new Error("无法连接后端服务");
}

async function postBlob(path: string, body: unknown): Promise<{ blob: Blob; filename: string | null }> {
  let lastErr: unknown = null;
  for (const base of candidateBases()) {
    try {
      const headers = new Headers();
      if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
      headers.set("Content-Type", "application/json");
      const res = await fetch(`${base}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body ?? {}),
      });
      if (res.status === 401) {
        setAuthToken(null);
        onUnauthorized?.();
        throw new Error("未登录或登录已过期，请重新登录");
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new ApiError(parseErrorDetail(err.detail) || res.statusText, res.status, err.detail);
      }
      const dispo = res.headers.get("content-disposition") || "";
      const m = dispo.match(/filename="([^"]+)"/i);
      return { blob: await res.blob(), filename: m?.[1] || null };
    } catch (e) {
      lastErr = e;
      if (!(e instanceof TypeError)) throw e;
    }
  }
  if (lastErr instanceof Error) throw lastErr;
  throw new Error("无法连接后端服务");
}

export interface AuditSkill {
  id: string;
  version: string;
  name: string;
  sha256: string;
  enabled: boolean;
  manifest: { description: string; tools: string[]; applies_to: { archetypes: string[] }; entrypoints: { keywords: string[] } };
  instructions?: string;
  references?: Record<string, string>;
}
export interface SkillAuditOptions {
  skills: { id: string; version: string }[];
  profile: "stable" | "balanced" | "broad";
  budget: { max_iterations: number; timeout_seconds: number };
}
export interface SkillAuditRun {
  id: number;
  status: string;
  profile: string;
  model: string;
  created_at: string;
  error_message: string | null;
  skills: { id: string; name: string; version: string; sha256: string }[];
  results: { id: string; status: string; rounds: number; tools: number; findings: number; added: number; files_read: string[]; summary?: string; candidates: Record<string, unknown>[] }[];
}


// ============ Phase 2: platform management ============

export interface AgentDefinition {
  id: number;
  slug: string;
  name: string;
  role: string;
  description: string;
  enabled: boolean;
  model_task: string;
  model_override: string;
  system_prompt: string;
  max_tool_rounds: number;
  max_files: number;
  max_tokens: number;
  effective_model: string;
  execution_wired: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export type AgentPayload = Omit<
  AgentDefinition,
  "id" | "effective_model" | "execution_wired" | "created_at" | "updated_at"
>;
export type AgentPatch = Partial<Omit<AgentPayload, "slug">>;

export interface AgentCapabilities {
  runtime_status: string;
  execution_wired: boolean;
  scheduler: string | null;
  blackboard: string | null;
  llm_configured: boolean;
  roles: string[];
  model_tasks: string[];
  resolved_models: Record<string, string>;
  budget_ranges: Record<string, [number, number]>;
  agent_tool_round_limit: number;
  note: string;
}

export interface McpServer {
  id: number;
  slug: string;
  name: string;
  description: string;
  transport: string;
  endpoint: string;
  command: string;
  args: string[];
  headers: Record<string, string>;
  timeout_seconds: number;
  enabled: boolean;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_message: string;
  last_test_latency_ms: number | null;
  created_at: string | null;
  updated_at: string | null;
}

export type McpServerPayload = Omit<
  McpServer,
  | "id"
  | "last_test_at"
  | "last_test_ok"
  | "last_test_message"
  | "last_test_latency_ms"
  | "created_at"
  | "updated_at"
>;
export type McpServerPatch = Partial<Omit<McpServerPayload, "slug">>;

export interface McpTestResult {
  ok: boolean;
  status: string;
  message: string;
  latency_ms: number | null;
  checked_at: string | null;
  server_info: { protocolVersion?: string; server_name?: string } | null;
}

export interface McpCapabilities {
  transports: string[];
  stdio_execution_enabled: boolean;
  credential_storage_enabled: boolean;
  ssrf_guard: string;
  redirects_followed: boolean;
  probe: string;
  note: string;
}

export interface AccountOverview {
  username: string;
  role: string;
  auth_enabled: boolean;
  sso_enabled: boolean;
  password_source: "database" | "env";
  password_storage: "bcrypt" | "plaintext";
  secret_key_configured: boolean;
  token_expire_hours: number;
  refresh_expire_days: number;
  session_count: number;
  user_management_enabled: boolean;
  notes: string[];
}

export interface AccountSession {
  id: number;
  username: string;
  role: string;
  token_hint: string;
  sso_linked: boolean;
  created_at: string | null;
  expire_at: string | null;
  expired: boolean;
}

export interface AuditLogEntry {
  id: number;
  actor: string;
  action: string;
  target_type: string;
  target_id: string | null;
  detail: Record<string, unknown>;
  created_at: string | null;
}

export const api = {
  listAuditSkills: () => request<AuditSkill[]>("/skills"),
  getSkillDefaults: () => request<{skills: {id: string; version: string}[]}>("/skills/defaults"),
  getProjectSkillDefaults: (id: number) => request<{source: "system" | "project"; skills: {id: string; version: string}[]}>(`/projects/${id}/skill-defaults`),
  setProjectSkillDefaults: (id: number, skills: {id: string; version: string}[] | null) => request<{source: "system" | "project"; skills: {id: string; version: string}[]}>(`/projects/${id}/skill-defaults`, {method: "PUT", body: JSON.stringify({skills})}),
  setSkillDefaults: (skills: {id: string; version: string}[]) => request("/skills/defaults", { method: "PUT", body: JSON.stringify({skills}) }),
  auditSkillDetail: (id: string, version: string) => request<AuditSkill>(`/skills/${encodeURIComponent(id)}/${encodeURIComponent(version)}`),
  validateAuditSkill: (file: File) => {
    const form = new FormData(); form.append("file", file);
    return request<{ manifest: AuditSkill["manifest"] & { id: string; name: string; version: string }; instructions: string; references: Record<string, string>; sha256: string }>("/skills/validate", { method: "POST", body: form });
  },
  validateSkillBundle: (file: File) => {
    const form = new FormData(); form.append("file", file);
    return request<{ skills: { path: string; manifest: AuditSkill["manifest"] & { id: string; name: string; version: string }; instructions: string; references: Record<string, string>; binary_files: string[]; sha256: string }[] }>("/skills/validate-bundle", { method: "POST", body: form });
  },
  installSkillBundle: (file: File, paths: string[]) => {
    const form = new FormData(); form.append("file", file); form.append("paths", JSON.stringify(paths));
    return request<{ skills: AuditSkill[] }>("/skills/install-bundle", { method: "POST", body: form });
  },
  installAuditSkill: (file: File) => {
    const form = new FormData(); form.append("file", file);
    return request<AuditSkill>("/skills/install", { method: "POST", body: form });
  },
  setAuditSkillEnabled: (id: string, version: string, enabled: boolean) => request<AuditSkill>(`/skills/${encodeURIComponent(id)}/${encodeURIComponent(version)}`, { method: "PATCH", body: JSON.stringify({ enabled }) }),
  downloadAuditSkill: async (id: string, version: string) => {
    const { blob } = await fetchBlob(`/skills/${encodeURIComponent(id)}/${encodeURIComponent(version)}/package`);
    triggerBlobDownload(blob, `${id}-${version}.zip`);
  },
  auditRuns: (scanId: number) => request<SkillAuditRun[]>(`/scans/${scanId}/audit-runs`),
  skillAuditPlan: (scanId: number, options: SkillAuditOptions) => request<{ model: string; profile: string; budget: SkillAuditOptions["budget"] }>(`/scans/${scanId}/llm-audit/plan`, { method: "POST", body: JSON.stringify(options) }),
  authConfig: () => request<AuthConfig>("/auth/config", { skipAuth: true }),
  login: (username: string, password: string) =>
    request<{
      access_token: string;
      refresh_token?: string;
      token_type: string;
      expires_in?: number;
      username: string;
      role?: string;
      auth_enabled: boolean;
    }>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      skipAuth: true,
    }),
  me: () => request<AuthUser>("/auth/me"),
  health: () => request<{ status: string; app?: string; auth_enabled?: boolean }>("/health", { skipAuth: true }),
  getBuildInfo: () => request<{ build_id: string; ui: string }>("/build-info"),
  listScanners: () => request<ScannerInfo[]>("/scanners"),
  listScans: (params?: ListScansParams) => {
    const q = new URLSearchParams();
    if (params?.q) q.set("q", params.q);
    if (params?.status) q.set("status", params.status);
    if (params?.archived) q.set("archived", params.archived);
    const qs = q.toString();
    return request<ScanSummary[]>(`/scans${qs ? `?${qs}` : ""}`);
  },
  listProjects: (params?: ListProjectsParams) => {
    const q = new URLSearchParams();
    if (params?.q) q.set("q", params.q);
    if (params?.archived) q.set("archived", params.archived);
    const qs = q.toString();
    return request<ProjectSummary[]>(`/projects${qs ? `?${qs}` : ""}`);
  },
  getProject: (id: number) => request<ProjectDetail>(`/projects/${id}`),
  listProjectScans: (id: number) => request<ScanSummary[]>(`/projects/${id}/scans`),
  updateProject: (
    id: number,
    body: { name?: string; notes?: string | null; scan_languages?: string[] | null }
  ) =>
    request<ProjectSummary>(`/projects/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteProject: (id: number) => request<{ deleted: boolean }>(`/projects/${id}`, { method: "DELETE" }),
  archiveProject: (id: number) => request<ProjectSummary>(`/projects/${id}/archive`, { method: "POST" }),
  unarchiveProject: (id: number) => request<ProjectSummary>(`/projects/${id}/unarchive`, { method: "POST" }),
  listProjectWhitelist: (id: number, includeExpired = false) =>
    request<ProjectWhitelistEntry[]>(
      `/projects/${id}/whitelist${includeExpired ? "?include_expired=true" : ""}`
    ),
  addProjectWhitelist: (id: number, body: { finding_id: number; reason: string }) =>
    request<ProjectWhitelistEntry>(`/projects/${id}/whitelist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteProjectWhitelist: (id: number, entryId: number) =>
    request<{ ok: boolean; id: number }>(`/projects/${id}/whitelist/${entryId}`, {
      method: "DELETE",
    }),
  uploadProjectScan: async (projectId: number, file: File, name?: string) => {
    const form = new FormData();
    form.append("file", file);
    if (name) form.append("name", name);
    return request<ScanSummary>(`/projects/${projectId}/scans/upload`, { method: "POST", body: form });
  },
  gitlabProjectScan: (
    projectId: number,
    body: {
      name?: string;
      project_url?: string;
      branch?: string;
      access_token?: string;
      notify_emails?: string[];
      report_severities?: string[];
    }
  ) =>
    request<ScanSummary>(`/projects/${projectId}/scans/gitlab`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  retestScan: (
    id: number,
    body?: {
      branch?: string;
      access_token?: string;
      name?: string;
      auto_start?: boolean;
      strategy?: RetestStrategy;
      include_unreviewed_high?: boolean;
      finding_ids?: number[];
    }
  ) =>
    request<ScanSummary>(`/scans/${id}/retest`, {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),
  getRetestResults: (id: number) => request<RetestResultsSummary>(`/scans/${id}/retest-results`),
  getScanDiff: (id: number, baselineScanId?: number) => {
    const q = baselineScanId != null ? `?baseline_scan_id=${baselineScanId}` : "";
    return request<ScanDiffSummary>(`/scans/${id}/diff${q}`);
  },
  updateScan: (id: number, body: { name?: string; notes?: string | null }) =>
    request<ScanSummary>(`/scans/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  archiveScan: (id: number) => request<ScanSummary>(`/scans/${id}/archive`, { method: "POST" }),
  unarchiveScan: (id: number) => request<ScanSummary>(`/scans/${id}/unarchive`, { method: "POST" }),
  getScan: (id: number) => request<ScanSummary & { findings?: Finding[] }>(`/scans/${id}`),
  getFindings: (
    id: number,
    params?: {
      severity?: string;
      verdict?: string;
      review?: string;
      external?: string;
      category?: string;
      tool?: string;
      owasp?: string;
      subtype?: string;
      q?: string;
    }
  ) => {
    const q = new URLSearchParams();
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value != null && value !== "") {
          q.set(key, value);
        }
      }
    }
    const qs = q.toString();
    return request<Finding[]>(`/scans/${id}/findings${qs ? `?${qs}` : ""}`);
  },
  getFindingsPage: (
    id: number,
    params?: {
      severity?: string;
      verdict?: string;
      review?: string;
      external?: string;
      category?: string;
      tool?: string;
      owasp?: string;
      subtype?: string;
      q?: string;
      limit?: number;
      offset?: number;
    }
  ) => {
    const q = new URLSearchParams();
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value != null && value !== "") {
          q.set(key, String(value));
        }
      }
    }
    const qs = q.toString();
    return request<FindingPage>(`/scans/${id}/findings/page${qs ? `?${qs}` : ""}`);
  },
  getFinding: (scanId: number, findingId: number) =>
    request<Finding>(`/scans/${scanId}/findings/${findingId}`),
  reviewFinding: (
    scanId: number,
    findingId: number,
    body: { review_status: ReviewStatus; review_note?: string; generate_poc?: boolean }
  ) =>
    request<Finding>(`/scans/${scanId}/findings/${findingId}/review`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  generatePoc: (scanId: number, findingId: number, body?: { force?: boolean }) =>
    request<PocGenerateResult>(`/scans/${scanId}/findings/${findingId}/poc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }),
  savePocDraft: (scanId: number, findingId: number, body: PocHttpRequest) =>
    request<PocGenerateResult>(`/scans/${scanId}/findings/${findingId}/poc`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  executePoc: (scanId: number, findingId: number, body: PocHttpRequest) =>
    request<PocExecuteResult>(`/scans/${scanId}/findings/${findingId}/poc/execute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  getFileContent: (
    scanId: number,
    params: { path: string; line_start?: number; line_end?: number; context?: number }
  ) => {
    const q = new URLSearchParams();
    q.set("path", params.path);
    if (params.line_start) q.set("line_start", String(params.line_start));
    if (params.line_end) q.set("line_end", String(params.line_end));
    if (params.context) q.set("context", String(params.context));
    return request<FileContent>(`/scans/${scanId}/files/content?${q.toString()}`);
  },
  locateFile: (scanId: number, params: { q: string; file_hint?: string; limit?: number }) => {
    const q = new URLSearchParams();
    q.set("q", params.q);
    if (params.file_hint) q.set("file_hint", params.file_hint);
    if (params.limit) q.set("limit", String(params.limit));
    return request<CodeLocation[]>(`/scans/${scanId}/files/locate?${q.toString()}`);
  },
  getStats: (id: number) => request<ScanStats>(`/scans/${id}/stats`),
  getScanScore: (id: number, opts?: { refresh?: boolean }) => {
    const q = opts?.refresh ? "?refresh=true" : "";
    return request<ScanScore>(`/scans/${id}/score${q}`);
  },
  getCodeqlFlowGraph: (id: number) => request<CodeqlFlowGraph>(`/scans/${id}/codeql-flow-graph`),
  getEvents: (id: number, limit = 200) => request<ScanEvent[]>(`/scans/${id}/events?limit=${limit}`),
  getAgentChatHistory: (id: number, limit = 30) =>
    request<AgentChatMessage[]>(`/scans/${id}/agent-chat/history?limit=${limit}`),
  getAgentChatActions: (id: number, limit = 12) =>
    request<AgentAction[]>(`/scans/${id}/agent-chat/actions?limit=${limit}`),
  agentChat: (id: number, body: { message: string; max_history?: number }) =>
    request<AgentChatResponse>(`/scans/${id}/agent-chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  runAgentTask: (id: number, body: { mode: AgentTaskMode; scope?: { categories?: FindingCategory[]; max_items?: number }; options?: { top_n?: number } }) =>
    request<AgentTaskResponse>(`/scans/${id}/agent-tasks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  uploadScan: async (file: File, name?: string, projectId?: number, scanLanguages?: string[]) => {
    const form = new FormData();
    form.append("file", file);
    if (name) form.append("name", name);
    if (projectId != null) form.append("project_id", String(projectId));
    if (scanLanguages?.length) form.append("scan_languages", JSON.stringify(scanLanguages));
    return request<ScanSummary>("/scans/upload", { method: "POST", body: form });
  },
  gitlabScan: (body: {
    name?: string;
    project_url: string;
    branch?: string;
    access_token?: string;
    project_id?: number;
    notify_emails?: string[];
    report_severities?: string[];
    scan_languages?: string[];
  }) =>
    request<ScanSummary>("/scans/gitlab", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  analyze: (id: number, body?: { finding_ids?: number[]; max_findings?: number; force?: boolean }) =>
    request<{ analyzed: number; pending: number; already_audited: number; message: string }>(
      `/scans/${id}/analyze`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      }
    ),
  llmReview: (id: number, body?: { finding_ids?: number[]; max_findings?: number; force?: boolean }) =>
    request<{ analyzed: number; pending: number; already_audited: number; message: string }>(
      `/scans/${id}/llm-review`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      }
    ),
  sastDeepAudit: (id: number, body?: { finding_ids?: number[]; max_findings?: number; force?: boolean }) =>
    request<{
      analyzed: number;
      pending: number;
      already_audited: number;
      message: string;
      started?: boolean;
    }>(`/scans/${id}/sast-deep-audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }),
  getSastDeepProgress: (id: number) =>
    request<{
      scan_status: string;
      scan_progress: number;
      scan_progress_message: string | null;
      cancelling: boolean;
      job: {
        status?: string;
        phase?: string;
        message?: string;
        total?: number;
        done?: number;
        percent?: number;
        current_task_id?: string | null;
        tasks?: Array<{
          id: string;
          label: string;
          kind?: string;
          status: string;
          detail?: string;
          finding_id?: number;
        }>;
        error?: string | null;
      } | null;
    }>(`/scans/${id}/sast-deep-audit/progress`),
  llmAudit: (id: number, categories?: FindingCategory[], options?: SkillAuditOptions) =>
    request<{ status: string; categories: string[] }>(`/scans/${id}/llm-audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ categories: categories || [], skills: options?.skills || [], ...options }),
    }),
  cancelLlmAudit: (id: number) =>
    request<{ status: string; message: string }>(`/scans/${id}/llm-audit/cancel`, { method: "POST" }),
  cancelScan: (id: number) =>
    request<{ status: string; message: string }>(`/scans/${id}/cancel`, { method: "POST" }),
  startScan: (id: number) => request<ScanSummary>(`/scans/${id}/start`, { method: "POST" }),
  getLlmAuditJournal: (id: number, limit = 300) =>
    request<LlmAuditJournalEntry[]>(`/scans/${id}/llm-audit/journal?limit=${limit}`),
  getLlmAuditStatus: (id: number) =>
    request<{ status: string; progress: number; progress_message: string | null; cancelling: boolean }>(
      `/scans/${id}/llm-audit/status`
    ),
  rerun: (id: number) => request<ScanSummary>(`/scans/${id}/rerun`, { method: "POST" }),
  deleteScan: (id: number) => request<{ deleted: boolean }>(`/scans/${id}`, { method: "DELETE" }),
  getSettings: () => request<Settings>("/settings"),
  updateSettings: (
    body: Partial<
      Settings & {
        llm_api_key?: string;
        gitlab_access_token?: string;
        webhook_token?: string;
        smtp_password?: string;
      }
    >
  ) =>
    request<Settings>("/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  testLlm: () =>
    request<{ ok: boolean; message: string; model?: string; api_base?: string; latency_ms?: number }>(
      "/settings/test-llm",
      { method: "POST" }
    ),
  testFeishu: (body?: {
    feishu_webhook_url?: string;
    feishu_at_user_ids?: string[];
    frontend_base_url?: string;
  }) =>
    request<{ ok: boolean; message: string }>("/settings/test-feishu", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }),
  testEmail: (body?: {
    smtp_host?: string;
    smtp_port?: number;
    smtp_user?: string;
    smtp_password?: string;
    smtp_tls?: boolean;
    email_from?: string;
    to_email?: string;
  }) => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 35_000);
    return request<{ ok: boolean; message: string }>("/settings/test-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      signal: controller.signal,
    }).finally(() => window.clearTimeout(timer));
  },
  testGitlab: (body?: { project_url?: string; branch?: string; access_token?: string }) =>
    request<{ ok: boolean; message: string; code?: string; http_status?: number }>(
      "/settings/test-gitlab",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      }
    ),
  openScanReport: async (scanId: number) => {
    const html = await fetchHtml(`/scans/${scanId}/report.html`);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  },
  downloadScanReportHtml: async (scanId: number) => {
    const { blob, filename } = await fetchBlob(`/scans/${scanId}/report.html?download=1`);
    triggerBlobDownload(blob, filename || `scan-${scanId}.html`);
  },
  downloadScanReportPdf: async (scanId: number) => {
    const { blob, filename } = await fetchBlob(`/scans/${scanId}/report.pdf`);
    triggerBlobDownload(blob, filename || `scan-${scanId}.pdf`);
  },
  downloadScanReportMarkdown: async (scanId: number) => {
    const { blob, filename } = await fetchBlob(`/scans/${scanId}/report.md`);
    triggerBlobDownload(blob, filename || `scan-${scanId}.md`);
  },
  downloadScanReportJson: async (scanId: number) => {
    const { blob, filename } = await fetchBlob(`/scans/${scanId}/report.json`);
    triggerBlobDownload(blob, filename || `scan-${scanId}.json`);
  },
  previewScanReport: (scanId: number, spec: ReportSpec) =>
    request<ReportPreview>(`/scans/${scanId}/report/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(spec),
    }),
  /** 按自定义范围打开 HTML 报告（新标签页） */
  openScanReportWithSpec: async (scanId: number, spec: ReportSpec) => {
    const html = await postHtml(`/scans/${scanId}/report.html`, spec);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  },
  downloadScanReportHtmlWithSpec: async (scanId: number, spec: ReportSpec) => {
    const { blob, filename } = await postBlob(`/scans/${scanId}/report.html?download=1`, spec);
    triggerBlobDownload(blob, filename || `scan-${scanId}.html`);
  },
  downloadScanReportPdfWithSpec: async (scanId: number, spec: ReportSpec) => {
    const { blob, filename } = await postBlob(`/scans/${scanId}/report.pdf`, spec);
    triggerBlobDownload(blob, filename || `scan-${scanId}.pdf`);
  },
  downloadScanReportMarkdownWithSpec: async (scanId: number, spec: ReportSpec) => {
    const { blob, filename } = await postBlob(`/scans/${scanId}/report.md`, spec);
    triggerBlobDownload(blob, filename || `scan-${scanId}.md`);
  },
  downloadScanReportJsonWithSpec: async (scanId: number, spec: ReportSpec) => {
    const { blob, filename } = await postBlob(`/scans/${scanId}/report.json`, spec);
    triggerBlobDownload(blob, filename || `scan-${scanId}.json`);
  },
  testDatabase: (body?: {
    database_backend?: string;
    database_url?: string;
    mysql_host?: string;
    mysql_port?: number;
    mysql_user?: string;
    mysql_password?: string;
    mysql_database?: string;
    mysql_charset?: string;
  }) =>
    request<{ ok: boolean; message: string }>("/settings/test-database", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }),
  checkSourceUrl: (url: string) =>
    request<CheckSourceUrlResult>(`/projects/check-source-url?url=${encodeURIComponent(url)}`),
  checkProjectName: (name: string) =>
    request<CheckProjectNameResult>(`/projects/check-name?name=${encodeURIComponent(name)}`),
  createExternalReviewLink: (scanId: number, findingId: number, body?: { expires_hours?: number }) =>
    request<ExternalReviewLinkOut>(`/scans/${scanId}/findings/${findingId}/external-review-link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }),
  revokeExternalReviewLink: (scanId: number, findingId: number) =>
    request<ExternalReviewLinkOut>(`/scans/${scanId}/findings/${findingId}/external-review-link/revoke`, {
      method: "POST",
    }),
  getExternalReview: (token: string) =>
    request<ExternalReviewOut>(`/external-review/${encodeURIComponent(token)}`, { skipAuth: true }),
  submitExternalReview: (
    token: string,
    body: { status: ExternalReviewStatus; note?: string; actor?: string }
  ) =>
    request<{ ok: boolean; status: ExternalReviewStatus; message: string }>(
      `/external-review/${encodeURIComponent(token)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        skipAuth: true,
      }
    ),
  getProjectReviewLink: (scanId: number) =>
    request<ExternalReviewLinkOut>(`/scans/${scanId}/project-review-link`),
  createProjectReviewLink: (scanId: number, body?: { expires_hours?: number }) =>
    request<ExternalReviewLinkOut>(`/scans/${scanId}/project-review-link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || { expires_hours: 168 }),
    }),
  revokeProjectReviewLink: (scanId: number) =>
    request<ExternalReviewLinkOut>(`/scans/${scanId}/project-review-link/revoke`, {
      method: "POST",
    }),
  getProjectReview: (token: string) =>
    request<ProjectReviewOut>(`/project-review/${encodeURIComponent(token)}`, { skipAuth: true }),
  getProjectReviewFinding: (token: string, findingId: number) =>
    request<ExternalReviewOut>(
      `/project-review/${encodeURIComponent(token)}/findings/${findingId}`,
      { skipAuth: true }
    ),
  submitProjectReviewFinding: (
    token: string,
    findingId: number,
    body: { status: ExternalReviewStatus; note?: string; actor?: string }
  ) =>
    request<{ ok: boolean; status: ExternalReviewStatus; message: string }>(
      `/project-review/${encodeURIComponent(token)}/findings/${findingId}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        skipAuth: true,
      }
    ),
  // ---- Phase 2: Agent definitions (configuration only) ----
  listAgents: () => request<AgentDefinition[]>("/agents"),
  getAgentCapabilities: () => request<AgentCapabilities>("/agents/capabilities"),
  createAgent: (body: AgentPayload) =>
    request<AgentDefinition>("/agents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  updateAgent: (id: number, body: AgentPatch) =>
    request<AgentDefinition>(`/agents/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: number) =>
    request<{ ok: boolean; id: number; slug: string }>(`/agents/${id}`, { method: "DELETE" }),

  // ---- Phase 2: MCP server registry ----
  listMcpServers: () => request<McpServer[]>("/mcp/servers"),
  getMcpCapabilities: () => request<McpCapabilities>("/mcp/capabilities"),
  createMcpServer: (body: McpServerPayload) =>
    request<McpServer>("/mcp/servers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  updateMcpServer: (id: number, body: McpServerPatch) =>
    request<McpServer>(`/mcp/servers/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteMcpServer: (id: number) =>
    request<{ ok: boolean; id: number; slug: string }>(`/mcp/servers/${id}`, { method: "DELETE" }),
  testMcpServer: (id: number) =>
    request<McpTestResult>(`/mcp/servers/${id}/test`, { method: "POST" }),

  // ---- Phase 2: Accounts ----
  getAccountOverview: () => request<AccountOverview>("/accounts/overview"),
  listAccountSessions: () => request<{ items: AccountSession[]; total: number }>("/accounts/sessions"),
  revokeAccountSession: (id: number) =>
    request<{ ok: boolean; id: number }>(`/accounts/sessions/${id}`, { method: "DELETE" }),
  cleanupAccountSessions: () =>
    request<{ ok: boolean; removed: number }>("/accounts/sessions/cleanup", { method: "POST" }),
  changeAccountPassword: (body: {
    current_password: string;
    new_password: string;
    revoke_sessions?: boolean;
  }) =>
    request<{
      ok: boolean;
      password_source: string;
      password_storage: string;
      sessions_revoked: number;
      min_length: number;
      max_length: number;
    }>("/accounts/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  listAuditLogs: (limit = 50) =>
    request<{ items: AuditLogEntry[]; total: number }>(`/accounts/audit-logs?limit=${limit}`),
};
