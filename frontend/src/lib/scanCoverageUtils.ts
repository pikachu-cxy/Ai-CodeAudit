import type {
  CapabilityCoverage,
  LlmAuditCoverage,
  LlmFocusCoverage,
  OwaspCategoryCoverage,
  ScanCoverage,
  ScannerCoverage,
  ScanStatus,
  ScanSummary,
  SemgrepRuleEvidence,
} from "../api";
import { OWASP_ORDER, OWASP_TOP10, SUBTYPE_LABELS } from "./owaspUtils";
import { LLM_AUDIT_FOCUS_OPTIONS, LLM_FOCUS_LABELS } from "./llmAuditFocus";

export type {
  CapabilityCoverage,
  LlmAuditCoverage,
  LlmFocusCoverage,
  OwaspCategoryCoverage,
  ScanCoverage,
  ScannerCoverage,
  SemgrepRuleEvidence,
};

export type ScannerCoverageStatus = ScannerCoverage["status"];
export type CapabilityCoverageStatus = CapabilityCoverage["status"];

export const LIST_CAPABILITY_IDS = [
  "sql_injection",
  "xss",
  "command_injection",
  "secrets",
  "vulnerable_dependency",
] as const;

const SAST_SCANNERS = new Set(["semgrep", "codeql"]);
const SECRETS_SCANNERS = new Set(["gitleaks"]);
const SCA_SCANNERS = new Set(["npm_audit", "pip_audit", "dep_exploit"]);
const PYTHON_SCANNERS = new Set(["bandit"]);

const RULE_EVIDENCE_CAPABILITIES = new Set([
  "sql_injection",
  "xss",
  "command_injection",
  "ldap_injection",
  "xpath_injection",
  "nosql_injection",
  "ssti",
  "header_injection",
  "code_injection",
  "xml_injection",
  "expression_injection",
  "log_injection",
  "other_injection",
  "path_traversal",
  "ssrf",
  "hardcoded_secret",
  "deserialization",
]);

const SCANNER_DISPLAY_NAMES: Record<string, string> = {
  semgrep: "Semgrep",
  codeql: "CodeQL",
  bandit: "Bandit",
  gitleaks: "Gitleaks",
  npm_audit: "npm audit",
  pip_audit: "pip audit",
  dep_exploit: "依赖漏洞",
};

const INJECTION_SUBTYPES = [
  "sql_injection",
  "xss",
  "command_injection",
  "ldap_injection",
  "xpath_injection",
  "nosql_injection",
  "ssti",
  "header_injection",
  "code_injection",
  "xml_injection",
  "expression_injection",
  "log_injection",
  "other_injection",
] as const;

interface ScannerRunSummary {
  scanner: string;
  findings?: number;
  skipped?: boolean;
  skip_reason?: string | null;
  error?: string | null;
  version?: string | null;
  detail?: Record<string, unknown> | null;
}

function parseScannerRuns(scannerSummary: string | null | undefined): ScannerRunSummary[] {
  if (!scannerSummary || scannerSummary.trim() === "" || scannerSummary === "[]") return [];
  try {
    const parsed = JSON.parse(scannerSummary) as unknown;
    if (Array.isArray(parsed)) return parsed as ScannerRunSummary[];
    if (parsed && typeof parsed === "object" && Array.isArray((parsed as { scanners?: unknown }).scanners)) {
      return (parsed as { scanners: ScannerRunSummary[] }).scanners;
    }
  } catch {
    return [];
  }
  return [];
}

function scannerStatus(entry: ScannerRunSummary): ScannerCoverageStatus {
  if (entry.error) return "failed";
  if (entry.skipped) return "skipped";
  return "ran";
}

function scannerReason(entry: ScannerRunSummary): string | null {
  if (entry.error) return entry.error;
  if (entry.skipped && entry.skip_reason) return entry.skip_reason;
  return null;
}

function semgrepConfigsFromRuns(runs: ScannerRunSummary[]): string[] {
  for (const entry of runs) {
    if (entry.scanner !== "semgrep") continue;
    const configs = entry.detail?.configs;
    if (Array.isArray(configs) && configs.length > 0) {
      return configs.map(String);
    }
  }
  return [];
}

function extractRuleInventory(runs: ScannerRunSummary[]): SemgrepRuleEvidence | null {
  for (const entry of runs) {
    if (entry.scanner !== "semgrep") continue;
    const inv = entry.detail?.rule_inventory;
    if (inv && typeof inv === "object") {
      const data = inv as SemgrepRuleEvidence;
      return {
        source: data.source ?? null,
        configs: Array.isArray(data.configs) ? data.configs.map(String) : [],
        total_rules: Number(data.total_rules || 0),
        by_subtype: (data.by_subtype || {}) as Record<string, number>,
        by_owasp: (data.by_owasp || {}) as Record<string, number>,
        sample_rules_by_subtype: data.sample_rules_by_subtype || {},
        sample_rules_by_owasp: data.sample_rules_by_owasp || {},
        inventory_error: data.inventory_error ?? null,
        resolved_at: data.resolved_at ?? null,
        project_languages: Array.isArray(data.project_languages)
          ? data.project_languages.map(String)
          : [],
        filtered: Boolean(data.filtered),
        unfiltered_total_rules:
          data.unfiltered_total_rules == null ? null : Number(data.unfiltered_total_rules),
      };
    }
  }
  return null;
}

function buildLlmAuditFallback(scanStatus?: ScanStatus): LlmAuditCoverage | null {
  if (scanStatus !== "llm_auditing") return null;
  const focusAreas: LlmFocusCoverage[] = LLM_AUDIT_FOCUS_OPTIONS.map((opt) => ({
    id: opt.id,
    label: opt.label,
    status: "configured",
    note: "已配置，审计进行中",
  }));
  return {
    ran: true,
    status: "running",
    focus_areas: focusAreas,
  };
}

/**
 * Client-side fallback when API omits scan_coverage.
 * Aligns with backend 实锤 gating: SAST subtypes require rule_inventory counts.
 */
export function buildScanCoverageFromSummary(
  scannerSummary: string | null | undefined,
  enabledScanners?: string[],
  scanStatus?: ScanStatus,
): ScanCoverage {
  const runs = parseScannerRuns(scannerSummary);
  const runById = new Map(runs.map((r) => [r.scanner, r]));
  const ran = new Set(runs.filter((r) => scannerStatus(r) === "ran").map((r) => r.scanner));
  const semgrepConfigs = semgrepConfigsFromRuns(runs);
  const evidence = extractRuleInventory(runs);
  const bySubtype = evidence?.by_subtype || {};
  const byOwasp = evidence?.by_owasp || {};
  const hasInventory = Boolean(evidence && (evidence.total_rules || 0) > 0);
  const inventoryError = evidence?.inventory_error || null;
  const partialInventory = Boolean(hasInventory && inventoryError);
  const enabled = enabledScanners ?? [
    "semgrep",
    "codeql",
    "bandit",
    "gitleaks",
    "npm_audit",
    "pip_audit",
    "dep_exploit",
  ];

  const scanners: ScannerCoverage[] = [];
  for (const scannerId of enabled) {
    const entry = runById.get(scannerId);
    if (!entry) {
      scanners.push({
        id: scannerId,
        name: SCANNER_DISPLAY_NAMES[scannerId] || scannerId,
        status: "not_run",
        findings: 0,
      });
      continue;
    }
    scanners.push({
      id: scannerId,
      name: SCANNER_DISPLAY_NAMES[scannerId] || scannerId,
      status: scannerStatus(entry),
      findings: entry.findings ?? 0,
      reason: scannerReason(entry),
      version: entry.version ?? null,
      detail: entry.detail ?? null,
    });
  }

  for (const entry of runs) {
    if (enabled.includes(entry.scanner)) continue;
    scanners.push({
      id: entry.scanner,
      name: SCANNER_DISPLAY_NAMES[entry.scanner] || entry.scanner,
      status: scannerStatus(entry),
      findings: entry.findings ?? 0,
      reason: scannerReason(entry),
      version: entry.version ?? null,
      detail: entry.detail ?? null,
    });
  }

  const capabilities: CapabilityCoverage[] = [];

  function addToolCapability(capId: string, required: Set<string>, label?: string): void {
    const sources = [...required].filter((id) => ran.has(id)).sort();
    const status: CapabilityCoverageStatus = sources.length ? "checked" : "not_checked";
    let note: string | null = null;
    if (capId === "secrets" && sources.length) note = "Gitleaks 密钥扫描（工具级）";
    if (capId === "vulnerable_dependency" && sources.length) note = "依赖漏洞扫描（工具级）";
    if (capId === "python_security" && sources.length) note = "Bandit Python 安全规则（工具级）";
    capabilities.push({
      id: capId,
      label: label || SUBTYPE_LABELS[capId] || capId,
      status,
      sources,
      note,
    });
  }

  function addRuleCapability(capId: string, label?: string): void {
    const count = Number(bySubtype[capId] || 0);
    const semgrepRan = ran.has("semgrep");
    const codeqlRan = ran.has("codeql");
    let status: CapabilityCoverageStatus = "not_checked";
    let sources: string[] = [];
    let note: string | null = null;

    if (hasInventory && count > 0) {
      status = partialInventory ? "partial" : "checked";
      sources = ["semgrep"];
      note = `规则清单 ${count} 条${partialInventory ? " · 部分规则包未解析" : ""}（客户端估算）`;
    } else if (hasInventory && semgrepRan && count === 0) {
      status = codeqlRan ? "partial" : "not_checked";
      sources = codeqlRan ? ["codeql"] : [];
      note = codeqlRan
        ? "规则清单无此类规则；CodeQL 工具级（客户端估算）"
        : "规则清单中无此类规则（客户端估算）";
    } else if (semgrepRan && !hasInventory) {
      status = codeqlRan ? "partial" : "not_checked";
      sources = codeqlRan ? ["codeql"] : [];
      note = inventoryError || "规则清单不可用，无法实锤（客户端估算）";
    } else if (codeqlRan) {
      status = "partial";
      sources = ["codeql"];
      note = "CodeQL 工具级，非规则清单（客户端估算）";
    }

    capabilities.push({
      id: capId,
      label: label || SUBTYPE_LABELS[capId] || capId,
      status,
      sources,
      note,
      rule_count: hasInventory ? count : null,
    });
  }

  for (const capId of INJECTION_SUBTYPES) {
    addRuleCapability(capId);
  }
  addRuleCapability("path_traversal", SUBTYPE_LABELS.path_traversal);
  addRuleCapability("ssrf", SUBTYPE_LABELS.ssrf);
  addRuleCapability("hardcoded_secret", SUBTYPE_LABELS.hardcoded_secret);
  addRuleCapability("deserialization", SUBTYPE_LABELS.deserialization || "不安全反序列化");

  for (const cap of capabilities) {
    if (cap.id === "hardcoded_secret" && ran.has("gitleaks") && cap.status === "not_checked") {
      cap.status = "partial";
      cap.sources = ["gitleaks", ...cap.sources];
      cap.note = `${cap.note || ""} · Gitleaks（工具级）`.trim();
    }
  }

  addToolCapability("secrets", SECRETS_SCANNERS, "密钥泄露");
  addToolCapability("vulnerable_dependency", SCA_SCANNERS, SUBTYPE_LABELS.vulnerable_dependency);
  addToolCapability("python_security", PYTHON_SCANNERS, "Python 安全");

  const owaspCategories: OwaspCategoryCoverage[] = OWASP_ORDER.map((owaspId) => {
    const label = OWASP_TOP10[owaspId] || owaspId;
    const ruleCount = Number(byOwasp[owaspId] || 0);
    if (owaspId === "A04") {
      return {
        id: owaspId,
        label,
        status: "not_checked",
        sources: [],
        note: "不安全设计主要靠 LLM 业务逻辑审计（客户端估算）",
      };
    }
    if (owaspId === "A06") {
      const sources = [...SCA_SCANNERS].filter((id) => ran.has(id)).sort();
      return {
        id: owaspId,
        label,
        status: sources.length ? "checked" : "not_checked",
        sources,
        note: sources.length ? "依赖漏洞扫描（工具级，客户端估算）" : null,
      };
    }
    if (hasInventory && ran.has("semgrep")) {
      if (ruleCount > 0) {
        let status: CapabilityCoverageStatus =
          owaspId === "A07" || owaspId === "A09" || partialInventory ? "partial" : "checked";
        return {
          id: owaspId,
          label,
          status,
          sources: ["semgrep"],
          note: `规则清单 ${ruleCount} 条（客户端估算）`,
          rule_count: ruleCount,
        };
      }
      return {
        id: owaspId,
        label,
        status: "not_checked" as const,
        sources: [],
        note: "规则清单中无此类规则（客户端估算）",
        rule_count: 0,
      };
    }
    if (ran.has("semgrep") && !hasInventory) {
      return {
        id: owaspId,
        label,
        status: "not_checked",
        sources: [],
        note: inventoryError || "Semgrep 已执行但规则清单不可用（客户端估算）",
      };
    }
    if (ran.has("codeql")) {
      return {
        id: owaspId,
        label,
        status: "partial",
        sources: ["codeql"],
        note: "CodeQL 工具级（客户端估算）",
      };
    }
    return { id: owaspId, label, status: "not_checked", sources: [], note: null };
  });

  return {
    scanners,
    capabilities,
    semgrep_configs: semgrepConfigs,
    sast_checked: [...SAST_SCANNERS].some((id) => ran.has(id)),
    owasp_categories: owaspCategories,
    llm_audit: buildLlmAuditFallback(scanStatus),
    semgrep_rule_evidence: evidence,
  };
}

export function resolveScanCoverage(
  scan: Pick<ScanSummary, "scanner_summary" | "scan_coverage" | "status">,
): ScanCoverage {
  if (scan.scan_coverage) return scan.scan_coverage;
  return buildScanCoverageFromSummary(scan.scanner_summary, undefined, scan.status);
}

export function shouldShowCoveragePanel(coverage: ScanCoverage): boolean {
  const anyScanner = coverage.scanners.some((s) => s.status !== "not_run");
  const llmActive = Boolean(coverage.llm_audit?.ran || coverage.llm_audit?.status === "running");
  const hasEvidence = Boolean(coverage.semgrep_rule_evidence);
  return anyScanner || llmActive || hasEvidence || coverage.sast_checked;
}

export function coverageSummaryLine(coverage: ScanCoverage): string {
  const ran = coverage.scanners.filter((s) => s.status === "ran").length;
  const totalScanners = coverage.scanners.filter((s) => s.status !== "not_run").length || coverage.scanners.length;
  const cats = coverage.owasp_categories || [];
  const owaspScore = cats.filter((c) => c.status === "checked" || c.status === "partial").length;
  const rules = coverage.semgrep_rule_evidence?.total_rules;
  const llm = coverage.llm_audit;
  const audited = (llm?.focus_areas || []).filter((f) => f.status === "audited").length;
  const focusTotal = (llm?.focus_areas || []).length;
  const parts = [
    `工具 ${ran}/${totalScanners || ran || 0}`,
    typeof rules === "number" ? `Semgrep ${rules} 规则` : "Semgrep 未实锤",
    cats.length ? `OWASP ${owaspScore}/${cats.length}` : null,
    focusTotal ? `LLM ${audited}/${focusTotal}` : llm?.status === "running" ? "LLM 审计中" : "LLM 未运行",
  ].filter(Boolean);
  return parts.join(" · ");
}

export function compactScannerLine(coverage: ScanCoverage): string {
  const ran = coverage.scanners.filter((s) => s.status === "ran");
  if (!ran.length) {
    const attempted = coverage.scanners.filter((s) => s.status !== "not_run");
    if (!attempted.length) return "尚未执行扫描器";
    return attempted.map((s) => `${s.name}${s.status === "skipped" ? "（跳过）" : "（失败）"}`).join(" · ");
  }
  return ran.map((s) => s.name).join(" · ");
}

export function compactCapabilityLine(coverage: ScanCoverage): string {
  const caps = LIST_CAPABILITY_IDS.map((id) => {
    const cap = coverage.capabilities.find((c) => c.id === id);
    if (!cap) return null;
    const short =
      id === "sql_injection"
        ? "SQL注入"
        : id === "xss"
          ? "XSS"
          : id === "command_injection"
            ? "命令注入"
            : id === "secrets"
              ? "密钥"
              : "依赖";
    const count =
      typeof cap.rule_count === "number" && cap.rule_count > 0 ? `·${cap.rule_count}` : "";
    if (cap.status === "checked") return `${short}✓${count}`;
    if (cap.status === "partial") return `${short}~${count}`;
    return `${short}—`;
  }).filter(Boolean);
  return caps.join(" ");
}

export function capabilityById(coverage: ScanCoverage, id: string): CapabilityCoverage | undefined {
  return coverage.capabilities.find((c) => c.id === id);
}

export function isRuleEvidenceCapability(id: string): boolean {
  return RULE_EVIDENCE_CAPABILITIES.has(id);
}

export function scannerStatusLabel(status: ScannerCoverageStatus): string {
  switch (status) {
    case "ran":
      return "已执行";
    case "skipped":
      return "已跳过";
    case "failed":
      return "失败";
    default:
      return "未运行";
  }
}

export function capabilityStatusLabel(status: CapabilityCoverageStatus): string {
  if (status === "checked") return "已检测";
  if (status === "partial") return "部分";
  return "未检测";
}

export function owaspStatusLabel(status: CapabilityCoverageStatus): string {
  return capabilityStatusLabel(status);
}

export function llmFocusStatusLabel(status: LlmFocusCoverage["status"]): string {
  switch (status) {
    case "audited":
      return "已审计";
    case "configured":
      return "已配置";
    case "skipped":
      return "未纳入";
    default:
      return "未启用";
  }
}

export function compactOwaspLine(coverage: ScanCoverage): string {
  const cats = coverage.owasp_categories || [];
  if (!cats.length) return "OWASP —";
  const checked = cats.filter((c) => c.status === "checked").length;
  const partial = cats.filter((c) => c.status === "partial").length;
  const score = checked + partial;
  return `OWASP ${score}/${cats.length}`;
}

export function owaspTooltip(coverage: ScanCoverage): string {
  const cats = coverage.owasp_categories || [];
  return cats
    .map((c) => `${c.id} ${c.label}：${owaspStatusLabel(c.status)}${c.note ? `（${c.note}）` : ""}`)
    .join("\n");
}

export function compactLlmLine(coverage: ScanCoverage): string {
  const llm = coverage.llm_audit;
  if (!llm) return "LLM 未运行";
  if (llm.status === "running") return "LLM 审计中";
  if (!llm.ran && llm.status === "not_run") return "LLM 未运行";
  const audited = (llm.focus_areas || []).filter((f) => f.status === "audited").length;
  const total = (llm.focus_areas || []).length;
  return total ? `LLM ${audited}/${total}` : "LLM 已运行";
}

export function llmTooltip(coverage: ScanCoverage): string {
  const llm = coverage.llm_audit;
  if (!llm) return "LLM 深度审计未运行";
  const lines = (llm.focus_areas || []).map(
    (f) => `${f.label}：${llmFocusStatusLabel(f.status)}${f.note ? ` · ${f.note}` : ""}`,
  );
  return [`状态：${llm.status}`, ...lines].join("\n");
}

export function historyCoverageChips(coverage: ScanCoverage): { label: string; title: string }[] {
  return [
    {
      label: `工具 ${coverage.scanners.filter((s) => s.status === "ran").length}`,
      title: compactScannerLine(coverage),
    },
    {
      label: compactOwaspLine(coverage),
      title: owaspTooltip(coverage),
    },
    {
      label: compactLlmLine(coverage),
      title: llmTooltip(coverage),
    },
  ];
}

export { LLM_FOCUS_LABELS };
