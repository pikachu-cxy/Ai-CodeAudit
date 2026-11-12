import type { Finding } from "../api";

export function parseMetadata(raw?: string | null): Record<string, any> {
  if (!raw) return {};
  try {
    const obj = JSON.parse(raw);
    return typeof obj === "object" && obj ? obj : {};
  } catch {
    return {};
  }
}

export const RISK_TAG_LABELS: Record<string, string> = {
  ssrf: "SSRF",
  prompt_injection: "Prompt 注入",
  agent_tool_abuse: "Agent 工具滥用",
  sensitive_data_exposure: "敏感数据泄露",
  injection: "注入",
  rce: "命令执行/RCE",
  deserialization: "不安全反序列化",
  business_flow: "业务流程绕过",
  race_condition: "竞态条件",
  rate_limit: "频控缺失",
  session: "会话失效",
  jwt: "JWT 风险",
  authz: "访问控制",
  idor: "IDOR",
  privilege_escalation: "权限提升",
  mass_assignment: "批量赋值",
  access_control: "访问控制",
  insecure_default: "不安全默认值",
  crypto_misuse: "加解密误用",
  supply_chain: "依赖/供应链",
  message_trust: "消息来源不可信",
  idempotency: "幂等缺失",
  internal_trust: "内部接口默认信任",
};

export function parseRiskTags(metadata_json?: string | null): string[] {
  const md = parseMetadata(metadata_json);
  const raw = md.risk_tags;
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const item of raw) {
    const tag = String(item || "").trim();
    if (!tag || seen.has(tag)) continue;
    seen.add(tag);
    tags.push(tag);
  }
  return tags;
}

export function riskTagLabel(tag: string): string {
  return RISK_TAG_LABELS[tag] || tag;
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

export interface PropertyTuple {
  source: string;
  sink: string;
  missingGuard: string;
  impact: string;
}

export function parseVerificationPoc(metadata_json?: string | null): VerificationPoc | null {
  if (!metadata_json) return null;
  try {
    const obj = JSON.parse(metadata_json);
    const poc = obj?.verification_poc;
    return poc && typeof poc === "object" ? (poc as VerificationPoc) : null;
  } catch {
    return null;
  }
}

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;

export function emptyPocHttpRequest(): PocHttpRequest {
  return { method: "GET", url: "", headers: {}, body: "" };
}

export function headersToText(headers: Record<string, string> | undefined): string {
  if (!headers) return "";
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

export function textToHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.includes(":")) continue;
    const idx = trimmed.indexOf(":");
    const name = trimmed.slice(0, idx).trim();
    if (!name) continue;
    headers[name] = trimmed.slice(idx + 1).trim();
  }
  return headers;
}

export function requestToCurl(req: PocHttpRequest): string {
  const parts = ["curl", "-i", "-X", req.method || "GET"];
  for (const [name, value] of Object.entries(req.headers || {})) {
    parts.push("-H", `${name}: ${value}`);
  }
  if (req.body) {
    parts.push("--data-raw", req.body);
  }
  if (req.url) parts.push(req.url);
  return parts.join(" ");
}

function unquote(value: string): string {
  const t = value.trim();
  if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) {
    return t.slice(1, -1);
  }
  return t;
}

export function parsePocContentToRequest(text: string): PocHttpRequest | null {
  const raw = text.trim();
  if (!raw) return null;
  const compact = raw.replace(/\\\r?\n/g, " ");
  if (/^\s*curl(\.exe)?\b/i.test(compact)) {
    const tokens = compact.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    let method = "GET";
    let url = "";
    const headers: Record<string, string> = {};
    let body = "";
    for (let i = 1; i < tokens.length; i++) {
      const tok = unquote(tokens[i]);
      const nxt = tokens[i + 1] ? unquote(tokens[i + 1]) : "";
      if ((tok === "-X" || tok === "--request") && nxt) {
        method = nxt.toUpperCase();
        i += 1;
        continue;
      }
      if ((tok === "-H" || tok === "--header") && nxt) {
        const colon = nxt.indexOf(":");
        if (colon > 0) headers[nxt.slice(0, colon).trim()] = nxt.slice(colon + 1).trim();
        i += 1;
        continue;
      }
      if (["-d", "--data", "--data-raw", "--data-binary", "--json"].includes(tok) && nxt) {
        body = nxt;
        if (tok === "--json") headers["Content-Type"] = headers["Content-Type"] || "application/json";
        if (method === "GET") method = "POST";
        i += 1;
        continue;
      }
      if (tok.startsWith("http://") || tok.startsWith("https://")) {
        url = tok;
      }
    }
    if (!url) return null;
    return { method: HTTP_METHODS.includes(method as (typeof HTTP_METHODS)[number]) ? method : "GET", url, headers, body };
  }
  const first = raw.split(/\r?\n/)[0]?.trim() || "";
  const httpLine = first.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i);
  if (httpLine) {
    return { method: httpLine[1].toUpperCase(), url: httpLine[2], headers: {}, body: "" };
  }
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith("http://") || t.startsWith("https://")) {
      return { method: "GET", url: t.split(/\s+/)[0], headers: {}, body: "" };
    }
  }
  return null;
}

export function seedHttpRequest(poc: VerificationPoc | null, apiEndpoint?: string | null): PocHttpRequest {
  const stored = poc?.http_request;
  if (stored && String(stored.url || "").trim()) {
    return {
      method: String(stored.method || "GET").toUpperCase() || "GET",
      url: String(stored.url || "").trim(),
      headers: stored.headers && typeof stored.headers === "object" ? { ...stored.headers } : {},
      body: String(stored.body || ""),
    };
  }
  const parsed = parsePocContentToRequest(poc?.poc_content || "");
  if (parsed?.url) return parsed;
  const ep = String(apiEndpoint || "").trim();
  if (ep && !["unknown", "n/a", "-"].includes(ep.toLowerCase())) {
    const parts = ep.split(/\s+/, 2);
    const maybeMethod = parts[0]?.toUpperCase() || "";
    if (HTTP_METHODS.includes(maybeMethod as (typeof HTTP_METHODS)[number])) {
      return { method: maybeMethod, url: parts[1] || "", headers: {}, body: "" };
    }
    return { method: "GET", url: ep.startsWith("/") || ep.includes("://") ? ep : `/${ep}`, headers: {}, body: "" };
  }
  return emptyPocHttpRequest();
}

function pickNonEmpty(...values: unknown[]): string {
  for (const v of values) {
    const s = String(v ?? "").trim();
    if (s) return s;
  }
  return "";
}

function firstLine(text: string): string {
  const t = text.trim();
  if (!t) return "";
  return t.split(/\r?\n/)[0]?.trim() || "";
}

function inferSourceFromReason(reason: string): string {
  const m = reason.match(/(?:来源|source)\s*[:：]\s*([^\n]+)/i);
  return m?.[1]?.trim() || "";
}

function inferSinkFromReason(reason: string): string {
  const m = reason.match(/(?:接口|sink|触发点)\s*[:：]\s*([^\n]+)/i);
  return m?.[1]?.trim() || "";
}

function inferImpactFromReason(reason: string): string {
  const m = reason.match(/(?:攻击场景|impact|后果)\s*[:：]\s*([^\n]+)/i);
  return m?.[1]?.trim() || "";
}

export function extractPropertyTuple(finding: Finding): PropertyTuple | null {
  const md = parseMetadata(finding.metadata_json);
  const reason = String(finding.ai_reason || "");
  const source = pickNonEmpty(md.data_source, inferSourceFromReason(reason));
  const sink = pickNonEmpty(md.trigger_point, md.api_endpoint, inferSinkFromReason(reason));
  const missingGuard = pickNonEmpty(md.description, firstLine(reason), displayMessage(finding));
  const impact = pickNonEmpty(md.attack_scenario, inferImpactFromReason(reason), finding.message_zh, finding.message);

  if (!source && !sink && !missingGuard && !impact) return null;
  return { source, sink, missingGuard, impact };
}

export function displayMessage(f: Finding): string {
  return f.message_zh || f.message;
}

/** In-repo path for display; never show host machine directories like C:\\Users\\...\\data\\repos\\... */
export function repoRelativePath(filePath: string): string {
  let p = (filePath || "").replace(/\\/g, "/").trim();
  if (!p) return "";
  p = p.replace(/^[A-Za-z]:/, "");
  p = p.replace(/^\/+/, "");
  const repos = p.match(/(?:^|\/)(?:(?:backend\/)?data\/)?repos\/[^/]+\/(.+)$/i);
  if (repos?.[1]) return repos[1];
  const uploads = p.match(/(?:^|\/)(?:(?:backend\/)?data\/)?uploads\/[^/]+\/[^/]+\/(.+)$/i);
  if (uploads?.[1]) return uploads[1];
  return p;
}

export function shortPath(filePath: string): string {
  return repoRelativePath(filePath);
}

export type FlowNodeKind = "endpoint" | "source" | "flow" | "trigger" | "location" | "step";

export interface CodeTarget {
  filePath: string;
  lineStart: number;
  lineEnd: number;
  searchText?: string;
}

export interface FlowNode {
  id: string;
  kind: FlowNodeKind;
  label: string;
  detail: string;
  target?: CodeTarget;
}

const HTTP_METHOD_RE = /^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b/i;
const ABSTRACT_FLOW_RE =
  /^(unknown|source|sink|validate|authn|authz|鉴权|校验|请求参数|敏感操作|service|controller|dao|repository)$/i;

function parsePathLine(text: string, defaultFile: string): CodeTarget | undefined {
  const m = text.match(/((?:[A-Za-z]:)?[^\s:|]+?\.\w+):(\d+)(?:-(\d+))?/);
  if (!m) return undefined;
  const lineStart = parseInt(m[2], 10);
  const lineEnd = parseInt(m[3] || m[2], 10);
  const pathPart = m[1];
  return {
    filePath: pathPart.includes("/") || pathPart.includes("\\") ? pathPart : defaultFile,
    lineStart,
    lineEnd,
  };
}

function parseSnippetTargets(snippet: string | null | undefined, defaultFile: string): CodeTarget[] {
  if (!snippet) return [];
  const targets: CodeTarget[] = [];
  const re = /^>>>\s+(\d+)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(snippet)) !== null) {
    const line = parseInt(m[1], 10);
    if (line > 0) {
      targets.push({ filePath: defaultFile, lineStart: line, lineEnd: line });
    }
  }
  return targets;
}

function splitFlowSegments(flow: string): string[] {
  return flow
    .split(/\s*(?:->|→|=>|➜)\s*/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function extractHttpRoute(text: string): string | undefined {
  const trimmed = text.trim();
  const methodMatch = trimmed.match(
    /(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\/[\w/.{}:*-]+)/i,
  );
  if (methodMatch) return methodMatch[1];
  if (/^\/[\w/.{}:*-]+$/.test(trimmed)) return trimmed;
  return undefined;
}

function isHttpRouteText(text: string): boolean {
  const trimmed = text.trim();
  if (/^unknown$/i.test(trimmed)) return false;
  if (HTTP_METHOD_RE.test(trimmed) && /\/[\w/.{}:*-]/.test(trimmed)) return true;
  if (/^\/[\w/.{}:*-]+$/.test(trimmed)) return true;
  if (/^@\w+Mapping\b/i.test(trimmed)) return true;
  return false;
}

function isAbstractFlowLabel(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed || /^unknown$/i.test(trimmed)) return true;
  if (ABSTRACT_FLOW_RE.test(trimmed)) return true;
  if (/^(GET|POST|PUT|DELETE|PATCH)\s*$/i.test(trimmed)) return true;
  return false;
}

function searchTarget(filePath: string, query: string): CodeTarget {
  return {
    filePath,
    lineStart: 0,
    lineEnd: 0,
    searchText: query,
  };
}

function targetFromText(text: string, defaultFile: string): CodeTarget | undefined {
  const trimmed = text.trim();
  if (!trimmed || isAbstractFlowLabel(trimmed)) return undefined;

  const fromPath = parsePathLine(trimmed, defaultFile);
  if (fromPath) return fromPath;

  const lineOnly = trimmed.match(/^(?:L|line\s*)(\d+)$/i);
  if (lineOnly) {
    const line = parseInt(lineOnly[1], 10);
    return { filePath: defaultFile, lineStart: line, lineEnd: line };
  }

  if (isHttpRouteText(trimmed)) {
    const route = extractHttpRoute(trimmed);
    return searchTarget(defaultFile, route || trimmed);
  }

  if (trimmed.length >= 2) {
    return searchTarget(defaultFile, trimmed);
  }
  return undefined;
}

/** Split "path/File.java:42 | GET /api/foo" into code ref + route label. */
function splitEndpointField(raw: string): { route: string; codeRef?: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { route: "" };

  const pipeParts = trimmed.split(/\s*\|\s*/);
  if (pipeParts.length >= 2) {
    const codeRef = pipeParts[0].trim();
    const route = pipeParts.slice(1).join(" | ").trim();
    if (parsePathLine(codeRef, "") || /\.\w+:\d+/.test(codeRef)) {
      return { route: route || trimmed, codeRef };
    }
  }

  const pathLine = parsePathLine(trimmed, "");
  if (pathLine && HTTP_METHOD_RE.test(trimmed)) {
    const route = trimmed.replace(/((?:[A-Za-z]:)?[^\s:|]+?\.\w+):(\d+)(?:-(\d+))?\s*/g, "").trim();
    return { route: route || trimmed, codeRef: trimmed.match(/((?:[A-Za-z]:)?[^\s:|]+?\.\w+):(\d+)/)?.[0] };
  }

  return { route: trimmed };
}

function endpointTarget(
  apiEndpoint: string,
  endpointCodeRef: string | undefined,
  defaultFile: string,
): CodeTarget | undefined {
  const codeRef = endpointCodeRef?.trim() || splitEndpointField(apiEndpoint).codeRef;
  if (codeRef) {
    const parsed = parsePathLine(codeRef, defaultFile);
    if (parsed) return parsed;
  }

  const { route } = splitEndpointField(apiEndpoint);
  if (!route || /^unknown$/i.test(route)) return undefined;

  if (isHttpRouteText(route)) {
    const path = extractHttpRoute(route);
    return searchTarget(defaultFile, path || route);
  }

  return targetFromText(route, defaultFile);
}

export function buildFlowNodes(finding: Finding): FlowNode[] {
  const md = parseMetadata(finding.metadata_json);
  const defaultFile = finding.file_path;
  const sinkLine = finding.line_start || 1;
  const sinkEnd = finding.line_end || sinkLine;
  const nodes: FlowNode[] = [];

  const addNode = (
    id: string,
    kind: FlowNodeKind,
    label: string,
    detail: string,
    target?: CodeTarget,
  ) => {
    if (!detail) return;
    nodes.push({ id, kind, label, detail, target });
  };

  if (md.api_endpoint) {
    const { route } = splitEndpointField(md.api_endpoint);
    addNode(
      "endpoint",
      "endpoint",
      "接口",
      route || md.api_endpoint,
      endpointTarget(md.api_endpoint, md.endpoint_code_ref, defaultFile),
    );
  }

  if (Array.isArray(md.flow_steps) && md.flow_steps.length > 0) {
    md.flow_steps.forEach((step: { file?: string; line?: number; label?: string; kind?: string }, i: number) => {
      if (!step || typeof step !== "object") return;
      const kind = String(step.kind || "propagation").toLowerCase();
      const label =
        kind === "source" ? "Source" : kind === "sink" ? "Sink" : `传播 ${i + 1}`;
      const detail = [step.label, step.file && step.line ? `${shortPath(step.file)}:${step.line}` : step.file]
        .filter(Boolean)
        .join(" · ");
      if (!detail) return;
      addNode(
        `recon-${i}`,
        kind === "source" ? "source" : kind === "sink" ? "trigger" : "flow",
        md.flow_reconstructed ? `AI追认·${label}` : label,
        detail,
        step.file
          ? { filePath: String(step.file), lineStart: Number(step.line) || 1, lineEnd: Number(step.line) || 1 }
          : undefined,
      );
    });
  } else if (md.data_flow_chain || md.data_flow_summary) {
    addNode(
      "sast-flow",
      "flow",
      md.flow_reconstructed ? "AI 重构数据流" : "SAST 污点流",
      md.data_flow_summary || md.data_flow_chain,
      undefined,
    );
  }

  if (md.data_source) {
    addNode(
      "source",
      "source",
      "数据来源",
      md.data_source,
      targetFromText(md.data_source, defaultFile),
    );
  }

  if (md.data_flow) {
    const segments = splitFlowSegments(md.data_flow);
    if (segments.length > 1) {
      segments.forEach((seg, i) => {
        addNode(
          `flow-${i}`,
          "flow",
          i === 0 ? "链路起点" : i === segments.length - 1 ? "链路终点" : `链路 ${i + 1}`,
          seg,
          targetFromText(seg, defaultFile),
        );
      });
    } else {
      addNode(
        "flow",
        "flow",
        "数据链路",
        md.data_flow,
        targetFromText(md.data_flow, defaultFile),
      );
    }
  }

  if (md.trigger_point) {
    addNode(
      "trigger",
      "trigger",
      "触发点",
      md.trigger_point,
      targetFromText(md.trigger_point, defaultFile),
    );
  }

  const snippetTargets = parseSnippetTargets(finding.code_snippet, defaultFile);
  snippetTargets.forEach((t, i) => {
    addNode(
      `snippet-${i}`,
      "step",
      snippetTargets.length > 1 ? `证据行 ${i + 1}` : "扫描证据",
      `${shortPath(t.filePath)}:${t.lineStart}`,
      t,
    );
  });

  addNode(
    "location",
    "location",
    "漏洞位置",
    `${shortPath(defaultFile)}:${sinkLine}`,
    { filePath: defaultFile, lineStart: sinkLine, lineEnd: sinkEnd },
  );

  if (nodes.length === 1) {
    return nodes;
  }

  const seen = new Set<string>();
  return nodes.filter((n) => {
    const key = n.target
      ? `${n.target.filePath}:${n.target.lineStart}:${n.target.searchText || ""}`
      : n.detail;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function targetLabel(target?: CodeTarget): string | null {
  if (!target) return null;
  if (target.searchText) {
    return `搜索: ${target.searchText.slice(0, 48)}`;
  }
  if (!target.lineStart || target.lineStart < 1) return null;
  return `${shortPath(target.filePath)}:${target.lineStart}`;
}
