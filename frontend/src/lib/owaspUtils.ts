export const OWASP_TOP10: Record<string, string> = {
  A01: "访问控制失效",
  A02: "加密机制失效",
  A03: "注入",
  A04: "不安全设计",
  A05: "安全配置错误",
  A06: "易受攻击和过时的组件",
  A07: "身份识别和身份验证失败",
  A08: "软件和数据完整性失效",
  A09: "安全日志和监控失效",
  A10: "服务端请求伪造 (SSRF)",
};

export const OWASP_COLORS: Record<string, string> = {
  A01: "bg-rose-500/20 text-rose-300 border border-rose-500/30",
  A02: "bg-sky-500/15 text-sky-300 border border-sky-500/25",
  A03: "bg-red-500/20 text-red-300 border border-red-500/30",
  A04: "bg-purple-500/20 text-purple-300 border border-purple-500/30",
  A05: "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  A06: "bg-sky-500/10 text-sky-200 border border-sky-500/20",
  A07: "bg-pink-500/20 text-pink-300 border border-pink-500/30",
  A08: "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30",
  A09: "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30",
  A10: "bg-teal-500/20 text-teal-300 border border-teal-500/30",
};

export const OWASP_CHART_COLORS: Record<string, string> = {
  A01: "#f43f5e",
  A02: "#f59e0b",
  A03: "#ef4444",
  A04: "#a855f7",
  A05: "#f97316",
  A06: "#eab308",
  A07: "#ec4899",
  A08: "#6366f1",
  A09: "#06b6d4",
  A10: "#14b8a6",
};

export const OWASP_ORDER = [
  "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10",
] as const;

export const INJECTION_SUBTYPES = [
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

export const SUBTYPE_LABELS: Record<string, string> = {
  sql_injection: "SQL 注入",
  xss: "XSS 跨站脚本",
  command_injection: "命令注入",
  ldap_injection: "LDAP 注入",
  xpath_injection: "XPath 注入",
  nosql_injection: "NoSQL 注入",
  ssti: "模板注入 (SSTI)",
  header_injection: "Header 注入",
  code_injection: "代码注入",
  xml_injection: "XML 注入",
  expression_injection: "表达式注入",
  log_injection: "日志注入",
  other_injection: "其他注入",
  path_traversal: "路径遍历",
  idor: "IDOR / 越权访问",
  open_redirect: "开放重定向",
  csrf: "CSRF",
  broken_access_control: "访问控制缺陷",
  hardcoded_secret: "硬编码密钥",
  weak_crypto: "弱加密",
  security_misconfiguration: "安全配置错误",
  vulnerable_dependency: "脆弱依赖",
  auth_failure: "认证失效",
  deserialization: "不安全反序列化",
  ssrf: "SSRF",
  other: "其他",
};

export const OWASP_SUBTYPES: Record<string, readonly string[]> = {
  A01: ["path_traversal", "idor", "open_redirect", "csrf", "broken_access_control"],
  A02: ["hardcoded_secret", "weak_crypto"],
  A03: INJECTION_SUBTYPES,
  A05: ["security_misconfiguration"],
  A06: ["vulnerable_dependency"],
  A07: ["auth_failure"],
  A08: ["deserialization"],
  A10: ["ssrf"],
};

export function subtypesForOwasp(owaspId: string): readonly string[] {
  return OWASP_SUBTYPES[owaspId] || [];
}

export function subtypeLabel(id?: string | null, name?: string | null): string {
  if (!id) return "";
  return name || SUBTYPE_LABELS[id] || id;
}

export function owaspLabel(id?: string | null, name?: string | null): string {
  if (!id) return "未分类";
  const label = name || OWASP_TOP10[id] || id;
  return `${id} ${label}`;
}
