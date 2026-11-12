export const LLM_AUDIT_FOCUS_OPTIONS: { id: string; label: string; hint: string }[] = [
  { id: "authz", label: "越权 / 鉴权", hint: "IDOR、权限提升、会话" },
  { id: "business_logic", label: "业务逻辑", hint: "支付/积分/状态机/资损" },
  { id: "ai_prompt", label: "AI / Prompt 注入", hint: "Agent、工具滥用" },
  { id: "injection", label: "注入类", hint: "SQL/命令/表达式等（端点可达）" },
  { id: "rce_command", label: "命令执行 / RCE", hint: "从端点反推 exec/ProcessBuilder" },
  { id: "deserialization", label: "不安全反序列化", hint: "从端点反推反序列化 sink" },
  { id: "ssrf", label: "SSRF / 外联", hint: "URL/回调目标限制" },
  { id: "sensitive_data", label: "敏感数据泄露", hint: "日志、回显、过度披露" },
];

export const LLM_FOCUS_LABELS: Record<string, string> = Object.fromEntries(
  LLM_AUDIT_FOCUS_OPTIONS.map((o) => [o.id, o.label]),
);

export function normalizeFocusAreas(raw: unknown): string[] {
  const allowed = new Set(LLM_AUDIT_FOCUS_OPTIONS.map((o) => o.id));
  const values = Array.isArray(raw) ? raw : [];
  const cleaned: string[] = [];
  const seen = new Set<string>();
  for (const item of values) {
    const key = String(item || "").trim().toLowerCase();
    if (!allowed.has(key) || seen.has(key)) continue;
    seen.add(key);
    cleaned.push(key);
  }
  return cleaned;
}
