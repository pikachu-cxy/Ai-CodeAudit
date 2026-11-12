import type { Finding } from "../api";
import { displayMessage, parseMetadata } from "../lib/findingUtils";

export function vulnDisplayId(findingId: number): string {
  return `VULN-${String(findingId).padStart(3, "0")}`;
}

export function authRequirementLabel(f: Finding): string {
  if (f.category === "authorization") return "需鉴权/授权";
  const md = parseMetadata(f.metadata_json);
  if (md.api_endpoint && !/^unknown$/i.test(String(md.api_endpoint))) {
    return "接口层 (见端点)";
  }
  if (f.vuln_subtype === "idor" || f.vuln_subtype === "broken_access_control") {
    return "需登录 + 归属校验";
  }
  if (f.category === "business_logic") return "视业务会话";
  if (f.rule_id?.toLowerCase().includes("unauth")) return "可能无需登录";
  return "待研判";
}

export function exploitabilityLabel(f: Finding): string {
  if (f.ai_verdict === "real_vuln") return "AI: 真实漏洞";
  if (f.ai_verdict === "false_positive") return "AI: 误报";
  if (f.ai_verdict === "uncertain") return "AI: 待确认";
  if (f.ai_verdict === "pending") return "AI: 待分析";
  if (f.ai_verdict === "skipped") return "AI: 已跳过";
  return "AI: 待分析";
}

export function auditStatusLabel(f: Finding): { label: string; tone: string } {
  if (f.review_status === "confirmed") return { label: "确认", tone: "text-red-400 bg-red-500/10 border-red-500/30" };
  if (f.review_status === "false_positive") return { label: "误报", tone: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" };
  if (f.review_status === "fixed") return { label: "已修复", tone: "text-amber-300 bg-amber-500/10 border-amber-500/30" };
  if (f.ai_verdict === "real_vuln") return { label: "待标记（AI: 真实）", tone: "text-orange-400 bg-orange-500/10 border-orange-500/30" };
  return { label: "未标记", tone: "text-slate-400 bg-slate-500/10 border-slate-500/30" };
}

export function findingTitle(f: Finding): string {
  return displayMessage(f);
}
