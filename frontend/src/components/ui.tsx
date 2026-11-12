import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock,
  FileCode2,
  GitBranch,
  HelpCircle,
  Loader2,
  LogOut,
  Plus,
  Settings,
  Shield,
  Trash2,
  Upload,
  XCircle,
  ArrowLeft,
} from "lucide-react";
import type { AiVerdict, FindingCategory, ExternalReviewStatus, ReviewStatus, ScanSummary, Severity } from "../api";
import { OWASP_COLORS, OWASP_TOP10, SUBTYPE_LABELS } from "../lib/owaspUtils";

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-sky-500 text-white",
  LOW: "bg-blue-500 text-white",
  INFO: "bg-slate-500 text-white",
  UNKNOWN: "bg-slate-600 text-white",
};

export const VERDICT_COLORS: Record<AiVerdict, string> = {
  real_vuln: "bg-red-500/20 text-red-400 border border-red-500/30",
  false_positive: "bg-green-500/20 text-green-400 border border-green-500/30",
  uncertain: "bg-sky-500/15 text-sky-300 border border-sky-500/25",
  pending: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
  skipped: "bg-slate-500/20 text-slate-500 border border-slate-500/30",
};

export const VERDICT_LABELS: Record<AiVerdict, string> = {
  real_vuln: "真实漏洞",
  false_positive: "误报",
  uncertain: "待确认",
  pending: "待分析",
  skipped: "已跳过",
};

export const REVIEW_COLORS: Record<ReviewStatus, string> = {
  unreviewed: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
  confirmed: "bg-red-500/20 text-red-400 border border-red-500/30",
  false_positive: "bg-green-500/20 text-green-400 border border-green-500/30",
  fixed: "bg-amber-500/20 text-amber-300 border border-amber-500/30",
};

export const REVIEW_LABELS: Record<ReviewStatus, string> = {
  unreviewed: "未标记",
  confirmed: "确认",
  false_positive: "误报",
  fixed: "已修复",
};

export const EXTERNAL_REVIEW_COLORS: Record<ExternalReviewStatus, string> = {
  unreviewed: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
  vuln_exists: "bg-red-500/20 text-red-400 border border-red-500/30",
  false_positive: "bg-green-500/20 text-green-400 border border-green-500/30",
  fixed_claimed: "bg-amber-500/20 text-amber-300 border border-amber-500/30",
};

export const EXTERNAL_REVIEW_LABELS: Record<ExternalReviewStatus, string> = {
  unreviewed: "外部未确认",
  vuln_exists: "外部: 漏洞存在",
  false_positive: "外部: 误报",
  fixed_claimed: "外部: 修复完成",
};

export const STATUS_LABELS: Record<ScanSummary["status"], string> = {
  pending: "等待中",
  cloning: "克隆中",
  scanning: "扫描中",
  analyzing: "AI 误报审计",
  llm_auditing: "LLM 端点审计",
  completed: "已完成",
  failed: "失败",
};

export const CATEGORY_LABELS: Record<FindingCategory, string> = {
  sast: "SAST",
  business_logic: "业务逻辑",
  authorization: "越权漏洞",
};

export const CATEGORY_COLORS: Record<FindingCategory, string> = {
  sast: "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  business_logic: "bg-purple-500/20 text-purple-400 border border-purple-500/30",
  authorization: "bg-orange-500/20 text-orange-400 border border-orange-500/30",
};

export function SubtypeBadge({
  subtype,
  subtypeName,
}: {
  subtype?: string | null;
  subtypeName?: string | null;
}) {
  if (!subtype) return null;
  const name = subtypeName || SUBTYPE_LABELS[subtype] || subtype;
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-slate-700/50 text-slate-300 border border-slate-600/50"
      title={name}
    >
      {name}
    </span>
  );
}

export function RiskTagBadge({ tag }: { tag: string }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-cyan-500/10 text-cyan-100 border border-cyan-500/25"
      title={tag}
    >
      {tag}
    </span>
  );
}

export function OwaspBadge({
  owaspId,
  owaspName,
  compact,
}: {
  owaspId?: string | null;
  owaspName?: string | null;
  compact?: boolean;
}) {
  if (!owaspId) return null;
  const cls = OWASP_COLORS[owaspId] || "bg-slate-500/20 text-slate-400 border border-slate-500/30";
  const name = owaspName || OWASP_TOP10[owaspId] || "";
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${cls}`}
      title={name ? `${owaspId}: ${name}` : owaspId}
    >
      <span>{owaspId}</span>
      {!compact && name && <span className="opacity-80 hidden sm:inline">{name}</span>}
    </span>
  );
}

export function StatusIcon({ status }: { status: ScanSummary["status"] }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="w-4 h-4 text-success" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-danger" />;
    case "pending":
    case "cloning":
    case "scanning":
    case "analyzing":
    case "llm_auditing":
      return <Loader2 className="w-4 h-4 text-accent animate-spin" />;
    default:
      return <Clock className="w-4 h-4 text-slate-400" />;
  }
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN}`}>{severity}</span>;
}

export function VerdictBadge({ verdict }: { verdict: AiVerdict }) {
  return <span className={`badge ${VERDICT_COLORS[verdict]}`}>{VERDICT_LABELS[verdict]}</span>;
}

export function CategoryBadge({ category }: { category: FindingCategory }) {
  return <span className={`badge ${CATEGORY_COLORS[category]}`}>{CATEGORY_LABELS[category]}</span>;
}

export function ReviewBadge({ status }: { status?: ReviewStatus | null }) {
  const s: ReviewStatus = status || "unreviewed";
  return <span className={`badge ${REVIEW_COLORS[s]}`}>{REVIEW_LABELS[s]}</span>;
}

export function InheritedFpBadge({ kind }: { kind: "strict" | "relaxed" }) {
  const label = kind === "strict" ? "继承误报" : "疑似重复";
  const cls =
    kind === "strict"
      ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
      : "bg-amber-500/15 text-amber-200 border border-amber-500/30";
  return <span className={`badge text-[10px] ${cls}`}>{label}</span>;
}

export function ExternalStatusBadge({ status }: { status?: ExternalReviewStatus | null }) {
  const s: ExternalReviewStatus = status || "unreviewed";
  return <span className={`badge ${EXTERNAL_REVIEW_COLORS[s]}`}>{EXTERNAL_REVIEW_LABELS[s]}</span>;
}

interface ReviewMarkButtonsProps {
  current?: ReviewStatus | null;
  onMark: (status: ReviewStatus) => void;
  disabled?: boolean;
  compact?: boolean;
}

export function ReviewMarkButtons({ current, onMark, disabled, compact }: ReviewMarkButtonsProps) {
  const items: { status: ReviewStatus; label: string; active: string }[] = [
    { status: "unreviewed", label: "未标记", active: "bg-slate-500/20 text-slate-300 border border-slate-500/30" },
    { status: "confirmed", label: "确认", active: "bg-red-500/30 border-red-500/50 text-red-300" },
    { status: "false_positive", label: "误报", active: "bg-green-500/30 border-green-500/50 text-green-300" },
    { status: "fixed", label: "已修复", active: "bg-amber-500/30 border-amber-500/50 text-amber-200" },
  ];
  return (
    <div className={`flex ${compact ? "flex-col" : "flex-row"} gap-1`}>
      {items.map((item) => (
        <button
          key={item.status}
          type="button"
          disabled={disabled}
          onClick={() => onMark(item.status)}
          className={`text-xs px-2 py-1 rounded border border-surface-border transition-colors disabled:opacity-50 ${
            current === item.status ? item.active : "hover:bg-surface text-slate-400"
          }`}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

export function SourceIcon({ source }: { source: ScanSummary["source"] }) {
  if (source === "gitlab") return <GitBranch className="w-4 h-4" />;
  return <Upload className="w-4 h-4" />;
}

interface ToolbarButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  running?: boolean;
  danger?: boolean;
}

export function ToolbarButton({
  running = false,
  danger = false,
  className = "",
  children,
  ...props
}: ToolbarButtonProps) {
  return (
    <button
      type="button"
      className={[
        "btn-action",
        running ? "btn-action-running" : "",
        danger ? "btn-action-danger" : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      {...props}
    >
      {children}
    </button>
  );
}

export { Shield, Plus, Settings, BarChart3, FileCode2, AlertTriangle, Trash2, HelpCircle, GitBranch, Upload, LogOut, ArrowLeft };
