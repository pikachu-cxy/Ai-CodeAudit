import type { ProjectSummary, ScanScore, ScanStats, ScanSummary } from "../api";
import { api } from "../api";
import { formatScanLanguages } from "../lib/scanLanguages";
import { Pencil } from "lucide-react";
import { StatusIcon, STATUS_LABELS } from "./ui";
import { SCAN_KIND_LABELS } from "./ScanHistoryPanel";
import { useState } from "react";
import { ReportBuilderModal, type ReportFilterDraft } from "./ReportBuilderModal";

interface Props {
  scan: ScanSummary;
  stats: ScanStats | null;
  score?: ScanScore | null;
  project?: ProjectSummary | null;
  onEdit?: () => void;
  /** 列表页已勾选的漏洞 ID，用于「生成报告」默认范围 */
  selectedFindingIds?: number[];
  /** 列表页当前筛选条件快照 */
  reportFilterDraft?: ReportFilterDraft;
}

function scoreAccent(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-300";
  return "text-red-400";
}

export function AuditReportHeader({
  scan,
  stats,
  score,
  project,
  onEdit,
  selectedFindingIds,
  reportFilterDraft,
}: Props) {
  const [downloading, setDownloading] = useState<"" | "html" | "pdf" | "md" | "json">("");
  const [scoreOpen, setScoreOpen] = useState(false);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [quickOpen, setQuickOpen] = useState(false);
  const selectedIds = selectedFindingIds ?? [];
  const critical = stats?.by_severity?.CRITICAL ?? 0;
  const high = stats?.by_severity?.HIGH ?? 0;
  const medium = stats?.by_severity?.MEDIUM ?? 0;
  const total = stats?.total ?? scan.total_findings;
  const securityScore =
    score?.score ?? stats?.security_score ?? scan.security_score ?? null;

  const created = scan.created_at ? new Date(scan.created_at).toLocaleString("zh-CN") : "—";
  const completed = scan.completed_at ? new Date(scan.completed_at).toLocaleString("zh-CN") : "—";
  const title = project?.name || scan.name;
  const version = scan.version_label;
  const kind = scan.scan_kind || "baseline";
  const notes = project?.notes || scan.notes;
  const notifyEmails = scan.notify_emails?.filter(Boolean) ?? [];
  const detected =
    scan.detected_languages?.length
      ? scan.detected_languages
      : project?.detected_languages ?? [];
  const scanScope = project?.scan_languages?.length ? project.scan_languages : null;

  return (
    <header className="audit-panel p-6 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-500/80">Security Audit Report</p>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <h1 className="text-2xl font-bold text-white">{title}</h1>
            {version && (
              <span className="text-xs px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 font-mono">
                {version}
              </span>
            )}
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/30 text-slate-400">
              {SCAN_KIND_LABELS[kind]}
            </span>
            {onEdit && (
              <button
                type="button"
                title="编辑项目"
                className="p-1.5 rounded text-slate-500 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                onClick={onEdit}
              >
                <Pencil className="w-4 h-4" />
              </button>
            )}
          </div>
          {(detected.length > 0 || scanScope) && (
            <div className="flex flex-wrap items-center gap-1.5 mt-2">
              {detected.map((d) => (
                <span
                  key={d.id}
                  className={`text-[11px] px-2 py-0.5 rounded border ${
                    d.primary
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                      : "border-surface-border text-slate-400"
                  }`}
                  title={`${d.file_count} 个源文件`}
                >
                  {d.label}
                </span>
              ))}
              {scanScope && (
                <span className="text-[11px] text-slate-500 ml-1">
                  扫描范围：{formatScanLanguages(scanScope)}
                </span>
              )}
            </div>
          )}
          {scan.name !== title && (
            <p className="text-xs text-slate-500 mt-1 font-mono">扫描：{scan.name}</p>
          )}
          {notes && (
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">{notes}</p>
          )}
          <p className="text-sm text-slate-500 mt-2 max-w-2xl">
            方法论: <span className="text-slate-400">静态代码分析 (Semgrep)</span>
            {" + "}
            <span className="text-slate-400">污点数据流 LLM 研判</span>
            {" + "}
            <span className="text-slate-400">LLM 自主端点深度审计</span>
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <StatusIcon status={scan.status} />
          <span className="text-slate-400">{STATUS_LABELS[scan.status]}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {securityScore != null && (
          <button
            type="button"
            className="text-left rounded-lg bg-black/25 border border-surface-border/80 px-3 py-2 hover:border-cyan-500/30 transition-colors"
            onClick={() => setScoreOpen((v) => !v)}
            title="点击查看扣分明细"
          >
            <p className="text-[10px] uppercase tracking-wider text-slate-600">安全分</p>
            <p className={`text-lg font-semibold mt-0.5 font-mono ${scoreAccent(securityScore)}`}>
              {securityScore}
              <span className="text-xs text-slate-500 font-normal"> / {score?.max_score ?? 100}</span>
            </p>
          </button>
        )}
        <StatCard label="总计" value={String(total)} accent="text-white" />
        <StatCard label="Critical" value={String(critical)} accent="text-red-400" />
        <StatCard label="High" value={String(high)} accent="text-orange-400" />
        <StatCard label="Medium" value={String(medium)} accent="text-sky-300" />
        <StatCard label="创建" value={created.split(" ")[0]} accent="text-slate-400" small />
        <StatCard label="完成" value={completed === "—" ? "—" : completed.split(" ")[0]} accent="text-slate-400" small />
      </div>

      {scoreOpen && score && (
        <div className="rounded-lg border border-cyan-500/15 bg-black/20 px-4 py-3 text-xs text-slate-400 space-y-2">
          <p>
            公式：满分 {score.max_score} − Σ(数量 × 权重)，下限 0
            {score.exclude_ai_fp ? "；已排除人工/AI 误报" : "；已排除人工误报"}
            。计入 {score.counted_findings} 条，排除 {score.excluded_findings} 条
            {score.has_critical ? "；含 Critical" : ""}。
          </p>
          {score.deduction_detail.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {score.deduction_detail.map((d) => (
                <span
                  key={d.severity}
                  className="px-2 py-1 rounded border border-surface-border/60 bg-black/30 font-mono"
                >
                  {d.severity}: {d.count} × {d.weight} = −{d.deduction}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-slate-500">无扣分项</p>
          )}
        </div>
      )}

      {total > 0 && (
        <p className="text-sm text-slate-400 border-t border-cyan-500/10 pt-3">
          审计摘要: 共 <span className="text-white font-medium">{total}</span> 条发现，
          其中 <span className="text-red-400 font-medium">{critical}</span> 严重、
          <span className="text-orange-400 font-medium"> {high}</span> 高危。
          建议优先处理已确认 (Confirmed) 且 AI 判定为真实漏洞的项。
        </p>
      )}

      <div className="flex flex-wrap items-center gap-3 border-t border-cyan-500/10 pt-3 text-xs">
        {scan.status === "completed" && (
          <>
            <button
              type="button"
              className="btn-primary text-xs"
              onClick={() => setBuilderOpen(true)}
            >
              生成报告
            </button>
            {selectedIds.length > 0 && (
              <span className="text-cyan-300">
                将默认导出已勾选的 {selectedIds.length} 条
              </span>
            )}
            <button
              type="button"
              className="btn-ghost text-xs"
              onClick={() => setQuickOpen((v) => !v)}
            >
              {quickOpen ? "收起快速导出" : "快速导出全量"}
            </button>
            {quickOpen && (
              <>
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  onClick={() => api.openScanReport(scan.id).catch((e) => alert(String(e)))}
                >
                  查看 HTML 报告
                </button>
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  disabled={!!downloading}
                  onClick={async () => {
                    setDownloading("html");
                    try {
                      await api.downloadScanReportHtml(scan.id);
                    } catch (e) {
                      alert(String(e));
                    } finally {
                      setDownloading("");
                    }
                  }}
                >
                  {downloading === "html" ? "下载中..." : "下载 HTML 报告"}
                </button>
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  disabled={!!downloading}
                  onClick={async () => {
                    setDownloading("pdf");
                    try {
                      await api.downloadScanReportPdf(scan.id);
                    } catch (e) {
                      alert(String(e));
                    } finally {
                      setDownloading("");
                    }
                  }}
                >
                  {downloading === "pdf" ? "下载中..." : "下载 PDF"}
                </button>
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  disabled={!!downloading}
                  onClick={async () => {
                    setDownloading("md");
                    try {
                      await api.downloadScanReportMarkdown(scan.id);
                    } catch (e) {
                      alert(String(e));
                    } finally {
                      setDownloading("");
                    }
                  }}
                >
                  {downloading === "md" ? "下载中..." : "下载 Markdown（AI）"}
                </button>
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  disabled={!!downloading}
                  onClick={async () => {
                    setDownloading("json");
                    try {
                      await api.downloadScanReportJson(scan.id);
                    } catch (e) {
                      alert(String(e));
                    } finally {
                      setDownloading("");
                    }
                  }}
                >
                  {downloading === "json" ? "下载中..." : "下载 JSON（AI）"}
                </button>
              </>
            )}
          </>
        )}
        {notifyEmails.length > 0 && (
          <span className="text-slate-500">
            报告收件人：<span className="text-slate-400 font-mono">{notifyEmails.join(", ")}</span>
          </span>
        )}
      </div>

      <ReportBuilderModal
        open={builderOpen}
        scanId={scan.id}
        projectName={project?.name ?? null}
        scanName={scan.name}
        scanTotal={total}
        selectedIds={selectedIds}
        filterDraft={reportFilterDraft ?? {}}
        onClose={() => setBuilderOpen(false)}
      />
    </header>
  );
}

function StatCard({
  label,
  value,
  accent,
  small,
}: {
  label: string;
  value: string;
  accent: string;
  small?: boolean;
}) {
  return (
    <div className="rounded-lg bg-black/25 border border-surface-border/80 px-3 py-2">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
      <p className={`${small ? "text-xs" : "text-lg"} font-semibold mt-0.5 font-mono ${accent}`}>{value}</p>
    </div>
  );
}
