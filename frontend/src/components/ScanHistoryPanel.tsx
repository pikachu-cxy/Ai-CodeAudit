import type { ScanSummary, ScanStatus } from "../api";
import { STATUS_LABELS, StatusIcon } from "./ui";
import {
  historyCoverageChips,
  resolveScanCoverage,
} from "../lib/scanCoverageUtils";

export const SCAN_KIND_LABELS: Record<import("../api").ScanKind, string> = {
  baseline: "基线",
  retest: "复测",
  ad_hoc: "追加",
};

export const DIFF_STATUS_LABELS: Record<string, string> = {
  fixed: "已修复",
  regressed: "恶化",
  new: "新增",
  unchanged: "仍存在",
};

interface Props {
  scans: ScanSummary[];
  currentScanId: number;
  onSelectScan: (scanId: number) => void;
  onRetest?: () => void;
  onAppendVersion?: () => void;
  retesting?: boolean;
}

const RUNNING_STATUSES: ScanStatus[] = ["cloning", "scanning", "analyzing", "llm_auditing"];

export function ScanHistoryPanel({
  scans,
  currentScanId,
  onSelectScan,
  onRetest,
  onAppendVersion,
  retesting,
}: Props) {
  if (scans.length === 0) return null;

  return (
    <section className="audit-panel p-4 space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-500/80">Scan History</p>
          <h3 className="text-sm font-semibold text-white mt-0.5">历史扫描 · {scans.length} 轮</h3>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {onAppendVersion && (
            <button type="button" className="btn-ghost text-xs" onClick={onAppendVersion}>
              追加新版本
            </button>
          )}
          {onRetest && (
            <button
              type="button"
              className="btn-primary text-xs py-1.5 px-3"
              onClick={onRetest}
              disabled={retesting}
              title="默认复测全部非误报漏洞；在详情页勾选可指定子集（含误报）"
            >
              {retesting ? "创建中…" : "定向复测"}
            </button>
          )}
        </div>
      </div>

      <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
        {scans.map((s) => {
          const active = s.id === currentScanId;
          const kind = s.scan_kind || "baseline";
          const label = s.version_label || `#${s.id}`;
          const when = s.created_at ? new Date(s.created_at).toLocaleString("zh-CN") : "—";
          const isRunning = RUNNING_STATUSES.includes(s.status);
          const isLlmRunning = s.status === "llm_auditing";
          const coverage = resolveScanCoverage(s);
          const chips = historyCoverageChips(coverage);

          return (
            <button
              key={s.id}
              type="button"
              onClick={() => onSelectScan(s.id)}
              className={`w-full text-left rounded-lg px-3 py-2 border transition-colors ${
                active
                  ? "border-cyan-500/40 bg-cyan-500/10"
                  : "border-transparent hover:bg-white/5 hover:border-surface-border"
              }`}
            >
              <div className="flex items-center gap-2 flex-wrap">
                <StatusIcon status={s.status as ScanStatus} />
                <span className={`text-sm font-medium ${active ? "text-cyan-100" : "text-slate-300"}`}>
                  {label}
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/30 text-slate-400">
                  {SCAN_KIND_LABELS[kind]}
                </span>
                <span className="text-[10px] text-slate-600 ml-auto">{STATUS_LABELS[s.status]}</span>
              </div>
              <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-500">
                <span>{when}</span>
                {s.branch && <span>· {s.branch}</span>}
                <span className="ml-auto flex items-center gap-2">
                  {s.security_score != null && (
                    <span
                      className={
                        s.security_score >= 80
                          ? "text-emerald-400"
                          : s.security_score >= 60
                            ? "text-amber-300"
                            : "text-red-400"
                      }
                      title="安全分"
                    >
                      {s.security_score}分
                    </span>
                  )}
                  <span>{s.total_findings} 条</span>
                </span>
              </div>
              {isRunning ? (
                <p className="mt-1 text-[10px] text-cyan-400/80 truncate" title={s.progress_message || undefined}>
                  {isLlmRunning ? s.progress_message || "LLM 审计中…" : s.progress_message || "扫描进行中…"}
                </p>
              ) : (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {chips.map((chip) => (
                    <span
                      key={chip.label}
                      className="text-[10px] px-1.5 py-0.5 rounded border border-surface-border/50 bg-black/20 text-slate-400"
                      title={chip.title}
                    >
                      {chip.label}
                    </span>
                  ))}
                </div>
              )}
            </button>
          );
        })}
      </div>
    </section>
  );
}
