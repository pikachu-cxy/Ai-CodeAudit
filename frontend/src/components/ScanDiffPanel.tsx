import type { DiffStatus, ScanDiffSummary } from "../api";
import { shortPath } from "../lib/findingUtils";
import { DIFF_STATUS_LABELS } from "./ScanHistoryPanel";

interface Props {
  diff: ScanDiffSummary | null;
  loading?: boolean;
  error?: string | null;
  filterDiff: DiffStatus | "";
  onFilterDiff: (status: DiffStatus | "") => void;
  onOpenBaselineFinding?: (scanId: number, findingId: number) => void;
  onOpenCurrentFinding?: (scanId: number, findingId: number) => void;
}

export function ScanDiffPanel({
  diff,
  loading,
  error,
  filterDiff,
  onFilterDiff,
  onOpenBaselineFinding,
  onOpenCurrentFinding,
}: Props) {
  if (loading) {
    return (
      <section className="audit-panel p-4">
        <p className="text-xs text-slate-500">正在对比基线扫描…</p>
      </section>
    );
  }
  if (error) {
    return (
      <section className="audit-panel p-4">
        <p className="text-xs text-amber-400/90">{error}</p>
      </section>
    );
  }
  if (!diff) return null;

  const cards: { key: DiffStatus; count: number; accent: string }[] = [
    { key: "fixed", count: diff.fixed_count, accent: "text-emerald-400" },
    { key: "regressed", count: diff.regressed_count, accent: "text-amber-300" },
    { key: "new", count: diff.new_count, accent: "text-rose-300" },
  ];

  const filteredItems = filterDiff
    ? diff.items.filter((i) => i.status === filterDiff)
    : [];

  return (
    <section className="audit-panel p-4 space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-500/80">Full Scan Diff</p>
          <h3 className="text-sm font-semibold text-white mt-0.5">
            全量对比（可选）
            <span className="text-slate-500 font-normal text-xs ml-2">
              基线 #{diff.baseline_scan_id}
            </span>
          </h3>
        </div>
        {filterDiff && (
          <button type="button" className="btn-ghost text-xs" onClick={() => onFilterDiff("")}>
            清除对比筛选
          </button>
        )}
      </div>

      <div className="grid grid-cols-3 gap-2">
        {cards.map((c) => {
          const active = filterDiff === c.key;
          return (
            <button
              key={c.key}
              type="button"
              onClick={() => onFilterDiff(active ? "" : c.key)}
              className={`rounded-lg border px-3 py-2 text-left transition-colors ${
                active
                  ? "border-cyan-500/40 bg-cyan-500/10"
                  : "border-surface-border bg-black/20 hover:border-cyan-500/20"
              }`}
            >
              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                {DIFF_STATUS_LABELS[c.key]}
              </p>
              <p className={`text-lg font-semibold font-mono mt-0.5 ${c.accent}`}>{c.count}</p>
            </button>
          );
        })}
      </div>

      <p className="text-[11px] text-slate-500">
        说明：新增/遗留/已修复为去重后的唯一漏洞数（按规则+路径+消息+近似行号指纹统计），不等同于本轮原始漏洞总条数。
      </p>

      {diff.status_changed_count > 0 && (
        <p className="text-[11px] text-slate-500">
          其中 {diff.status_changed_count} 条相对基线的人工标记状态有变化。
        </p>
      )}

      {filterDiff && (
        <div className="border-t border-cyan-500/10 pt-3 space-y-2">
          <p className="text-xs text-slate-400">
            {DIFF_STATUS_LABELS[filterDiff]}：
            {filteredItems.length} 条
          </p>
          {filteredItems.length === 0 ? (
            <p className="text-xs text-slate-600">无</p>
          ) : (
            <ul className="space-y-1 max-h-40 overflow-y-auto">
              {filteredItems.slice(0, 50).map((item) => {
                const f =
                  filterDiff === "fixed"
                    ? item.baseline
                    : item.current;
                if (!f) return null;
                return (
                  <li key={item.fingerprint}>
                    <button
                      type="button"
                      className="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-white/5 text-slate-400"
                      onClick={() => {
                        if (filterDiff === "fixed") {
                          onOpenBaselineFinding?.(diff.baseline_scan_id, f.id);
                        } else {
                          onOpenCurrentFinding?.(diff.scan_id, f.id);
                        }
                      }}
                    >
                      <span
                        className={`mr-2 ${
                          filterDiff === "fixed"
                            ? "text-emerald-400/80"
                            : filterDiff === "new"
                              ? "text-rose-300/90"
                              : "text-amber-300/90"
                        }`}
                      >
                        #{f.id}
                      </span>
                      <span className="text-slate-300">{f.rule_id}</span>
                      <span className="text-slate-600 ml-2 truncate">{shortPath(f.file_path)}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
