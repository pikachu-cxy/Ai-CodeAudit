import type { RetestResultsSummary, RetestVerdict } from "../api";
import { shortPath } from "../lib/findingUtils";

const VERDICT_LABELS: Record<RetestVerdict, string> = {
  fixed: "已修复",
  still_present: "仍存在",
  inconclusive: "无法判定",
  skipped: "已跳过",
};

const VERDICT_ACCENT: Record<RetestVerdict, string> = {
  fixed: "text-emerald-400",
  still_present: "text-rose-300",
  inconclusive: "text-amber-300",
  skipped: "text-slate-400",
};

interface Props {
  results: RetestResultsSummary | null;
  loading?: boolean;
  error?: string | null;
  onOpenBaselineFinding?: (baselineScanId: number, findingId: number) => void;
  onOpenCurrentFinding?: (currentScanId: number, findingId: number) => void;
}

export function RetestResultsPanel({
  results,
  loading,
  error,
  onOpenBaselineFinding,
  onOpenCurrentFinding,
}: Props) {
  if (loading) {
    return (
      <section className="audit-panel p-4">
        <p className="text-xs text-slate-500">正在加载定向复测结果…</p>
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
  if (!results) return null;

  const cards: { key: RetestVerdict; count: number }[] = [
    { key: "fixed", count: results.fixed_count },
    { key: "still_present", count: results.still_present_count },
    { key: "inconclusive", count: results.inconclusive_count },
    { key: "skipped", count: results.skipped_count },
  ];

  return (
    <section className="audit-panel p-4 space-y-3">
      <div>
        <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-cyan-500/80">Targeted Retest</p>
        <h3 className="text-sm font-semibold text-white mt-0.5">
          定向复测结果
          <span className="text-slate-500 font-normal text-xs ml-2">
            基线 #{results.baseline_scan_id} · 队列 {results.queue_size} 条
          </span>
        </h3>
        {results.message && (
          <p className="text-xs text-amber-300/90 mt-1">{results.message}</p>
        )}
      </div>

      <div className="flex gap-3 flex-wrap">
        {cards.map((c) => (
          <div key={c.key} className="rounded-lg border border-slate-700/60 bg-slate-900/40 px-3 py-2 min-w-[88px]">
            <p className={`text-lg font-semibold ${VERDICT_ACCENT[c.key]}`}>{c.count}</p>
            <p className="text-[10px] text-slate-500 uppercase tracking-wide">{VERDICT_LABELS[c.key]}</p>
          </div>
        ))}
      </div>

      {results.items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-slate-500 border-b border-slate-700/50">
                <th className="py-2 pr-3 font-medium">结论</th>
                <th className="py-2 pr-3 font-medium">基线漏洞</th>
                <th className="py-2 pr-3 font-medium">工具</th>
                <th className="py-2 pr-3 font-medium">说明</th>
                <th className="py-2 font-medium">跳转</th>
              </tr>
            </thead>
            <tbody>
              {results.items.map((item) => {
                const bf = item.baseline_finding;
                let evidenceNote = "";
                if (item.evidence_json) {
                  try {
                    const ev = JSON.parse(item.evidence_json);
                    evidenceNote =
                      ev.reason || ev.matched || ev.endpoint || (ev.file_path ? shortPath(ev.file_path) : "") || "";
                  } catch {
                    evidenceNote = "";
                  }
                }
                return (
                  <tr key={item.id} className="border-b border-slate-800/60 hover:bg-slate-800/20">
                    <td className={`py-2 pr-3 font-medium ${VERDICT_ACCENT[item.verdict]}`}>
                      {VERDICT_LABELS[item.verdict]}
                    </td>
                    <td className="py-2 pr-3 text-slate-300 max-w-[240px] truncate" title={bf?.message}>
                      {bf?.message || `#${item.baseline_finding_id}`}
                    </td>
                    <td className="py-2 pr-3 text-slate-500 font-mono">{bf?.tool || item.method}</td>
                    <td className="py-2 pr-3 text-slate-500 max-w-[200px] truncate" title={evidenceNote}>
                      {evidenceNote || "—"}
                    </td>
                    <td className="py-2 whitespace-nowrap space-x-2">
                      {bf && onOpenBaselineFinding && (
                        <button
                          type="button"
                          className="text-cyan-400/90 hover:text-cyan-300"
                          onClick={() => onOpenBaselineFinding(results.baseline_scan_id, bf.id)}
                        >
                          基线
                        </button>
                      )}
                      {item.current_finding_id && onOpenCurrentFinding && (
                        <button
                          type="button"
                          className="text-cyan-400/90 hover:text-cyan-300"
                          onClick={() => onOpenCurrentFinding(results.scan_id, item.current_finding_id!)}
                        >
                          本轮
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
