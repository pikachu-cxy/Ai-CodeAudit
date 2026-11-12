import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { ScanEvent, ScanStats, ScanSummary } from "../api";
import { resolveScanCoverage } from "../lib/scanCoverageUtils";

interface Props {
  scan: ScanSummary | null;
  stats: ScanStats | null;
  events: ScanEvent[];
  highlightedCount?: number;
}

const PHASE_LABELS: Record<string, string> = {
  prepare: "准备",
  scan: "SAST 扫描",
  persist: "入库",
  llm_fp: "误报审计",
  llm: "LLM 深度审计",
  done: "完成",
  error: "错误",
};

function eventIcon(level: string) {
  if (level === "error") return <XCircle className="w-3.5 h-3.5 text-red-400" />;
  if (level === "warning") return <Loader2 className="w-3.5 h-3.5 text-slate-300 animate-spin" />;
  return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />;
}

export function AgentPanel({ scan, stats, events, highlightedCount = 0 }: Props) {
  const critical = stats?.by_severity?.CRITICAL ?? 0;
  const high = stats?.by_severity?.HIGH ?? 0;
  const agentEvents = events
    .filter((e) => e.phase && ["llm", "llm_fp", "scan", "done"].includes(e.phase))
    .slice(-12)
    .reverse();

  const scanCoverage = scan ? resolveScanCoverage(scan) : null;
  const semgrepEvent = events.find((e) => e.tool === "semgrep" && e.message.includes("Semgrep 规则:"));
  const semgrepConfigs =
    scanCoverage?.semgrep_configs.length
      ? scanCoverage.semgrep_configs
      : semgrepEvent
        ? semgrepEvent.message.replace(/^Semgrep 规则:\s*/, "").split("（")[0].split(",").map((s) => s.trim())
        : [];

  const displayScanners = (scanCoverage?.scanners || []).filter((r) => r.status !== "not_run");

  return (
    <aside className="w-80 border-l border-cyan-500/10 bg-[#0a0e14]/80 flex flex-col shrink-0 overflow-hidden">
      <div className="p-4 border-b border-cyan-500/10">
        <p className="text-[10px] font-mono uppercase tracking-wider text-cyan-400/70">Audit Copilot</p>
        {scan && (
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-500">项目</span>
              <span className="text-slate-300 truncate max-w-[140px]">{scan.name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">进度</span>
              <span className="text-cyan-300">{scan.progress}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">漏洞</span>
              <span>
                <span className="text-red-400">{critical} C</span>
                <span className="text-slate-600 mx-1">/</span>
                <span className="text-orange-400">{high} H</span>
              </span>
            </div>
            {highlightedCount > 0 && (
              <p className="text-[10px] text-cyan-300/80 pt-1 border-t border-cyan-500/10">
                列表已高亮 {highlightedCount} 条相关漏洞
              </p>
            )}
          </div>
        )}
      </div>

      <div className="p-4 border-b border-cyan-500/10">
        <p className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-2">Scanners</p>
        {semgrepConfigs.length > 0 && (
          <p className="text-[10px] text-slate-600 mb-2 leading-relaxed">
            Semgrep: {semgrepConfigs.slice(0, 3).join(", ")}
            {semgrepConfigs.length > 3 ? "…" : ""}
          </p>
        )}
        <div className="space-y-1.5">
          {displayScanners.length === 0 && (
            <p className="text-xs text-slate-600">等待扫描器执行</p>
          )}
          {displayScanners.slice(0, 5).map((r) => (
            <div key={r.id} className="rounded border border-surface-border/40 bg-black/20 px-2 py-1.5">
              <div className="flex justify-between text-xs gap-2">
                <span className="text-slate-400 font-mono">{r.name}</span>
                <span className="text-slate-500">
                  {r.status === "failed" ? "失败" : r.status === "skipped" ? "跳过" : `${r.findings} 条`}
                </span>
              </div>
            </div>
          ))}
          {displayScanners.length > 0 && (
            <p className="text-[10px] text-slate-600 pt-1">
              完整漏洞扫描清单见主面板「漏洞扫描清单」
            </p>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        <p className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-3">运行日志</p>
        <div className="space-y-2">
          {agentEvents.length === 0 && (
            <div className="flex items-center gap-2 text-xs text-slate-600">
              <Circle className="w-3 h-3" /> 等待审计任务…
            </div>
          )}
          {agentEvents.map((ev) => (
            <div
              key={ev.id}
              className="flex gap-2 text-xs rounded-lg border border-surface-border/60 bg-black/20 p-2.5"
            >
              <div className="mt-0.5 shrink-0">{eventIcon(ev.level)}</div>
              <div className="min-w-0">
                <p className="text-[10px] text-cyan-500/80 font-mono uppercase">
                  {PHASE_LABELS[ev.phase || ""] || ev.phase}
                </p>
                <p className="text-slate-400 mt-0.5 leading-relaxed line-clamp-3">{ev.message}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="p-4 border-t border-cyan-500/10 text-[10px] text-slate-600">
        方法论: 多引擎静态分析（Semgrep / CodeQL）+ LLM 数据流研判 + 深度代码审计
      </div>
    </aside>
  );
}
