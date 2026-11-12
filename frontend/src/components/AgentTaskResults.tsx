import type { AgentTaskItem, ReviewStatus } from "../api";
import { shortPath } from "../lib/findingUtils";

const TASK_MODE_LABELS: Record<string, string> = {
  auth_gap_hunt: "补盲越权",
  biz_gap_hunt: "补盲业务流程",
  prioritize: "漏洞优先级排序",
};

interface Props {
  variant?: "chat" | "panel";
  taskMode?: string | null;
  notice?: string | null;
  items: AgentTaskItem[];
  reviewingId?: number | null;
  onOpenFinding?: (findingId: number) => void;
  onReview?: (findingId: number, status: ReviewStatus) => void;
  onClear?: () => void;
  maxItems?: number;
}

export function AgentTaskResults({
  variant = "chat",
  taskMode,
  notice,
  items,
  reviewingId,
  onOpenFinding,
  onReview,
  onClear,
  maxItems = 6,
}: Props) {
  if (!notice && items.length === 0) return null;

  const modeLabel = taskMode ? TASK_MODE_LABELS[taskMode] || taskMode : null;
  const isPanel = variant === "panel";
  const shown = items.slice(0, maxItems);

  return (
    <div
      className={
        isPanel
          ? "rounded-lg border border-cyan-500/20 bg-cyan-500/5 overflow-hidden"
          : "mb-2 rounded-lg border border-cyan-500/25 bg-cyan-500/5 overflow-hidden"
      }
    >
      <div
        className={`flex items-center justify-between gap-2 border-b border-cyan-500/15 ${
          isPanel ? "px-2.5 py-2" : "px-3 py-2"
        }`}
      >
        <div className="min-w-0">
          <p className={`uppercase tracking-wide text-cyan-300/90 ${isPanel ? "text-[9px]" : "text-[10px]"}`}>
            Agent 任务结果
            {modeLabel && <span className="text-cyan-200/80 normal-case ml-1.5">· {modeLabel}</span>}
          </p>
          {notice && (
            <p className={`text-slate-300 mt-0.5 leading-relaxed ${isPanel ? "text-[10px]" : "text-[11px]"}`}>
              {notice}
            </p>
          )}
        </div>
        {onClear && (items.length > 0 || notice) && (
          <button
            type="button"
            className="shrink-0 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
            onClick={onClear}
          >
            清除
          </button>
        )}
      </div>

      {shown.length > 0 && (
        <div
          className={`space-y-1.5 overflow-y-auto ${
            isPanel ? "max-h-56 p-2" : "max-h-40 p-2"
          }`}
        >
          {shown.map((item, idx) => (
            <div
              key={item.id}
              className={`rounded border border-surface-border/70 bg-black/20 ${
                isPanel ? "px-2 py-1.5" : "px-2.5 py-2"
              }`}
            >
              <div className="flex items-start gap-2">
                <span className="shrink-0 mt-0.5 text-[10px] font-mono text-cyan-400/80 w-4">
                  {idx + 1}
                </span>
                <button
                  type="button"
                  className="flex-1 min-w-0 text-left hover:opacity-95 transition-opacity"
                  onClick={() => item.finding_id && onOpenFinding?.(item.finding_id)}
                  disabled={!item.finding_id}
                >
                  <p className={`text-slate-200 truncate ${isPanel ? "text-[11px]" : "text-xs"}`}>
                    {item.title}
                  </p>
                  <p className={`text-slate-500 mt-0.5 ${isPanel ? "text-[9px]" : "text-[10px]"}`}>
                    score {item.priority_score} · {item.category}
                    {item.attack_path && <span> · {shortPath(item.attack_path)}</span>}
                  </p>
                </button>
                {item.finding_id && onReview && (
                  <div className="flex flex-col gap-0.5 shrink-0">
                    <button
                      type="button"
                      className="btn-action text-[9px] px-1.5 py-0.5"
                      disabled={reviewingId === item.finding_id}
                      onClick={() => onReview(item.finding_id!, "confirmed")}
                    >
                      确认
                    </button>
                    <button
                      type="button"
                      className="btn-action btn-action-danger text-[9px] px-1.5 py-0.5"
                      disabled={reviewingId === item.finding_id}
                      onClick={() => onReview(item.finding_id!, "false_positive")}
                    >
                      误报
                    </button>
                    <button
                      type="button"
                      className="btn-action text-[9px] px-1.5 py-0.5"
                      disabled={reviewingId === item.finding_id}
                      onClick={() => onReview(item.finding_id!, "fixed")}
                    >
                      已修复
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
          {items.length > maxItems && (
            <p className="text-[10px] text-slate-600 px-1">另有 {items.length - maxItems} 条，见列表高亮</p>
          )}
        </div>
      )}
    </div>
  );
}

export { TASK_MODE_LABELS };
