type TaskStatus = "pending" | "running" | "done" | "error" | "skipped";

export type SastDeepTask = {
  id: string;
  label: string;
  kind?: string;
  status: TaskStatus | string;
  detail?: string;
  finding_id?: number;
};

export type SastDeepJob = {
  status?: string;
  phase?: string;
  message?: string;
  total?: number;
  done?: number;
  percent?: number;
  current_task_id?: string | null;
  tasks?: SastDeepTask[];
  error?: string | null;
};

type Props = {
  job: SastDeepJob | null;
  scanProgress?: number;
  scanMessage?: string | null;
  onPause?: () => void;
  pausing?: boolean;
};

const STATUS_STYLE: Record<string, string> = {
  pending: "text-slate-500 border-slate-600/40 bg-black/20",
  running: "text-cyan-300 border-cyan-500/40 bg-cyan-500/10",
  done: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
  error: "text-red-300 border-red-500/40 bg-red-500/10",
  skipped: "text-slate-400 border-slate-600/30 bg-black/10",
};

const STATUS_LABEL: Record<string, string> = {
  pending: "等待",
  running: "进行中",
  done: "完成",
  error: "失败",
  skipped: "跳过",
};

export function SastDeepProgressPanel({ job, scanProgress, scanMessage, onPause, pausing }: Props) {
  if (!job) return null;

  const percent = job.percent ?? scanProgress ?? 0;
  const message = job.message || scanMessage || "深度研判进行中…";
  const tasks = job.tasks || [];
  const running = job.status === "running";
  const done = job.status === "done";
  const failed = job.status === "failed";
  const cancelled = job.status === "cancelled";

  return (
    <div className="card p-4 border border-cyan-500/25 bg-cyan-500/5 space-y-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-medium text-cyan-100">
            {running ? "深度研判进行中" : done ? "深度研判已完成" : failed ? "深度研判失败" : cancelled ? "深度研判已暂停" : "深度研判"}
          </p>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed break-words">{message}</p>
          {job.error && <p className="text-xs text-red-300 mt-1">{job.error}</p>}
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-sm font-mono text-cyan-200">{percent}%</span>
          {running && onPause && (
            <button
              type="button"
              className="text-xs px-2.5 py-1 rounded border border-danger/40 text-red-300 hover:bg-danger/10 disabled:opacity-50"
              onClick={onPause}
              disabled={pausing}
            >
              {pausing ? "暂停中…" : "暂停"}
            </button>
          )}
        </div>
      </div>

      <div className="h-2 bg-surface rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-500 ${failed ? "bg-danger" : cancelled ? "bg-amber-400" : "bg-cyan-400"}`}
          style={{ width: `${Math.max(2, Math.min(100, percent))}%` }}
        />
      </div>

      <div className="flex gap-3 text-[11px] text-slate-500">
        <span>
          任务 {job.done ?? 0}/{job.total ?? tasks.length}
        </span>
        {job.phase && <span>阶段: {job.phase}</span>}
      </div>

      {tasks.length > 0 && (
        <ul className="max-h-56 overflow-y-auto space-y-1.5 pr-1">
          {tasks.map((t) => {
            const st = String(t.status || "pending");
            const active = t.id === job.current_task_id || st === "running";
            return (
              <li
                key={t.id}
                className={`rounded-lg border px-3 py-2 text-xs ${STATUS_STYLE[st] || STATUS_STYLE.pending} ${
                  active ? "ring-1 ring-cyan-400/40" : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium truncate">{t.label}</span>
                  <span className="shrink-0 text-[10px] opacity-80">{STATUS_LABEL[st] || st}</span>
                </div>
                {t.detail && <p className="mt-1 text-[11px] opacity-80 leading-relaxed break-words">{t.detail}</p>}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
