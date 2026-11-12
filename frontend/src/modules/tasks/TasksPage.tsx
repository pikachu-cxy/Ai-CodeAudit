import { useEffect, useState } from "react";
import { ListTodo, Search, Trash2 } from "lucide-react";
import { api, type ScanStatus, type ScanSummary } from "../../api";
import { navigate } from "../../app/router";
import type { PageContext } from "../../app/pageTypes";
import { STATUS_LABELS, StatusIcon } from "../../components/ui";
import { useAsyncData } from "../../shared/hooks/useAsyncData";
import { formatDateTime } from "../../shared/format";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MonoMeta,
  PageHeader,
  SectionCard,
} from "../../shared/ui";

type StatusFilter = ScanStatus | "all";

const STATUS_FILTERS: { value: StatusFilter; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "pending", label: "等待中" },
  { value: "scanning", label: "扫描中" },
  { value: "analyzing", label: "AI 审计" },
  { value: "llm_auditing", label: "LLM 审计" },
  { value: "completed", label: "已完成" },
  { value: "failed", label: "失败" },
];

export function TasksPage(ctx: PageContext) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const scans = useAsyncData<ScanSummary[]>(
    () =>
      api.listScans({
        q: query.trim() || undefined,
        status: status === "all" ? undefined : status,
        archived: "false",
      }),
    [ctx.refreshKey, query, status],
  );

  // Mirror the pre-refactor ScanList polling cadence for in-flight scans.
  useEffect(() => {
    const timer = window.setInterval(() => scans.reload(), 5000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const rows = scans.data ?? [];

  const handleDelete = async (scan: ScanSummary) => {
    if (!confirm(`确定删除扫描任务「${scan.name}」？此操作不可恢复。`)) return;
    setDeletingId(scan.id);
    setActionError(null);
    try {
      await api.deleteScan(scan.id);
      scans.reload();
      ctx.onDataChanged();
    } catch (e) {
      setActionError(String(e));
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Workspace / Tasks"
        title="扫描任务"
        description="全部未归档扫描任务的执行状态。列表来自 /api/scans，每 5 秒自动刷新进行中的任务。"
        actions={
          <button type="button" className="btn-action" onClick={() => scans.reload()}>
            刷新
          </button>
        }
      />

      <SectionCard bodyClassName="p-3 space-y-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            className="input pl-9"
            placeholder="按任务名称搜索"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <div className="flex flex-wrap items-center gap-1">
          {STATUS_FILTERS.map((item) => (
            <button
              key={item.value}
              type="button"
              className={status === item.value ? "filter-chip filter-chip-active" : "filter-chip"}
              onClick={() => setStatus(item.value)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </SectionCard>

      {actionError && <ErrorState message={actionError} onRetry={() => setActionError(null)} />}

      <SectionCard
        title="任务列表"
        description={`共 ${rows.length} 条`}
        bodyClassName="p-0"
      >
        {scans.loading ? (
          <LoadingState label="正在加载任务…" />
        ) : scans.error ? (
          <div className="p-4"><ErrorState message={scans.error} onRetry={() => scans.reload()} /></div>
        ) : rows.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={ListTodo}
              title="没有匹配的扫描任务"
              description="调整筛选条件，或从项目页创建一轮新的扫描。"
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-border text-left text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                  <th className="px-4 py-2.5 font-medium">任务</th>
                  <th className="px-4 py-2.5 font-medium">状态</th>
                  <th className="px-4 py-2.5 font-medium">进度</th>
                  <th className="px-4 py-2.5 font-medium">发现</th>
                  <th className="px-4 py-2.5 font-medium">创建时间</th>
                  <th className="px-4 py-2.5 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--surface-border)]">
                {rows.map((scan) => (
                  <tr key={scan.id} className="hover:bg-[var(--hover-overlay)] transition-colors">
                    <td className="px-4 py-3">
                      <button type="button" className="text-left" onClick={() => navigate(`/tasks/${scan.id}`)}>
                        <span className="block font-medium hover:text-cyan-500 transition-colors">{scan.name}</span>
                        <MonoMeta>
                          #{scan.id} · {scan.source} · {scan.version_label || "—"}
                        </MonoMeta>
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
                        <StatusIcon status={scan.status} />
                        {STATUS_LABELS[scan.status]}
                      </span>
                      {scan.error_message && (
                        <p className="mt-1 max-w-xs truncate text-[11px] text-red-400" title={scan.error_message}>
                          {scan.error_message}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="h-1.5 w-24 overflow-hidden rounded-full bg-[var(--bg-raised)]">
                          <span className="block h-full rounded-full bg-cyan-500" style={{ width: `${Math.max(0, Math.min(100, scan.progress))}%` }} />
                        </span>
                        <MonoMeta>{scan.progress}%</MonoMeta>
                      </div>
                      {scan.progress_message && (
                        <p className="mt-1 max-w-xs truncate text-[11px] text-[var(--text-muted)]" title={scan.progress_message}>
                          {scan.progress_message}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3"><MonoMeta>{scan.total_findings}</MonoMeta></td>
                    <td className="px-4 py-3"><MonoMeta>{formatDateTime(scan.created_at)}</MonoMeta></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" className="btn-action" onClick={() => navigate(`/tasks/${scan.id}`)}>
                          打开
                        </button>
                        <button
                          type="button"
                          className="btn-action btn-action-danger"
                          disabled={deletingId === scan.id}
                          onClick={() => void handleDelete(scan)}
                          title="删除任务"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
