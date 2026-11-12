import { useMemo } from "react";
import {
  Activity,
  ArrowRight,
  FolderOpen,
  ListTodo,
  MessageSquare,
  Plus,
  ShieldCheck,
} from "lucide-react";
import { api, type ProjectSummary, type ScanSummary } from "../../api";
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
  StatCard,
  StatusPill,
} from "../../shared/ui";

const RUNNING_STATUSES: ScanSummary["status"][] = [
  "pending",
  "cloning",
  "scanning",
  "analyzing",
  "llm_auditing",
];

const SHORTCUTS = [
  { label: "新建审计项目", hint: "上传代码包或接入 GitLab", path: "/projects/new", icon: Plus },
  { label: "查看项目", hint: "项目、版本与报告", path: "/projects", icon: FolderOpen },
  { label: "查看任务", hint: "扫描进度与执行状态", path: "/tasks", icon: ListTodo },
  { label: "进入对话", hint: "选择扫描上下文开始审计对话", path: "/chat", icon: MessageSquare },
];

/**
 * Every number on this page is derived from `api.listProjects()` /
 * `api.listScans()`. There is no statistics endpoint yet, so no chart or
 * severity breakdown is fabricated.
 */
export function DashboardPage(ctx: PageContext) {
  const projects = useAsyncData<ProjectSummary[]>(
    () => api.listProjects({ archived: "false" }),
    [ctx.refreshKey],
  );
  const scans = useAsyncData<ScanSummary[]>(
    () => api.listScans({ archived: "false" }),
    [ctx.refreshKey],
  );

  const stats = useMemo(() => {
    const rows = scans.data ?? [];
    return {
      projects: projects.data?.length ?? 0,
      scans: rows.length,
      running: rows.filter((row) => RUNNING_STATUSES.includes(row.status)).length,
      completed: rows.filter((row) => row.status === "completed").length,
      findings: rows.reduce((sum, row) => sum + (row.total_findings || 0), 0),
    };
  }, [projects.data, scans.data]);

  const recent = useMemo(() => {
    return [...(scans.data ?? [])]
      .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""))
      .slice(0, 6);
  }, [scans.data]);

  const loading = projects.loading || scans.loading;
  const error = projects.error || scans.error;
  const retry = () => {
    projects.reload();
    scans.reload();
  };

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Workspace / Overview"
        title="审计态势"
        description="汇总当前工作空间中的真实项目与扫描任务数据。平台暂无独立统计接口，本页数字均由项目与任务列表实时聚合。"
        actions={
          <button type="button" className="btn-primary inline-flex items-center gap-2" onClick={() => navigate("/projects/new")}>
            <Plus className="h-4 w-4" /> 新建审计项目
          </button>
        }
      />

      {error ? (
        <ErrorState message={error} onRetry={retry} />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <StatCard label="项目" value={stats.projects} hint="未归档" icon={FolderOpen} loading={loading} />
          <StatCard label="扫描任务" value={stats.scans} hint="未归档" icon={ListTodo} loading={loading} />
          <StatCard label="执行中" value={stats.running} hint="含排队、扫描、LLM 审计" icon={Activity} tone="warning" loading={loading} />
          <StatCard label="已完成" value={stats.completed} hint="状态 completed" icon={ShieldCheck} tone="success" loading={loading} />
          <StatCard
            label="发现总数"
            value={stats.findings}
            hint="各任务 total_findings 累加（含跨版本重复）"
            icon={ShieldCheck}
            tone="danger"
            loading={loading}
          />
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-3">
        <SectionCard
          title="最近扫描任务"
          description="按创建时间排序，最多显示 6 条"
          className="xl:col-span-2"
          bodyClassName="p-0"
          actions={
            <button type="button" className="btn-action" onClick={() => navigate("/tasks")}>
              全部任务 <ArrowRight className="h-3 w-3 inline" />
            </button>
          }
        >
          {loading ? (
            <LoadingState />
          ) : error ? (
            <div className="p-4"><ErrorState message={error} onRetry={retry} /></div>
          ) : recent.length === 0 ? (
            <div className="p-4">
              <EmptyState
                title="还没有扫描任务"
                description="创建一个审计项目后，扫描任务和报告会出现在这里。"
                action={
                  <button type="button" className="btn-action" onClick={() => navigate("/projects/new")}>
                    新建项目
                  </button>
                }
              />
            </div>
          ) : (
            <div className="divide-y divide-[var(--surface-border)]">
              {recent.map((scan) => (
                <button
                  key={scan.id}
                  type="button"
                  className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-[var(--hover-overlay)] transition-colors"
                  onClick={() => navigate(`/tasks/${scan.id}`)}
                >
                  <StatusIcon status={scan.status} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{scan.name}</span>
                    <span className="block truncate text-[11px] text-[var(--text-muted)]">
                      #{scan.id} · {scan.version_label || scan.source} · {formatDateTime(scan.created_at)}
                    </span>
                  </span>
                  <StatusPill tone={scan.status === "failed" ? "danger" : scan.status === "completed" ? "success" : "warning"}>
                    {STATUS_LABELS[scan.status]}
                  </StatusPill>
                  <MonoMeta>{scan.total_findings} 项</MonoMeta>
                </button>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="快捷入口" description="跳转到已有的真实功能">
          <div className="grid gap-2">
            {SHORTCUTS.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.path}
                  type="button"
                  onClick={() => navigate(item.path)}
                  className="flex items-center gap-3 rounded-lg border border-surface-border px-3 py-2.5 text-left transition-colors hover:bg-[var(--hover-overlay)]"
                >
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-500">
                    <Icon className="h-4 w-4" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium">{item.label}</span>
                    <span className="block truncate text-[11px] text-[var(--text-muted)]">{item.hint}</span>
                  </span>
                  <ArrowRight className="h-3.5 w-3.5 text-[var(--text-faint)] shrink-0" />
                </button>
              );
            })}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
