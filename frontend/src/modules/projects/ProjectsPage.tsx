import { useState } from "react";
import { Archive, ArchiveRestore, GitBranch, Plus, Search, Trash2, Upload } from "lucide-react";
import { api, type ListProjectsParams, type ProjectSummary } from "../../api";
import { navigate } from "../../app/router";
import type { PageContext } from "../../app/pageTypes";
import { STATUS_LABELS } from "../../components/ui";
import { useAsyncData } from "../../shared/hooks/useAsyncData";
import { formatDateTime } from "../../shared/format";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MonoMeta,
  PageHeader,
  SectionCard,
  StatusPill,
} from "../../shared/ui";

type ArchivedFilter = "false" | "true" | "all";

export function ProjectsPage(ctx: PageContext) {
  const [query, setQuery] = useState("");
  const [archived, setArchived] = useState<ArchivedFilter>("false");
  const [busyId, setBusyId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const params: ListProjectsParams = { archived };
  const projects = useAsyncData<ProjectSummary[]>(
    () => api.listProjects({ ...params, q: query.trim() || undefined }),
    [ctx.refreshKey, archived, query],
  );

  const rows = projects.data ?? [];

  const mutate = async (id: number, work: () => Promise<unknown>) => {
    setBusyId(id);
    setActionError(null);
    try {
      await work();
      projects.reload();
      ctx.onDataChanged();
    } catch (e) {
      setActionError(String(e));
    } finally {
      setBusyId(null);
    }
  };

  const openProject = (project: ProjectSummary) => {
    const scanId = project.latest_scan?.id;
    navigate(
      scanId
        ? `/projects/${project.id}?scan=${scanId}`
        : `/projects/${project.id}`,
    );
  };

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Workspace / Projects"
        title="审计项目"
        description="项目、扫描版本与报告的统一入口。列表来自 /api/projects，归档与删除均调用真实接口。"
        actions={
          <button type="button" className="btn-primary inline-flex items-center gap-2" onClick={() => navigate("/projects/new")}>
            <Plus className="h-4 w-4" /> 新建项目
          </button>
        }
      />

      <SectionCard bodyClassName="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
            <input
              className="input pl-9"
              placeholder="按项目名称搜索"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="flex items-center gap-1">
            {(["false", "true", "all"] as ArchivedFilter[]).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setArchived(value)}
                className={archived === value ? "filter-chip filter-chip-active" : "filter-chip"}
              >
                {value === "false" ? "进行中" : value === "true" ? "已归档" : "全部"}
              </button>
            ))}
          </div>
          <button type="button" className="btn-action" onClick={() => projects.reload()}>
            刷新
          </button>
        </div>
      </SectionCard>

      {actionError && <ErrorState message={actionError} onRetry={() => setActionError(null)} />}

      <SectionCard title="项目列表" description={`共 ${rows.length} 个项目`} bodyClassName="p-0">
        {projects.loading ? (
          <LoadingState label="正在加载项目…" />
        ) : projects.error ? (
          <div className="p-4"><ErrorState message={projects.error} onRetry={() => projects.reload()} /></div>
        ) : rows.length === 0 ? (
          <div className="p-4">
            <EmptyState
              title="没有匹配的项目"
              description="调整搜索条件或新建一个审计项目。"
              action={
                <button type="button" className="btn-action" onClick={() => navigate("/projects/new")}>
                  新建项目
                </button>
              }
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-border text-left text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                  <th className="px-4 py-2.5 font-medium">项目</th>
                  <th className="px-4 py-2.5 font-medium">来源</th>
                  <th className="px-4 py-2.5 font-medium">最新版本</th>
                  <th className="px-4 py-2.5 font-medium">创建时间</th>
                  <th className="px-4 py-2.5 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--surface-border)]">
                {rows.map((project) => (
                  <tr key={project.id} className="hover:bg-[var(--hover-overlay)] transition-colors">
                    <td className="px-4 py-3">
                      <button type="button" className="text-left" onClick={() => openProject(project)}>
                        <span className="block font-medium hover:text-cyan-500 transition-colors">{project.name}</span>
                        <MonoMeta>#{project.id} · {project.scan_count} 个版本</MonoMeta>
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
                        {project.source_type === "gitlab" ? <GitBranch className="h-3.5 w-3.5" /> : <Upload className="h-3.5 w-3.5" />}
                        {project.source_type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {project.latest_scan ? (
                        <div className="flex items-center gap-2">
                          <StatusPill tone={project.latest_scan.status === "completed" ? "success" : project.latest_scan.status === "failed" ? "danger" : "warning"}>
                            {STATUS_LABELS[project.latest_scan.status]}
                          </StatusPill>
                          <MonoMeta>{project.latest_scan.total_findings} 项</MonoMeta>
                        </div>
                      ) : (
                        <MonoMeta>尚无扫描</MonoMeta>
                      )}
                    </td>
                    <td className="px-4 py-3"><MonoMeta>{formatDateTime(project.created_at)}</MonoMeta></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button type="button" className="btn-action" onClick={() => openProject(project)}>
                          打开
                        </button>
                        <button
                          type="button"
                          className="btn-action"
                          onClick={() => navigate(`/projects/new?appendProjectId=${project.id}`)}
                          title="追加扫描版本"
                        >
                          追加版本
                        </button>
                        <button
                          type="button"
                          className="btn-action"
                          disabled={busyId === project.id}
                          onClick={() =>
                            void mutate(project.id, () =>
                              project.archived_at
                                ? api.unarchiveProject(project.id)
                                : api.archiveProject(project.id),
                            )
                          }
                          title={project.archived_at ? "取消归档" : "归档"}
                        >
                          {project.archived_at ? <ArchiveRestore className="h-3.5 w-3.5" /> : <Archive className="h-3.5 w-3.5" />}
                        </button>
                        <button
                          type="button"
                          className="btn-action btn-action-danger"
                          disabled={busyId === project.id}
                          onClick={() => {
                            if (!confirm(`确定删除项目「${project.name}」及其全部扫描数据？此操作不可恢复。`)) return;
                            void mutate(project.id, () => api.deleteProject(project.id));
                          }}
                          title="删除项目"
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
