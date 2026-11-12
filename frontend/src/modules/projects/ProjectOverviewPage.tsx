import { useMemo } from "react";
import { ArrowLeft, FilePlus2, FolderOpen } from "lucide-react";
import { api, type ProjectDetail } from "../../api";
import { navigate } from "../../app/router";
import { useInspector } from "../../app/AppShell";
import type { PageContext } from "../../app/pageTypes";
import { STATUS_LABELS, StatusIcon } from "../../components/ui";
import { useAsyncData } from "../../shared/hooks/useAsyncData";
import { formatDateTime } from "../../shared/format";
import {
  EmptyState,
  ErrorState,
  KeyValueRow,
  LoadingState,
  MonoMeta,
  PageHeader,
  SectionCard,
  StatusPill,
} from "../../shared/ui";

interface Props extends PageContext {
  projectId: number;
}

export function ProjectOverviewPage({ projectId, onDataChanged, refreshKey }: Props) {
  const project = useAsyncData<ProjectDetail>(
    () => api.getProject(projectId),
    [projectId, refreshKey],
  );

  const inspector = useMemo(() => {
    if (!project.data) return null;
    const p = project.data;
    return {
      title: p.name,
      subtitle: `项目 #${p.id}`,
      content: (
        <div className="space-y-1">
          <KeyValueRow label="来源类型">{p.source_type}</KeyValueRow>
          <KeyValueRow label="默认分支">{p.default_branch || "—"}</KeyValueRow>
          <KeyValueRow label="版本数">{p.scans.length}</KeyValueRow>
          <KeyValueRow label="创建时间"><MonoMeta>{formatDateTime(p.created_at)}</MonoMeta></KeyValueRow>
          <KeyValueRow label="源地址">
            <span className="break-all text-xs">{p.source_url || "—"}</span>
          </KeyValueRow>
          {p.notes && (
            <div className="pt-3">
              <p className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">备注</p>
              <p className="mt-1 whitespace-pre-wrap text-xs text-[var(--text-secondary)]">{p.notes}</p>
            </div>
          )}
        </div>
      ),
    };
  }, [project.data]);
  useInspector(inspector);

  const scans = project.data?.scans ?? [];
  const latestId = project.data?.latest_scan?.id ?? scans[0]?.id ?? null;

  return (
    <div className="page-container space-y-4">
      <button
        type="button"
        className="btn-ghost text-sm inline-flex items-center gap-1.5 -ml-2"
        onClick={() => navigate("/projects")}
      >
        <ArrowLeft className="h-4 w-4" /> 返回项目列表
      </button>

      <PageHeader
        eyebrow={`Workspace / Projects / #${projectId}`}
        title={project.data?.name ?? `项目 #${projectId}`}
        description="项目下的全部扫描版本。点击任一版本进入原有的扫描详情、报告与漏洞复核界面。"
        actions={
          <>
            <button
              type="button"
              className="btn-action inline-flex items-center gap-1.5"
              onClick={() => navigate(`/projects/new?appendProjectId=${projectId}`)}
            >
              <FilePlus2 className="h-3.5 w-3.5" /> 追加扫描版本
            </button>
            {latestId && (
              <button
                type="button"
                className="btn-primary inline-flex items-center gap-1.5"
                onClick={() => navigate(`/projects/${projectId}?scan=${latestId}`)}
              >
                <FolderOpen className="h-4 w-4" /> 打开最新扫描
              </button>
            )}
          </>
        }
      />

      <SectionCard title="扫描版本" description={`共 ${scans.length} 个版本`} bodyClassName="p-0">
        {project.loading ? (
          <LoadingState label="正在加载项目…" />
        ) : project.error ? (
          <div className="p-4"><ErrorState message={project.error} onRetry={() => project.reload()} /></div>
        ) : scans.length === 0 ? (
          <div className="p-4">
            <EmptyState
              title="该项目还没有扫描版本"
              description="追加一个代码包或 GitLab 版本后，扫描结果会显示在这里。"
              action={
                <button type="button" className="btn-action" onClick={() => navigate(`/projects/new?appendProjectId=${projectId}`)}>
                  追加扫描版本
                </button>
              }
            />
          </div>
        ) : (
          <div className="divide-y divide-[var(--surface-border)]">
            {scans.map((scan) => (
              <button
                key={scan.id}
                type="button"
                className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-[var(--hover-overlay)] transition-colors"
                onClick={() => navigate(`/projects/${projectId}?scan=${scan.id}`)}
              >
                <StatusIcon status={scan.status} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">
                    {scan.version_label || scan.name}
                  </span>
                  <span className="block truncate text-[11px] text-[var(--text-muted)]">
                    #{scan.id} · {scan.source} · {formatDateTime(scan.created_at)}
                  </span>
                </span>
                <StatusPill tone={scan.status === "completed" ? "success" : scan.status === "failed" ? "danger" : "warning"}>
                  {STATUS_LABELS[scan.status]}
                </StatusPill>
                <MonoMeta>{scan.total_findings} 项</MonoMeta>
              </button>
            ))}
          </div>
        )}
      </SectionCard>

      <button type="button" className="btn-action" onClick={onDataChanged}>
        刷新项目数据
      </button>
    </div>
  );
}
