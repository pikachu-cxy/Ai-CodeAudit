import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type ProjectSummary, type ScanStatus } from "../api";
import { formatScanLanguages } from "../lib/scanLanguages";
import { BuildVersion } from "./BuildVersion";
import { ThemeToggle } from "./ThemeToggle";
import { Archive, ArchiveRestore, LogOut, Plus, Settings, Trash2 } from "lucide-react";
import { STATUS_LABELS, StatusIcon } from "./ui";

interface Props {
  selectedProjectId: number | null;
  selectedScanId: number | null;
  username: string;
  isAdmin?: boolean;
  onSelectProject: (projectId: number, scanId: number | null) => void;
  onNewProject: () => void;
  onGoHome: () => void;
  onOpenSettings: () => void;
  onLogout: () => void;
  onProjectDeleted?: (projectId: number) => void;
  refreshKey: number;
}

type FilterKey = "active" | "running" | "completed" | "failed" | "archived";

const FILTER_TABS: { key: FilterKey; label: string }[] = [
  { key: "active", label: "活跃" },
  { key: "running", label: "进行中" },
  { key: "completed", label: "已完成" },
  { key: "failed", label: "失败" },
  { key: "archived", label: "已归档" },
];

const RUNNING_STATUSES: ScanStatus[] = ["pending", "cloning", "scanning", "analyzing", "llm_auditing"];

function parseUtcDate(iso: string): Date {
  const trimmed = iso.trim();
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(trimmed)) {
    return new Date(trimmed);
  }
  return new Date(`${trimmed.replace(" ", "T")}Z`);
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const at = parseUtcDate(iso);
  const diff = Date.now() - at.getTime();
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  if (diff < 604_800_000) return `${Math.floor(diff / 86_400_000)} 天前`;
  return at.toLocaleDateString("zh-CN");
}

export function ProjectSidebar({
  selectedProjectId,
  selectedScanId,
  username,
  isAdmin = false,
  onSelectProject,
  onNewProject,
  onGoHome,
  onOpenSettings,
  onLogout,
  onProjectDeleted,
  refreshKey,
}: Props) {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [healthOk, setHealthOk] = useState(true);
  const [searchInput, setSearchInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [filter, setFilter] = useState<FilterKey>("active");

  useEffect(() => {
    const t = setTimeout(() => setSearchQuery(searchInput.trim()), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const listParams = useMemo(() => {
    const params: { q?: string; archived?: "false" | "true" | "all" } = {};
    if (searchQuery) params.q = searchQuery;
    if (filter === "archived") {
      params.archived = "true";
    } else {
      params.archived = "false";
    }
    return params;
  }, [searchQuery, filter]);

  const loadProjects = useCallback(() => api.listProjects(listParams).then(setProjects), [listParams]);

  const hasRunning = useMemo(
    () =>
      projects.some((p) => {
        const st = p.latest_scan?.status;
        return Boolean(st && RUNNING_STATUSES.includes(st));
      }),
    [projects]
  );

  useEffect(() => {
    loadProjects();
    const intervalMs = hasRunning ? 5000 : 20000;
    const t = setInterval(loadProjects, intervalMs);
    return () => clearInterval(t);
  }, [loadProjects, refreshKey, hasRunning]);

  useEffect(() => {
    api.health().then(() => setHealthOk(true)).catch(() => setHealthOk(false));
    const t = setInterval(() => {
      api.health().then(() => setHealthOk(true)).catch(() => setHealthOk(false));
    }, 30000);
    return () => clearInterval(t);
  }, []);

  const displayedProjects = useMemo(() => {
    return projects.filter((p) => {
      const latest = p.latest_scan;
      if (filter === "archived") return true;
      if (filter === "running") {
        return Boolean(latest && RUNNING_STATUSES.includes(latest.status));
      }
      if (filter === "completed") return latest?.status === "completed";
      if (filter === "failed") return latest?.status === "failed";
      return true;
    });
  }, [projects, filter]);

  const handleArchive = async (e: React.MouseEvent, project: ProjectSummary) => {
    e.stopPropagation();
    const latest = project.latest_scan;
    if (latest && RUNNING_STATUSES.includes(latest.status) && latest.status !== "pending") {
      alert("进行中的扫描无法归档，请先暂停或等待完成。");
      return;
    }
    if (!confirm(`归档项目「${project.name}」？归档后将从主列表隐藏。`)) return;
    try {
      await api.archiveProject(project.id);
      await loadProjects();
    } catch (err) {
      alert(String(err));
    }
  };

  const handleUnarchive = async (e: React.MouseEvent, project: ProjectSummary) => {
    e.stopPropagation();
    await api.unarchiveProject(project.id);
    await loadProjects();
  };

  const handleDeleteProject = async (e: React.MouseEvent, project: ProjectSummary) => {
    e.stopPropagation();
    if (!confirm(`确定删除项目「${project.name}」及其所有扫描结果？此操作不可恢复。`)) return;
    try {
      await api.deleteProject(project.id);
      await loadProjects();
      onProjectDeleted?.(project.id);
    } catch (err) {
      alert(String(err));
    }
  };

  return (
    <aside className="w-72 sidebar-shell flex flex-col shrink-0">
      <div className="p-5 border-b border-cyan-500/10 flex items-start justify-between gap-2">
        <button type="button" className="min-w-0 text-left hover:opacity-90 transition-opacity" onClick={onGoHome}>
          <p className="text-[10px] font-mono tracking-[0.25em] text-cyan-400/80 uppercase">Code Security</p>
          <h1 className="text-lg font-bold tracking-tight text-white mt-1">// AUDIT</h1>
          <p className="text-[11px] text-slate-500 mt-1">SAST · LLM · 数据流研判</p>
        </button>
        <ThemeToggle className="shrink-0 mt-0.5" />
      </div>

      <div className="p-3 space-y-2">
        <button
          type="button"
          className="w-full btn-primary flex items-center justify-center gap-2 text-sm py-2.5 bg-cyan-600 hover:bg-cyan-500"
          onClick={onNewProject}
        >
          <Plus className="w-4 h-4" /> 新建项目
        </button>
        <input
          type="search"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="搜索项目…"
          className="w-full rounded-lg bg-black/30 border border-surface-border px-3 py-2 text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/40"
        />
        <div className="flex flex-wrap gap-1">
          {FILTER_TABS.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setFilter(tab.key)}
              className={`px-2 py-1 rounded text-[10px] transition-colors ${
                filter === tab.key
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-500 hover:text-slate-300 border border-transparent"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-2 space-y-1">
        <p className="text-[10px] uppercase tracking-wider text-slate-600 px-2 py-1">Projects</p>
        {displayedProjects.length === 0 && (
          <p className="text-xs text-slate-600 px-3 py-4">
            {filter === "archived" ? "暂无已归档项目" : "暂无项目"}
          </p>
        )}
        {displayedProjects.map((p) => {
          const latest = p.latest_scan;
          const active =
            selectedProjectId === p.id ||
            Boolean(latest && latest.id === selectedScanId);
          const status = latest?.status ?? "pending";
          const done = status === "completed";
          const failed = status === "failed";
          const progress = failed ? 100 : done ? 100 : Math.max(5, latest?.progress ?? 0);
          const activityAt = p.updated_at || latest?.updated_at || p.created_at;
          return (
            // 项目行外层不能用 <button>：内部还有删除/归档等真实 <button>，
            // 按钮嵌套按钮是非法 HTML（React 会报 validateDOMNesting）。
            // 改用 div + role/tabIndex 保留可访问性与键盘操作。
            <div
              key={p.id}
              role="button"
              tabIndex={0}
              onClick={() => onSelectProject(p.id, latest?.id ?? null)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelectProject(p.id, latest?.id ?? null);
                }
              }}
              className={`w-full text-left rounded-lg px-3 py-2.5 transition-all group cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40 ${
                active
                  ? "bg-cyan-500/15 border border-cyan-500/30"
                  : "hover:bg-white/5 border border-transparent"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <p className={`text-sm font-medium truncate ${active ? "text-cyan-100" : "text-slate-300"}`}>
                    {p.name}
                  </p>
                  {p.notes ? (
                    <p className="text-[10px] text-slate-500 truncate mt-0.5">{p.notes}</p>
                  ) : (
                    <p className="text-[10px] text-slate-600 truncate mt-0.5 font-mono">
                      {p.source_url || p.source_type}
                    </p>
                  )}
                  {(() => {
                    const detected =
                      p.detected_languages?.length
                        ? p.detected_languages
                        : p.latest_scan?.detected_languages ?? [];
                    if (!detected.length && !p.scan_languages?.length) return null;
                    return (
                      <div className="flex flex-wrap items-center gap-1 mt-1">
                        {detected.slice(0, 4).map((d) => (
                          <span
                            key={d.id}
                            className={`text-[9px] px-1.5 py-0.5 rounded border ${
                              d.primary
                                ? "border-emerald-500/30 text-emerald-400/90"
                                : "border-surface-border text-slate-500"
                            }`}
                          >
                            {d.label}
                          </span>
                        ))}
                        {detected.length > 4 && (
                          <span className="text-[9px] text-slate-600">+{detected.length - 4}</span>
                        )}
                        {p.scan_languages && p.scan_languages.length > 0 && (
                          <span
                            className="text-[9px] text-slate-600 truncate max-w-[9rem]"
                            title={`扫描范围：${formatScanLanguages(p.scan_languages)}`}
                          >
                            范围:{formatScanLanguages(p.scan_languages)}
                          </span>
                        )}
                      </div>
                    );
                  })()}
                </div>
                <div className="flex items-center gap-0.5 shrink-0">
                  <button
                    type="button"
                    title="删除项目"
                    className="opacity-0 group-hover:opacity-100 p-1 text-slate-600 hover:text-red-400"
                    onClick={(e) => handleDeleteProject(e, p)}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                  {filter === "archived" ? (
                    <button
                      type="button"
                      title="取消归档"
                      className="opacity-0 group-hover:opacity-100 p-1 text-slate-600 hover:text-cyan-400"
                      onClick={(e) => handleUnarchive(e, p)}
                    >
                      <ArchiveRestore className="w-3.5 h-3.5" />
                    </button>
                  ) : (
                    <button
                      type="button"
                      title="归档"
                      className="opacity-0 group-hover:opacity-100 p-1 text-slate-600 hover:text-amber-400"
                      onClick={(e) => handleArchive(e, p)}
                    >
                      <Archive className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 mt-2">
                {latest ? <StatusIcon status={status} /> : null}
                <span className="text-[10px] text-slate-500">
                  {latest ? STATUS_LABELS[status] : "无扫描"}
                </span>
                <span className="text-[10px] text-slate-600 ml-auto">
                  {p.scan_count} 轮 · {latest?.total_findings ?? 0} 条
                  {latest?.security_score != null ? ` · ${latest.security_score}分` : ""}
                </span>
              </div>
              {activityAt && (
                <p className="text-[10px] text-slate-600 mt-1">{relativeTime(activityAt)}</p>
              )}
              <div className="h-1 bg-slate-800 rounded-full mt-2 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${
                    failed ? "bg-red-500" : done ? "bg-emerald-500" : "bg-cyan-500"
                  }`}
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div className="p-3 border-t border-cyan-500/10 space-y-2">
        <div className="rounded-lg bg-black/30 border border-surface-border p-3">
          <p className="text-[10px] uppercase tracking-wider text-slate-600 mb-2">Server Status</p>
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-500">API</span>
            <span className={healthOk ? "text-emerald-400" : "text-red-400"}>
              {healthOk ? "Online" : "Offline"}
            </span>
          </div>
          <div className="flex items-center justify-between text-xs mt-1">
            <span className="text-slate-500">User</span>
            <span className="text-slate-400 truncate max-w-[120px]">{username}</span>
          </div>
        </div>
        {isAdmin && (
          <button type="button" className="w-full btn-ghost text-xs flex items-center gap-2" onClick={onOpenSettings}>
            <Settings className="w-3.5 h-3.5" /> 系统设置
          </button>
        )}
        <button type="button" className="w-full btn-ghost text-xs flex items-center gap-2" onClick={onLogout}>
          <LogOut className="w-3.5 h-3.5" /> 退出登录
        </button>
        <BuildVersion />
      </div>
    </aside>
  );
}
