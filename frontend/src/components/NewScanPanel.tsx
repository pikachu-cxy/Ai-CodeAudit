import { useEffect, useState } from "react";
import { api, ApiError, type DuplicateGitUrlDetail, type ProjectSummary } from "../api";
import { SCAN_LANGUAGE_OPTIONS } from "../lib/scanLanguages";
import { GitBranch, Upload } from "./ui";

/** 邮件报告可选的严重级别（与后端 _REPORT_SEVERITY_ORDER 同序，不含 UNKNOWN）。 */
const EMAIL_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/**
 * 是否是可以拿去查重的「完整 GitLab 项目地址」。
 *
 * 后端 split_project_url 要求 scheme + host + **至少一段路径**，否则抛 ValueError
 * 让 /projects/check-source-url 返回 400。而本组件在挂载时会把 project_url 预填成
 * 配置里的默认主机（如 https://gitlab.example.com/），只有 host 没有项目路径，
 * 一切到 GitLab 标签就会打出一个必然失败的 400。
 * 这里先做同样的判断，既消掉噪音请求，也避免用户边输入边发无用请求。
 */
function isCompleteGitlabProjectUrl(raw: string): boolean {
  const value = (raw || "").trim();
  if (!value) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  return parsed.pathname.replace(/^\/+|\/+$/g, "").length > 0;
}

interface Props {
  onCreated: (id: number) => void;
  /** When set, append a new scan version under this project. */
  projectId?: number | null;
  projectHint?: ProjectSummary | null;
}

export function NewScanPanel({ onCreated, projectId: fixedProjectId, projectHint }: Props) {
  const [tab, setTab] = useState<"upload" | "gitlab">("upload");
  const [mode, setMode] = useState<"new" | "append">(fixedProjectId ? "append" : "new");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [tokenConfigured, setTokenConfigured] = useState(false);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | "">(
    fixedProjectId ?? ""
  );
  const [duplicateProject, setDuplicateProject] = useState<Pick<ProjectSummary, "id" | "name" | "source_url" | "default_branch"> | null>(null);
  const [duplicateCode, setDuplicateCode] = useState<string | null>(null);
  const [scanLanguages, setScanLanguages] = useState<string[]>([]);

  const [uploadName, setUploadName] = useState("");
  const [file, setFile] = useState<File | null>(null);

  const [gitlab, setGitlab] = useState({
    name: "",
    project_url: "",
    branch: "main",
    access_token: "",
    notify_emails: "",
    // 邮件报告范围：空数组 = 发送全量报告（与后端默认一致）。
    report_severities: [] as string[],
  });

  const parseNotifyEmails = (raw: string): string[] | undefined => {
    const emails = raw
      .split(/[,;，；\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    return emails.length ? emails : undefined;
  };

  useEffect(() => {
    if (fixedProjectId) {
      setMode("append");
      setSelectedProjectId(fixedProjectId);
    }
  }, [fixedProjectId]);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => {
        setTokenConfigured(Boolean(s.gitlab_access_token_configured));
        setGitlab((prev) => ({
          ...prev,
          branch: s.gitlab_default_branch || prev.branch || "main",
          project_url: prev.project_url || (s.gitlab_default_url ? `${s.gitlab_default_url.replace(/\/$/, "")}/` : ""),
        }));
      })
      .catch(() => {
        /* ignore — form still usable with manual token */
      });
  }, []);

  useEffect(() => {
    if (mode !== "append" || fixedProjectId) return;
    let cancelled = false;
    api
      .listProjects({ archived: "false" })
      .then((list) => {
        if (cancelled) return;
        setProjects(list);
        setSelectedProjectId((prev) => (prev === "" && list[0] ? list[0].id : prev));
      })
      .catch(() => {
        if (!cancelled) setProjects([]);
      });
    return () => {
      cancelled = true;
    };
  }, [mode, fixedProjectId]);

  useEffect(() => {
    if (mode !== "append") return;
    const pid = typeof selectedProjectId === "number" ? selectedProjectId : fixedProjectId;
    const fromList = projects.find((p) => p.id === pid);
    const p = projectHint?.id === pid ? projectHint : fromList;
    if (!p) return;
    setGitlab((prev) => ({
      ...prev,
      project_url: p.source_url || prev.project_url,
      branch: p.default_branch || prev.branch,
      name: prev.name || `${p.name} 新版本`,
    }));
    if (p.source_type === "gitlab") setTab("gitlab");
    else if (p.source_type === "upload") setTab("upload");
  }, [mode, selectedProjectId, fixedProjectId, projects, projectHint]);

  useEffect(() => {
    if (mode !== "new" || tab !== "gitlab" || !isCompleteGitlabProjectUrl(gitlab.project_url)) {
      setDuplicateCode((code) => {
        if (code === "duplicate_git_url") {
          setDuplicateProject(null);
          return null;
        }
        return code;
      });
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      api
        .checkSourceUrl(gitlab.project_url.trim())
        .then((r) => {
          if (cancelled) return;
          if (r.duplicate && r.project) {
            setDuplicateProject({
              id: r.project.id,
              name: r.project.name,
              source_url: r.project.source_url ?? null,
              default_branch: r.project.default_branch ?? null,
            });
            setDuplicateCode("duplicate_git_url");
            return;
          }
          setDuplicateCode((code) => {
            if (code === "duplicate_git_url") {
              setDuplicateProject(null);
              return null;
            }
            return code;
          });
        })
        .catch(() => {
          /* keep last known duplicate state */
        });
    }, 400);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [mode, tab, gitlab.project_url]);

  useEffect(() => {
    if (mode !== "new") return;
    const typedName = (tab === "upload" ? uploadName : gitlab.name).trim();
    if (!typedName) {
      setDuplicateCode((code) => {
        if (code === "duplicate_project_name") {
          setDuplicateProject(null);
          return null;
        }
        return code;
      });
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      api
        .checkProjectName(typedName)
        .then((r) => {
          if (cancelled) return;
          const existing = r.project;
          if (r.duplicate && existing) {
            setDuplicateCode((code) => {
              if (code === "duplicate_git_url") return code;
              setDuplicateProject({
                id: existing.id,
                name: existing.name,
                source_url: existing.source_url ?? null,
                default_branch: existing.default_branch ?? null,
              });
              return "duplicate_project_name";
            });
            return;
          }
          setDuplicateCode((code) => {
            if (code === "duplicate_project_name") {
              setDuplicateProject(null);
              return null;
            }
            return code;
          });
        })
        .catch(() => {
          /* keep last known duplicate state */
        });
    }, 400);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [mode, tab, uploadName, gitlab.name]);

  const applyDuplicateConflict = (detail: DuplicateGitUrlDetail) => {
    setDuplicateProject({
      id: detail.project.id,
      name: detail.project.name,
      source_url: detail.project.source_url ?? null,
      default_branch: null,
    });
    setDuplicateCode(detail.code || "duplicate_git_url");
    setError(
      detail.message ||
        (detail.code === "duplicate_project_name"
          ? "项目名已存在，请改用「追加扫描版本」。"
          : "该 Git 地址已存在，请改用「追加扫描版本」。")
    );
  };

  const switchToAppendProject = (project: Pick<ProjectSummary, "id" | "name" | "source_url" | "default_branch">) => {
    setMode("append");
    setSelectedProjectId(project.id);
    setDuplicateProject(null);
    setDuplicateCode(null);
    setError("");
    setGitlab((prev) => ({
      ...prev,
      project_url: project.source_url || prev.project_url,
      branch: project.default_branch || prev.branch,
      name: prev.name || `${project.name} 新版本`,
    }));
    setTab(project.source_url ? "gitlab" : "upload");
  };

  const targetProjectId =
    mode === "append"
      ? (typeof selectedProjectId === "number" ? selectedProjectId : fixedProjectId ?? null)
      : null;

  const toggleScanLanguage = (id: string) => {
    setScanLanguages((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const submitUpload = async () => {
    if (!file) {
      setError("请选择 ZIP 文件");
      return;
    }
    if (mode === "append" && !targetProjectId) {
      setError("请选择要追加版本的项目");
      return;
    }
    if (mode === "new" && duplicateProject && duplicateCode === "duplicate_project_name") {
      setError(`项目名「${duplicateProject.name}」已存在，请改用「追加扫描版本」。`);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const langs = mode === "new" && scanLanguages.length ? scanLanguages : undefined;
      const scan = targetProjectId
        ? await api.uploadProjectScan(targetProjectId, file, uploadName || undefined)
        : await api.uploadScan(file, uploadName || undefined, undefined, langs);
      onCreated(scan.id);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.detail && typeof e.detail === "object") {
        const detail = e.detail as DuplicateGitUrlDetail;
        if (detail.project) {
          applyDuplicateConflict(detail);
          return;
        }
      }
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const submitGitlab = async () => {
    if (mode === "append" && !targetProjectId) {
      setError("请选择要追加版本的项目");
      return;
    }
    if (mode === "new" && !gitlab.project_url.trim()) {
      setError("请填写 GitLab 项目地址");
      return;
    }
    if (mode === "new" && duplicateProject) {
      setError(
        duplicateCode === "duplicate_project_name"
          ? `项目名「${duplicateProject.name}」已存在，请改用「追加扫描版本」。`
          : `该 Git 地址已存在于项目「${duplicateProject.name}」，请改用「追加扫描版本」。`
      );
      return;
    }
    if (!gitlab.access_token.trim() && !tokenConfigured) {
      setError("请先在系统设置中配置 GitLab Token，或在此填写 Access Token");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const notifyEmails = parseNotifyEmails(gitlab.notify_emails);
      // 不勾选任何级别时不传该字段，让后端沿用「全量报告」的旧行为。
      const reportSeverities = gitlab.report_severities.length
        ? gitlab.report_severities
        : undefined;
      const langs = mode === "new" && scanLanguages.length ? scanLanguages : undefined;
      const scan = targetProjectId
        ? await api.gitlabProjectScan(targetProjectId, {
            name: gitlab.name || undefined,
            project_url: gitlab.project_url.trim() || undefined,
            branch: gitlab.branch || undefined,
            access_token: gitlab.access_token.trim() || undefined,
            notify_emails: notifyEmails,
            report_severities: reportSeverities,
          })
        : await api.gitlabScan({
            name: gitlab.name || undefined,
            project_url: gitlab.project_url.trim(),
            branch: gitlab.branch || undefined,
            access_token: gitlab.access_token.trim() || undefined,
            notify_emails: notifyEmails,
            report_severities: reportSeverities,
            scan_languages: langs,
          });
      onCreated(scan.id);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.detail && typeof e.detail === "object") {
        const detail = e.detail as DuplicateGitUrlDetail;
        if (detail.project) {
          applyDuplicateConflict(detail);
          return;
        }
      }
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold mb-4">
        {mode === "append" ? "为项目追加扫描版本" : "新建扫描任务"}
      </h2>

      {!fixedProjectId && (
        <div className="flex gap-2 mb-4">
          <button
            type="button"
            className={`px-3 py-1.5 rounded-lg text-sm ${
              mode === "new" ? "bg-accent text-white" : "bg-surface text-slate-400 hover:text-white"
            }`}
            onClick={() => {
              setMode("new");
              setDuplicateProject(null);
              setDuplicateCode(null);
            }}
          >
            新建项目
          </button>
          <button
            type="button"
            className={`px-3 py-1.5 rounded-lg text-sm ${
              mode === "append" ? "bg-accent text-white" : "bg-surface text-slate-400 hover:text-white"
            }`}
            onClick={() => setMode("append")}
          >
            已有项目追加版本
          </button>
        </div>
      )}

      {mode === "append" && !fixedProjectId && (
        <div className="mb-4">
          <label className="text-sm text-slate-400 mb-1 block">选择项目</label>
          <select
            className="input"
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value ? Number(e.target.value) : "")}
          >
            <option value="">请选择…</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}（{p.scan_count} 轮）
              </option>
            ))}
          </select>
        </div>
      )}

      {mode === "append" && (projectHint || fixedProjectId) && (
        <p className="text-xs text-slate-500 mb-4">
          目标项目：{projectHint?.name || `#${fixedProjectId}`}
          {projectHint?.source_type === "upload" && " · 上传型项目请重新上传 ZIP"}
        </p>
      )}

      <div className="flex gap-2 mb-6">
        <button
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === "upload" ? "bg-accent text-white" : "bg-surface text-slate-400 hover:text-white"
          }`}
          onClick={() => setTab("upload")}
        >
          <Upload className="w-4 h-4" /> 上传代码
        </button>
        <button
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === "gitlab" ? "bg-accent text-white" : "bg-surface text-slate-400 hover:text-white"
          }`}
          onClick={() => setTab("gitlab")}
        >
          <GitBranch className="w-4 h-4" /> GitLab 接入
        </button>
      </div>

      {mode === "new" && duplicateProject && (
        <div className="text-sm p-3 mb-4 rounded-lg border border-warning/40 bg-warning/10 text-warning space-y-2">
          <p>
            {duplicateCode === "duplicate_project_name"
              ? `项目名「${duplicateProject.name}」已存在（#${duplicateProject.id}），无法重复新建。`
              : `该 Git 地址已关联项目「${duplicateProject.name}」（#${duplicateProject.id}），无法重复新建。`}
          </p>
          <button
            type="button"
            className="btn-ghost border border-warning/40 text-sm"
            onClick={() => switchToAppendProject(duplicateProject)}
          >
            追加扫描版本到该项目
          </button>
        </div>
      )}

      {mode === "new" && (
        <div className="mb-6 space-y-2">
          <label className="text-sm text-slate-400 block">扫描语言（可选，可多选）</label>
          <p className="text-xs text-slate-600">
            不选则系统按仓库文件自动识别（与以前相同）；多选则扫描时挂上对应语言规则包。
          </p>
          <div className="flex flex-wrap gap-2">
            {SCAN_LANGUAGE_OPTIONS.map((opt) => {
              const on = scanLanguages.includes(opt.id);
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => toggleScanLanguage(opt.id)}
                  className={`px-2.5 py-1 rounded-md text-xs border transition-colors ${
                    on
                      ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-300"
                      : "border-surface-border bg-black/20 text-slate-500 hover:text-slate-300"
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {tab === "upload" ? (
        <div className="space-y-4">
          <div>
            <label className="text-sm text-slate-400 mb-1 block">任务名称（可选）</label>
            <input className="input" value={uploadName} onChange={(e) => setUploadName(e.target.value)} />
          </div>
          <div>
            <label className="text-sm text-slate-400 mb-1 block">上传 ZIP 压缩包</label>
            <div
              className="border-2 border-dashed border-surface-border rounded-xl p-8 text-center hover:border-accent/50 transition-colors cursor-pointer"
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const f = e.dataTransfer.files[0];
                if (f) setFile(f);
              }}
              onClick={() => document.getElementById("file-input")?.click()}
            >
              <Upload className="w-10 h-10 mx-auto text-slate-500 mb-2" />
              <p className="text-sm text-slate-400">
                {file ? file.name : "拖拽 ZIP 文件到此处，或点击选择"}
              </p>
              <input
                id="file-input"
                type="file"
                accept=".zip"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
            </div>
          </div>
          <button className="btn-primary w-full" onClick={submitUpload} disabled={loading}>
            {loading ? "提交中..." : mode === "append" ? "追加扫描版本" : "创建任务"}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <div
            className={`text-xs p-3 rounded-lg border ${
              tokenConfigured
                ? "border-success/40 bg-success/10 text-success"
                : "border-warning/40 bg-warning/10 text-warning"
            }`}
          >
            {tokenConfigured
              ? "已使用系统设置中的 GitLab Token；下方可留空，或临时覆盖。"
              : "尚未在系统设置中配置 GitLab Token，请先去设置，或在下方临时填写。"}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm text-slate-400 mb-1 block">任务名称（可选）</label>
              <input className="input" value={gitlab.name} onChange={(e) => setGitlab({ ...gitlab, name: e.target.value })} />
            </div>
            <div>
              <label className="text-sm text-slate-400 mb-1 block">分支</label>
              <input className="input" value={gitlab.branch} onChange={(e) => setGitlab({ ...gitlab, branch: e.target.value })} />
            </div>
          </div>
          <div>
            <label className="text-sm text-slate-400 mb-1 block">
              GitLab 项目地址{mode === "append" ? "（可选，默认用项目配置）" : ""}
            </label>
            <input
              className="input"
              value={gitlab.project_url}
              onChange={(e) => setGitlab({ ...gitlab, project_url: e.target.value })}
              placeholder="例如：https://gitlab.example.com/group/backend-service.git"
            />
          </div>
          <div>
            <label className="text-sm text-slate-400 mb-1 block">
              Access Token{tokenConfigured ? "（可选，留空则用系统设置）" : ""}
            </label>
            <input
              className="input font-mono"
              type="password"
              value={gitlab.access_token}
              onChange={(e) => setGitlab({ ...gitlab, access_token: e.target.value })}
              placeholder={tokenConfigured ? "留空使用系统设置中的 Token" : "需要 read_repository 权限"}
            />
          </div>
          <div>
            <label className="text-sm text-slate-400 mb-1 block">
              报告收件邮箱（可选，逗号分隔）
            </label>
            <input
              className="input"
              value={gitlab.notify_emails}
              onChange={(e) => setGitlab({ ...gitlab, notify_emails: e.target.value })}
              placeholder="a@example.com, b@example.com"
            />
            <p className="text-xs text-slate-600 mt-1">
              扫描完成后发送 HTML 漏洞汇总报告（需在系统设置中配置 SMTP）。
            </p>
          </div>
          <div>
            <label className="text-sm text-slate-400 mb-1 block">
              邮件报告范围（可选，不选 = 全量）
            </label>
            <div className="flex flex-wrap gap-1.5">
              {EMAIL_SEVERITY_ORDER.map((s) => {
                const active = gitlab.report_severities.includes(s);
                return (
                  <button
                    key={s}
                    type="button"
                    aria-pressed={active}
                    className={`px-2.5 py-1 rounded-lg text-xs border transition-colors ${
                      active
                        ? "border-cyan-500/40 bg-cyan-500/15 text-cyan-100"
                        : "border-surface-border text-slate-400 hover:text-slate-200 hover:bg-white/[0.04]"
                    }`}
                    onClick={() =>
                      setGitlab({
                        ...gitlab,
                        report_severities: active
                          ? gitlab.report_severities.filter((x) => x !== s)
                          : [...gitlab.report_severities, s],
                      })
                    }
                  >
                    {s}
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-slate-600 mt-1">
              只把勾选的严重级别写进邮件报告；不勾选则发送全量报告。
            </p>
          </div>
          <button className="btn-primary w-full" onClick={submitGitlab} disabled={loading}>
            {loading ? "克隆中..." : mode === "append" ? "追加扫描版本" : "创建任务"}
          </button>
        </div>
      )}

      {error && <p className="mt-4 text-sm text-danger">{error}</p>}
    </div>
  );
}
