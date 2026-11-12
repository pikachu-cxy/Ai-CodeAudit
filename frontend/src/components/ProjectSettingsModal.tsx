import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { api, ApiError, type ProjectSummary, type ScanSummary } from "../api";
import { SCAN_LANGUAGE_OPTIONS, formatScanLanguages } from "../lib/scanLanguages";
import { X } from "lucide-react";

interface Props {
  open: boolean;
  scan: ScanSummary;
  project?: ProjectSummary | null;
  onClose: () => void;
  onSaved: (scan: ScanSummary, project?: ProjectSummary | null) => void;
}

export function ProjectSettingsModal({ open, scan, project, onClose, onSaved }: Props) {
  const [name, setName] = useState(project?.name || scan.name);
  const [notes, setNotes] = useState(project?.notes ?? scan.notes ?? "");
  const [scanLanguages, setScanLanguages] = useState<string[]>(project?.scan_languages ?? []);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setName(project?.name || scan.name);
    setNotes(project?.notes ?? scan.notes ?? "");
    setScanLanguages(project?.scan_languages ?? []);
    setError(null);
  }, [open, scan, project]);

  if (!open) return null;

  const toggleLang = (id: string) => {
    setScanLanguages((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const detected =
    project?.detected_languages?.length
      ? project.detected_languages
      : scan.detected_languages ?? [];

  const handleSave = async () => {
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError("项目名称不能为空");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      let nextProject = project ?? null;
      if (scan.project_id) {
        nextProject = await api.updateProject(scan.project_id, {
          name: trimmedName,
          notes: notes.trim() || null,
          scan_languages: scanLanguages,
        });
      }
      const updated = await api.updateScan(scan.id, {
        name: trimmedName,
        notes: notes.trim() || null,
      });
      onSaved(updated, nextProject);
      onClose();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const created = scan.created_at ? new Date(scan.created_at).toLocaleString("zh-CN") : "—";

  // 见 FalsePositiveNoteModal 的说明：弹窗必须 portal 到 body，
  // 否则会被 `.audit-panel` / `.card` 的 backdrop-filter 劫持定位。
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" onClick={onClose}>
      <div
        className="audit-panel w-full max-w-md p-6 space-y-4 max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white">项目设置</h2>
          <button type="button" className="text-slate-500 hover:text-slate-300" onClick={onClose}>
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-3">
          <label className="block space-y-1">
            <span className="text-xs text-slate-500">项目名称</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={255}
              className="w-full rounded-lg bg-black/30 border border-surface-border px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/40"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-xs text-slate-500">备注</span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              maxLength={2000}
              rows={3}
              placeholder="负责人、环境说明等…"
              className="w-full rounded-lg bg-black/30 border border-surface-border px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/40 resize-none"
            />
          </label>

          {scan.project_id != null && (
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-slate-500">扫描语言范围</span>
                <button
                  type="button"
                  className="text-[11px] text-cyan-500/80 hover:text-cyan-400"
                  onClick={() => setScanLanguages([])}
                >
                  恢复自动识别
                </button>
              </div>
              <p className="text-[11px] text-slate-600">
                清空 = 按仓库文件自动识别（与新建时不选相同）。下次扫描生效。
              </p>
              <div className="flex flex-wrap gap-2">
                {SCAN_LANGUAGE_OPTIONS.map((opt) => {
                  const on = scanLanguages.includes(opt.id);
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => toggleLang(opt.id)}
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
              {scanLanguages.length > 0 && (
                <p className="text-[11px] text-slate-500">
                  当前范围：{formatScanLanguages(scanLanguages)}
                </p>
              )}
            </div>
          )}

          {detected.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-xs text-slate-500">最近扫描检测到的语言</span>
              <div className="flex flex-wrap gap-1.5">
                {detected.map((d) => (
                  <span
                    key={d.id}
                    className={`text-[11px] px-2 py-0.5 rounded border ${
                      d.primary
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                        : "border-surface-border text-slate-400"
                    }`}
                    title={`${d.file_count} 个源文件`}
                  >
                    {d.label}
                    {d.file_count > 0 ? ` · ${d.file_count}` : ""}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="rounded-lg bg-black/20 border border-surface-border p-3 space-y-1 text-xs text-slate-500">
          <p>来源: <span className="text-slate-400">{project?.source_type || scan.source}</span></p>
          {(project?.source_url || scan.source_url) && (
            <p className="truncate">
              地址:{" "}
              <span className="text-slate-400 font-mono">
                {project?.source_url || scan.source_url}
              </span>
            </p>
          )}
          {(project?.default_branch || scan.branch) && (
            <p>
              分支:{" "}
              <span className="text-slate-400">{project?.default_branch || scan.branch}</span>
            </p>
          )}
          {scan.version_label && (
            <p>
              当前版本: <span className="text-slate-400">{scan.version_label}</span>
            </p>
          )}
          <p>创建: <span className="text-slate-400">{created}</span></p>
        </div>

        {error && <p className="text-sm text-red-400">{error}</p>}

        <div className="flex justify-end gap-2 pt-1">
          <button type="button" className="btn-ghost" onClick={onClose} disabled={saving}>
            取消
          </button>
          <button type="button" className="btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? "保存中…" : "保存"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
