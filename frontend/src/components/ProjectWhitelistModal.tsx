import { useCallback, useEffect, useState } from "react";
import { createPortal } from "react-dom";

import { api, type ProjectWhitelistEntry } from "../api";

const STATUS_LABEL: Record<string, string> = {
  whitelist: "手动加白",
  false_positive: "误报",
};

function statusLabel(status: string): string {
  return STATUS_LABEL[status] || status || "未知";
}

function statusClass(status: string): string {
  return status === "whitelist"
    ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"
    : "bg-amber-500/15 text-amber-300 border-amber-500/30";
}

interface Props {
  open: boolean;
  projectId: number | null;
  projectName?: string | null;
  onClose: () => void;
  /** 删除条目后回调，便于外层刷新扫描/项目数据。 */
  onChanged?: () => void;
}

export function ProjectWhitelistModal({
  open,
  projectId,
  projectName,
  onClose,
  onChanged,
}: Props) {
  const [rows, setRows] = useState<ProjectWhitelistEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const load = useCallback(async () => {
    if (projectId == null) return;
    setLoading(true);
    setError(null);
    try {
      setRows(await api.listProjectWhitelist(projectId));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    if (open) {
      void load();
    } else {
      setRows([]);
      setError(null);
    }
  }, [open, load]);

  // Escape 关闭，与点遮罩关闭（见下面的 onClick={onClose}）保持一致。
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const remove = async (entry: ProjectWhitelistEntry) => {
    if (projectId == null) return;
    if (!confirm(`移除该白名单条目？\n\n${entry.reason || "(无原因)"}\n\n移除后重新扫描会重新上报此漏洞。`)) {
      return;
    }
    setDeletingId(entry.id);
    setError(null);
    try {
      await api.deleteProjectWhitelist(projectId, entry.id);
      setRows((prev) => prev.filter((r) => r.id !== entry.id));
      onChanged?.();
    } catch (e) {
      setError(String(e));
    } finally {
      setDeletingId(null);
    }
  };

  return createPortal(
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="card w-full max-w-3xl p-5 space-y-4 shadow-2xl max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-lg font-semibold text-white">项目白名单</h3>
            <p className="text-xs text-slate-500 mt-1">
              {projectName ? `项目「${projectName}」· ` : ""}
              命中的漏洞在该项目后续扫描中不再上报。误报（LLM 或人工标记）也会出现在这里。
            </p>
          </div>
          <button type="button" className="btn-ghost" onClick={onClose}>
            关闭
          </button>
        </div>

        {error && <p className="text-xs text-danger">{error}</p>}

        <div className="overflow-auto flex-1">
          {loading ? (
            <p className="text-xs text-slate-500 py-6 text-center">正在加载白名单…</p>
          ) : rows.length === 0 ? (
            <p className="text-xs text-slate-500 py-6 text-center">
              暂无白名单条目。在扫描详情里勾选漏洞后点「加入白名单」即可。
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500">
                <tr className="text-left">
                  <th className="py-2 pr-3 font-normal">状态</th>
                  <th className="py-2 pr-3 font-normal">规则</th>
                  <th className="py-2 pr-3 font-normal">文件</th>
                  <th className="py-2 pr-3 font-normal">原因</th>
                  <th className="py-2 pr-3 font-normal">创建</th>
                  <th className="py-2 font-normal text-right">操作</th>
                </tr>
              </thead>
              <tbody className="text-slate-300">
                {rows.map((row) => (
                  <tr key={row.id} className="border-t border-white/5 align-top">
                    <td className="py-2 pr-3 whitespace-nowrap">
                      <span
                        className={`inline-block rounded border px-1.5 py-0.5 text-xs ${statusClass(row.status)}`}
                      >
                        {statusLabel(row.status)}
                      </span>
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs break-all max-w-[220px]">
                      {row.rule_id || "-"}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs break-all max-w-[180px]">
                      {row.file_path || "-"}
                    </td>
                    <td className="py-2 pr-3 max-w-[260px] break-words">{row.reason || "-"}</td>
                    <td className="py-2 pr-3 text-xs text-slate-500 whitespace-nowrap">
                      <div>{row.created_by || "-"}</div>
                      <div>{row.created_at ? row.created_at.slice(0, 19).replace("T", " ") : ""}</div>
                    </td>
                    <td className="py-2 text-right">
                      <button
                        type="button"
                        className="btn-ghost !text-danger"
                        disabled={deletingId === row.id}
                        onClick={() => remove(row)}
                      >
                        {deletingId === row.id ? "移除中…" : "移除"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <p className="text-xs text-slate-500">
          提示：移除条目不会回滚历史扫描里已经标记为误报的结果，重新跑一次扫描即可按最新白名单重新判定。
        </p>
      </div>
    </div>,
    document.body,
  );
}
