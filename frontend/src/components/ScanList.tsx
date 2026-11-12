import { useEffect, useState, type MouseEvent } from "react";
import { api, type ScanSummary } from "../api";
import { SourceIcon, StatusIcon, STATUS_LABELS, Trash2 } from "./ui";

interface Props {
  onSelect: (id: number) => void;
  onDeleted?: () => void;
  refreshKey: number;
}

export function ScanList({ onSelect, onDeleted, refreshKey }: Props) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => api.listScans({ archived: "false" }).then(setScans);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [refreshKey]);

  const stopRowNav = (e: MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDelete = async (scan: ScanSummary) => {
    if (!confirm(`确定删除扫描任务「${scan.name}」？此操作不可恢复。`)) return;
    setError(null);
    setDeletingId(scan.id);
    try {
      await api.deleteScan(scan.id);
      await load();
      onDeleted?.();
    } catch (e) {
      setError(String(e));
    } finally {
      setDeletingId(null);
    }
  };

  if (scans.length === 0) {
    return (
      <div className="card p-12 text-center text-slate-500">
        <p>暂无扫描任务，请创建新任务开始审计</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {error && (
        <div className="card p-3 text-sm text-red-300 border border-danger/40 bg-danger/10">
          删除失败: {error}
        </div>
      )}
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-border text-slate-400 text-left">
              <th className="p-4 font-medium">任务</th>
              <th className="p-4 font-medium">来源</th>
              <th className="p-4 font-medium">状态</th>
              <th className="p-4 font-medium">发现数</th>
              <th className="p-4 font-medium">安全分</th>
              <th className="p-4 font-medium">创建时间</th>
              <th className="p-4 font-medium w-20 text-center">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-border">
            {scans.map((s) => (
              <tr key={s.id} className="hover:bg-surface transition-colors">
                <td
                  className="p-4 font-medium cursor-pointer"
                  onClick={() => onSelect(s.id)}
                >
                  {s.name}
                </td>
                <td
                  className="p-4 cursor-pointer"
                  onClick={() => onSelect(s.id)}
                >
                  <span className="flex items-center gap-2 text-slate-400">
                    <SourceIcon source={s.source} />
                    {s.source}
                  </span>
                </td>
                <td
                  className="p-4 cursor-pointer"
                  onClick={() => onSelect(s.id)}
                >
                  <span className="flex items-center gap-2">
                    <StatusIcon status={s.status} />
                    {STATUS_LABELS[s.status]}
                  </span>
                </td>
                <td
                  className="p-4 cursor-pointer"
                  onClick={() => onSelect(s.id)}
                >
                  <span className={s.total_findings > 0 ? "text-warning font-medium" : ""}>
                    {s.total_findings}
                  </span>
                </td>
                <td
                  className="p-4 cursor-pointer font-mono"
                  onClick={() => onSelect(s.id)}
                >
                  {s.security_score != null ? (
                    <span
                      className={
                        s.security_score >= 80
                          ? "text-emerald-400"
                          : s.security_score >= 60
                            ? "text-amber-300"
                            : "text-red-400"
                      }
                    >
                      {s.security_score}
                    </span>
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                <td
                  className="p-4 text-slate-500 cursor-pointer"
                  onClick={() => onSelect(s.id)}
                >
                  {new Date(s.created_at).toLocaleString("zh-CN")}
                </td>
                <td className="p-4 text-center" onClick={stopRowNav}>
                  <button
                    type="button"
                    className="inline-flex p-2 rounded-lg text-slate-500 hover:text-danger hover:bg-danger/10 transition-colors disabled:opacity-50"
                    title="删除任务"
                    disabled={deletingId === s.id}
                    onMouseDown={stopRowNav}
                    onClick={() => handleDelete(s)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
