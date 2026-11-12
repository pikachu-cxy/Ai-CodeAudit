import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

interface Props {
  open: boolean;
  /** targeted = 定向复测（只核实已有漏洞）；full = 全量扫描（重跑完整流水线）。 */
  mode: "targeted" | "full";
  /** 基线扫描的分支，作为默认值。 */
  baselineBranch: string | null;
  /** 上传型项目没有分支概念。 */
  branchEditable: boolean;
  /** 本次复测范围说明。 */
  scopeHint: string;
  submitting?: boolean;
  onCancel: () => void;
  onConfirm: (branch: string | null) => void;
}

export function RetestOptionsModal({
  open,
  mode,
  baselineBranch,
  branchEditable,
  scopeHint,
  submitting,
  onCancel,
  onConfirm,
}: Props) {
  const [branch, setBranch] = useState("");

  useEffect(() => {
    if (open) {
      setBranch(baselineBranch || "");
    }
  }, [open, baselineBranch]);

  // Escape 关闭。注意**不做**点遮罩关闭：误点会丢掉刚改的分支名。
  useEffect(() => {
    if (!open || submitting) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, submitting, onCancel]);

  if (!open) return null;

  const trimmed = branch.trim();
  const changed = trimmed !== (baselineBranch || "");
  const title = mode === "full" ? "全量扫描" : "定向复测";

  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="card w-full max-w-md p-5 space-y-4 shadow-2xl">
        <div>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <p className="text-xs text-slate-500 mt-1">{scopeHint}</p>
        </div>

        {branchEditable ? (
          <label className="text-sm text-slate-400 block">
            复测分支
            <input
              className="input mt-1"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder={baselineBranch || "main"}
              disabled={submitting}
              autoFocus
            />
            <span className="text-xs text-slate-500 mt-1 block">
              默认沿用上次扫描的分支
              {baselineBranch ? `（${baselineBranch}）` : ""}
              。可改成其它分支，例如把 master 换成 test 再复测。
            </span>
          </label>
        ) : (
          <p className="text-xs text-slate-500">
            上传型项目不使用 Git 分支：将使用同一项目下最新已完成的代码版本，
            请先「追加新版本」再复测。
          </p>
        )}

        {changed && branchEditable && (
          <p className="text-xs text-amber-300/90">
            将拉取分支「{trimmed || "(留空则沿用基线分支)"}」的代码，而非上次扫描的
            {baselineBranch ? `「${baselineBranch}」` : "分支"}。
          </p>
        )}

        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={submitting}>
            取消
          </button>
          <button
            type="button"
            className="btn-primary"
            onClick={() => onConfirm(trimmed || null)}
            disabled={submitting}
          >
            {submitting ? "创建中..." : "开始"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
