import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

/** 加白是「接受风险」的轻量动作，理由通常很短（如「内网接口」），门槛不宜过高。 */
const MIN_LEN = 4;

interface Props {
  open: boolean;
  /** 本次将加白的漏洞条数（勾选批量时 > 1）。 */
  count?: number;
  onCancel: () => void;
  onConfirm: (reason: string) => void;
  submitting?: boolean;
}

export function WhitelistReasonModal({
  open,
  count = 1,
  onCancel,
  onConfirm,
  submitting,
}: Props) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setReason("");
      setError(null);
    }
  }, [open]);

  // Escape 关闭。注意**不做**点遮罩关闭：这是表单弹窗，误点会丢掉已填的原因。
  useEffect(() => {
    if (!open || submitting) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, submitting, onCancel]);

  if (!open) return null;

  const submit = () => {
    const trimmed = reason.trim();
    if (trimmed.length < MIN_LEN) {
      setError(`加白原因至少 ${MIN_LEN} 字`);
      return;
    }
    onConfirm(trimmed);
  };

  // 与其它弹窗一致：必须 portal 到 document.body。祖先的 `backdrop-filter`
  // 会为 `position: fixed` 后代创建包含块，导致弹窗被裁切 / 点不到。
  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="card w-full max-w-md p-5 space-y-4 shadow-2xl">
        <div>
          <h3 className="text-lg font-semibold text-white">
            {count > 1 ? `加入白名单（${count} 条）` : "加入白名单"}
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            加白后，该项目后续扫描不再上报匹配到的漏洞（按规则 + 文件 + 代码位置指纹匹配）。
            可在「项目白名单」里随时移除。
          </p>
        </div>
        <label className="text-sm text-slate-400 block">
          加白原因（必填，至少 {MIN_LEN} 字）
          <textarea
            className="input mt-1 min-h-[110px]"
            value={reason}
            onChange={(e) => {
              setReason(e.target.value);
              setError(null);
            }}
            placeholder="例如：内网接口，已确认无外部可达路径..."
            disabled={submitting}
            autoFocus
          />
        </label>
        {error && <p className="text-xs text-danger">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={submitting}>
            取消
          </button>
          <button type="button" className="btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? "提交中..." : count > 1 ? `确认加白 ${count} 条` : "确认加白"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
