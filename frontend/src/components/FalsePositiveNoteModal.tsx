import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

const MIN_LEN = 10;

interface Props {
  open: boolean;
  onCancel: () => void;
  onConfirm: (note: string) => void;
  submitting?: boolean;
}

export function FalsePositiveNoteModal({ open, onCancel, onConfirm, submitting }: Props) {
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setNote("");
      setError(null);
    }
  }, [open]);

  if (!open) return null;

  const submit = () => {
    const trimmed = note.trim();
    if (trimmed.length < MIN_LEN) {
      setError(`误报原因至少 ${MIN_LEN} 字`);
      return;
    }
    onConfirm(trimmed);
  };

  // 必须 portal 到 document.body：`.card` / `.audit-panel` / `.sidebar-shell` 都带
  // `backdrop-blur-sm`，而 `backdrop-filter` 会为 `position: fixed` 后代创建包含块，
  // 使 `fixed inset-0` 变成「相对该面板」定位并被祖先 overflow 裁切 —— 表现为
  // 弹窗能显示但按钮点不到、滚不动、关不掉，且控制台零报错。
  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="card w-full max-w-md p-5 space-y-4 shadow-2xl">
        <div>
          <h3 className="text-lg font-semibold text-white">标记误报</h3>
          <p className="text-xs text-slate-500 mt-1">必须填写误报原因，便于审计追溯与跨扫描继承。</p>
        </div>
        <label className="text-sm text-slate-400 block">
          误报原因（必填，至少 {MIN_LEN} 字）
          <textarea
            className="input mt-1 min-h-[110px]"
            value={note}
            onChange={(e) => {
              setNote(e.target.value);
              setError(null);
            }}
            placeholder="例如：该接口已有鉴权拦截，静态规则误报..."
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
            {submitting ? "提交中..." : "确认误报"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
