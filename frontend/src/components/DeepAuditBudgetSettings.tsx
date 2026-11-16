import { useState, type FormEvent } from "react";
import { api, type DeepAuditBudgetSettings as Budget } from "../api";
import { useAsyncData } from "../shared/hooks/useAsyncData";
import { ErrorState, LoadingState } from "../shared/ui";
import { InlineMessage } from "../shared/ui/forms";

const FIELDS = [
  { key: "max_llm_rounds", label: "最大 LLM 轮次", min: 1 },
  { key: "max_tool_calls", label: "最大工具调用次数", min: 1 },
  { key: "max_total_tokens", label: "最大总 Token", min: 256 },
] as const;

export function DeepAuditBudgetSettings({ onSaved }: { onSaved?: () => void }) {
  const budget = useAsyncData(api.getDeepAuditBudget);
  if (budget.loading) return <LoadingState label="正在读取执行预算…" />;
  if (budget.error || !budget.data) {
    return <ErrorState message={budget.error ?? "无法读取执行预算"} onRetry={budget.reload} />;
  }
  return <BudgetForm initial={budget.data} onSaved={onSaved} />;
}

function BudgetForm({ initial, onSaved }: { initial: Budget; onSaved?: () => void }) {
  const [form, setForm] = useState(initial);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (saving) return;
    setNotice(null);
    if (FIELDS.some(({ key, min }) => !Number.isSafeInteger(form[key]) || form[key] < min)) {
      setNotice({ tone: "error", text: "请输入符合最小值要求的整数。" });
      return;
    }
    setSaving(true);
    try {
      setForm(await api.updateDeepAuditBudget(form));
      setNotice({ tone: "success", text: "预算已保存，下次启动 Deep Audit V1 时生效。" });
      onSaved?.();
    } catch (error) {
      setNotice({ tone: "error", text: `保存失败：${String(error)}` });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={(event) => void save(event)} className="max-w-2xl space-y-5">
      <p className="text-sm text-[var(--text-secondary)]">
        这些上限由整次运行中的任务共享。选择自定义 Agent 时，其配置可能进一步收紧预算。
      </p>
      <div className="grid gap-4 sm:grid-cols-3">
        {FIELDS.map(({ key, label, min }) => (
          <label key={key} className="block text-sm">
            {label}
            <input
              className="input mt-2 w-full"
              type="number"
              min={min}
              step={1}
              required
              disabled={saving}
              value={form[key] || ""}
              onChange={(event) => setForm((current) => ({ ...current, [key]: Number(event.target.value) }))}
            />
          </label>
        ))}
      </div>
      <p className="text-xs text-[var(--text-secondary)]">恢复中断运行时仍使用该次运行原有的预算。</p>
      {notice && <InlineMessage tone={notice.tone}>{notice.text}</InlineMessage>}
      <button className="btn-primary" type="submit" disabled={saving}>
        {saving ? "保存中…" : "保存预算"}
      </button>
    </form>
  );
}
