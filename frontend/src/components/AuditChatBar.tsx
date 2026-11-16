import { useEffect, useRef, useState } from "react";
import { ArrowUp, Bot, ChevronDown, LoaderCircle, UserRound, Zap } from "lucide-react";
import type { AgentAction, AgentChatMessage, AgentTaskItem, AgentTaskMode } from "../api";
import { AgentTaskResults } from "./AgentTaskResults";

interface Props {
  disabled?: boolean;
  liveReply?: string;
  progress?: string;
  onCommand: (text: string) => Promise<void>;
  notice?: string | null;
  messages: AgentChatMessage[];
  actions: AgentAction[];
  onRunTask: (mode: AgentTaskMode) => void;
  taskNotice?: string | null;
  taskItems: AgentTaskItem[];
  taskMode?: string | null;
  onOpenFinding: (findingId: number) => void;
  onClearTaskResults: () => void;
}

type Shortcut =
  | { label: string; mode: AgentTaskMode }
  | { label: string; text: string };

const SHORTCUTS: Shortcut[] = [
  { label: "补盲越权", mode: "auth_gap_hunt" },
  { label: "补盲业务流程", mode: "biz_gap_hunt" },
  { label: "漏洞优先级排序", mode: "prioritize" },
  { label: "可利用性研判（快速）", text: "运行可利用性研判，使用快速模式" },
  { label: "可利用性研判（深度）", text: "运行可利用性研判，使用深度模式" },
  { label: "LLM 端点审计", text: "运行 LLM 端点驱动深度审计，不预设漏洞类型，先自由发挥。" },
  { label: "只看支付模块补盲越权", text: "只看 payment/pay/order 模块，帮我补盲越权，给出 Top 10 并按优先级排序。" },
  { label: "只看订单流程补盲逻辑", text: "只看 order/checkout/refund 流程，帮我补盲业务流程漏洞（竞态/幂等/绕过），给出 Top 10。" },
];

const ACTION_LABELS: Record<string, string> = {
  fp_audit: "SAST 误报审计",
  sast_deep_audit: "数据流深度研判",
  llm_review: "LLM 复审",
  llm_audit: "LLM 端点审计",
  rerun: "清空并重置",
};

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
  });
}

function ReplyText({ text }: { text: string }) {
  return (
    <div className="whitespace-pre-wrap break-words text-sm leading-7 [overflow-wrap:anywhere]">
      {text.split(/(\*\*[^*\n]+\*\*|`[^`\n]+`)/g).map((part, index) => {
        if (index % 2 === 0) return part;
        if (part.startsWith("**")) return <strong key={index}>{part.slice(2, -2)}</strong>;
        return <code key={index} className="rounded border border-[var(--conversation-border)] px-1 text-[0.9em]">{part.slice(1, -1)}</code>;
      })}
    </div>
  );
}

export function AuditChatBar({
  disabled, liveReply, progress, onCommand, notice, messages, actions, onRunTask,
  taskNotice, taskItems, taskMode, onOpenFinding, onClearTaskResults,
}: Props) {
  const [input, setInput] = useState("");
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const transcript = useRef<HTMLDivElement>(null);
  const composer = useRef<HTMLTextAreaElement>(null);
  const followLatest = useRef(true);
  const hasResults = Boolean(taskNotice || taskItems.length);
  const empty = !messages.length && !progress && !liveReply && !hasResults && !notice && !actions.length;

  useEffect(() => {
    const panel = transcript.current;
    if (panel && followLatest.current) panel.scrollTop = panel.scrollHeight;
  }, [messages, liveReply, progress, taskItems, taskNotice, notice]);

  const submit = async () => {
    const text = input.trim();
    if (!text || disabled) return;
    followLatest.current = true;
    setInput("");
    setShortcutsOpen(false);
    await onCommand(text);
  };

  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <div
        ref={transcript} role="log" aria-label="对话消息" aria-live="off"
        className="min-h-0 flex-1 overflow-y-auto"
        onScroll={({ currentTarget: panel }) => {
          followLatest.current = panel.scrollHeight - panel.clientHeight - panel.scrollTop < 64;
        }}
      >
        {empty ? (
          <div className="grid h-full min-h-32 place-content-center justify-items-center gap-3 px-5 text-center">
            <span className="grid h-12 w-12 place-items-center rounded-full bg-[var(--conversation-muted)]">
              <Bot size={24} />
            </span>
            <h2 className="text-base font-semibold">开始和审计 Agent 对话</h2>
            <p className="text-sm text-[var(--conversation-secondary)]">可以询问扫描结果、漏洞证据或相关代码。</p>
          </div>
        ) : (
          <div className="mx-auto flex max-w-5xl flex-col gap-5 px-4 py-5 sm:px-6">
            {actions.length > 0 && (
              <details className="text-xs text-[var(--conversation-secondary)]">
                <summary className="cursor-pointer py-1">审计操作记录（{actions.length}）</summary>
                <ul className="mt-2 space-y-2 border-l border-[var(--conversation-border)] pl-3">
                  {actions.slice().reverse().map((action, index) => (
                    <li key={`${action.created_at}-${index}`}>
                      <span className="font-medium">{ACTION_LABELS[action.action] ?? action.action}</span>
                      <span className="ml-2">{formatTime(action.created_at)}</span>
                      {action.result && <p className="mt-1 whitespace-pre-wrap break-words">{action.result}</p>}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {messages.slice(-30).map((message, index) => {
              const own = message.role === "user";
              return (
                <article key={`${message.created_at}-${index}`}
                  className={`flex min-w-0 items-start gap-2 ${own ? "max-w-[88%] flex-row-reverse self-end" : ""}`}>
                  <span aria-hidden="true" className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-[var(--conversation-muted)]">
                    {own ? <UserRound size={16} /> : <Bot size={17} />}
                  </span>
                  <div className={`min-w-0 ${own ? "text-right" : "flex-1"}`}>
                    <div className={`rounded-xl px-4 py-2.5 text-left ${own
                      ? "bg-[var(--conversation-action)] text-[var(--conversation-action-text)]"
                      : "bg-[var(--conversation-muted)]"}`}>
                      {own ? <p className="whitespace-pre-wrap break-words text-sm leading-7 [overflow-wrap:anywhere]">{message.content}</p>
                        : <ReplyText text={message.content} />}
                    </div>
                    {formatTime(message.created_at) && (
                      <time dateTime={message.created_at} className="mt-1 block text-[11px] text-[var(--conversation-secondary)]">
                        {formatTime(message.created_at)}
                      </time>
                    )}
                  </div>
                </article>
              );
            })}
            {(progress || liveReply) && (
              <article className="flex min-w-0 items-start gap-2">
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-[var(--conversation-muted)]"><Bot size={17} /></span>
                <div className="min-w-0 flex-1">
                  {liveReply ? (
                    <div className="rounded-xl bg-[var(--conversation-muted)] px-4 py-2.5"><ReplyText text={liveReply} /></div>
                  ) : (
                    <div role="status" className="flex items-center gap-2 py-2 text-sm text-[var(--conversation-secondary)]">
                      <LoaderCircle size={14} className="animate-spin" />{progress}
                    </div>
                  )}
                </div>
              </article>
            )}
            {hasResults && (
              <AgentTaskResults variant="chat" taskMode={taskMode} notice={taskNotice}
                items={taskItems} onOpenFinding={onOpenFinding} onClear={onClearTaskResults} />
            )}
            {notice && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{notice}</p>}
          </div>
        )}
      </div>

      <form onSubmit={(event) => { event.preventDefault(); void submit(); }}
        className="shrink-0 border-t border-[var(--conversation-border)] px-4 py-3 sm:px-6">
        <div className="mx-auto max-w-5xl">
          <div className="flex items-end gap-2 rounded-xl border border-[var(--conversation-border)] p-2 focus-within:border-[var(--conversation-secondary)]">
            <textarea
              ref={composer} rows={2} aria-label="输入消息" placeholder="输入消息，回车发送"
              className="min-w-0 flex-1 resize-none bg-transparent px-2 py-1.5 text-sm leading-6 outline-none placeholder:text-[var(--conversation-secondary)]"
              value={input} onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
                  event.preventDefault();
                  void submit();
                }
              }}
            />
            <button type="submit" aria-label="发送消息" disabled={disabled || !input.trim()}
              className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--conversation-action)] text-[var(--conversation-action-text)] disabled:opacity-40">
              <ArrowUp size={18} />
            </button>
          </div>
          <div className="relative mt-2">
            <button type="button" aria-expanded={shortcutsOpen}
              className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-[var(--conversation-secondary)] hover:bg-[var(--conversation-muted)]"
              onClick={() => setShortcutsOpen(!shortcutsOpen)} onKeyDown={(event) => {
                if (event.key === "Escape") setShortcutsOpen(false);
              }}>
              <Zap size={13} />审计操作<ChevronDown size={13} />
            </button>
            {shortcutsOpen && (
              <div className="absolute bottom-full left-0 z-10 mb-1 max-h-48 w-64 max-w-[80vw] overflow-y-auto rounded-xl border border-[var(--conversation-border)] bg-[var(--conversation-panel)] p-1.5 shadow-lg"
                onKeyDown={(event) => { if (event.key === "Escape") { setShortcutsOpen(false); composer.current?.focus(); } }}>
                {SHORTCUTS.map((shortcut) => (
                  <button key={shortcut.label} type="button" disabled={disabled}
                    className="block w-full rounded-md px-3 py-2 text-left text-sm hover:bg-[var(--conversation-muted)] disabled:opacity-50"
                    onClick={() => {
                      followLatest.current = true;
                      setShortcutsOpen(false);
                      if ("mode" in shortcut) onRunTask(shortcut.mode);
                      else { setInput(shortcut.text); composer.current?.focus(); }
                    }}>{shortcut.label}</button>
                ))}
              </div>
            )}
          </div>
        </div>
      </form>
    </section>
  );
}
