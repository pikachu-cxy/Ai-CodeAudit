import { useCallback, useEffect, useRef, useState } from "react";
import { GripHorizontal, Send } from "lucide-react";
import type { AgentAction, AgentChatMessage, AgentTaskItem, AgentTaskMode, ReviewStatus } from "../api";
import { AgentTaskResults } from "./AgentTaskResults";

interface Props {
  disabled?: boolean;
  onCommand: (text: string) => void | Promise<void>;
  notice?: string | null;
  messages?: AgentChatMessage[];
  lastAction?: string | null;
  lastActionResult?: string | null;
  actions?: AgentAction[];
  onRunTask?: (mode: AgentTaskMode) => void | Promise<void>;
  taskNotice?: string | null;
  taskItems?: AgentTaskItem[];
  taskMode?: string | null;
  onOpenFinding?: (findingId: number) => void;
  onReviewFinding?: (findingId: number, status: ReviewStatus) => void;
  reviewingId?: number | null;
  onClearTaskResults?: () => void;
}

type Shortcut =
  | { kind: "task"; label: string; mode: AgentTaskMode }
  | { kind: "cmd"; label: string; text: string };

const SHORTCUTS: Shortcut[] = [
  { kind: "task", label: "补盲越权", mode: "auth_gap_hunt" },
  { kind: "task", label: "补盲业务流程", mode: "biz_gap_hunt" },
  { kind: "task", label: "漏洞优先级排序", mode: "prioritize" },
  { kind: "cmd", label: "可利用性研判(快速)", text: "运行可利用性研判，使用快速模式" },
  { kind: "cmd", label: "可利用性研判(深度)", text: "运行可利用性研判，使用深度模式" },
  { kind: "cmd", label: "LLM 端点审计", text: "运行 LLM 端点驱动深度审计，不预设漏洞类型，先自由发挥。" },
  { kind: "cmd", label: "清空并重置", text: "清空并重置任务" },
  { kind: "cmd", label: "只看支付模块补盲越权", text: "只看 payment/pay/order 模块，帮我补盲越权，给出 Top 10 并按优先级排序。" },
  { kind: "cmd", label: "只看订单流程补盲逻辑", text: "只看 order/checkout/refund 流程，帮我补盲业务流程漏洞（竞态/幂等/绕过），给出 Top 10。" },
];

const ACTION_LABELS: Record<string, string> = {
  fp_audit: "SAST 误报审计",
  sast_deep_audit: "数据流深度研判",
  llm_review: "LLM 复审",
  llm_audit: "LLM 端点审计",
  rerun: "清空并重置",
};

const HEIGHT_KEY = "ai-audit.chatBarHeight";
const MIN_HEIGHT = 160;
const DEFAULT_HEIGHT = 280;

function clampHeight(h: number) {
  const maxH = Math.max(MIN_HEIGHT + 40, Math.floor(window.innerHeight * 0.72));
  return Math.max(MIN_HEIGHT, Math.min(maxH, Math.round(h)));
}

function readStoredHeight(): number {
  try {
    const raw = localStorage.getItem(HEIGHT_KEY);
    if (!raw) return DEFAULT_HEIGHT;
    const n = Number(raw);
    if (!Number.isFinite(n)) return DEFAULT_HEIGHT;
    return clampHeight(n);
  } catch {
    return DEFAULT_HEIGHT;
  }
}

export function AuditChatBar({
  disabled,
  onCommand,
  notice,
  messages = [],
  lastAction,
  lastActionResult,
  actions = [],
  onRunTask,
  taskNotice,
  taskItems = [],
  taskMode,
  onOpenFinding,
  onReviewFinding,
  reviewingId,
  onClearTaskResults,
}: Props) {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [height, setHeight] = useState(DEFAULT_HEIGHT);
  const [dragging, setDragging] = useState(false);
  const dragStartY = useRef(0);
  const dragStartH = useRef(DEFAULT_HEIGHT);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setHeight(readStoredHeight());
  }, []);

  useEffect(() => {
    const onResize = () => setHeight((h) => clampHeight(h));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ block: "nearest" });
  }, [messages.length, lastAction, taskItems.length]);

  const onDragMove = useCallback((clientY: number) => {
    // Dragging the top handle upward increases height.
    const delta = dragStartY.current - clientY;
    const next = clampHeight(dragStartH.current + delta);
    setHeight(next);
  }, []);

  useEffect(() => {
    if (!dragging) return;

    const onMove = (e: MouseEvent) => {
      e.preventDefault();
      onDragMove(e.clientY);
    };
    const onUp = () => {
      setDragging(false);
      setHeight((h) => {
        const clamped = clampHeight(h);
        try {
          localStorage.setItem(HEIGHT_KEY, String(clamped));
        } catch {
          /* ignore */
        }
        return clamped;
      });
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };

    document.body.style.cursor = "ns-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [dragging, onDragMove]);

  const submit = async () => {
    const text = input.trim();
    // When parent disables the chat (e.g. scan is running), keep input editable for UX
    // but block sending.
    if (!text || busy || disabled) return;
    setBusy(true);
    try {
      await onCommand(text);
      setInput("");
    } finally {
      setBusy(false);
    }
  };

  const showTaskInChat = Boolean(taskNotice) || taskItems.length > 0;

  return (
    <div
      className={`chat-shell border-t border-cyan-500/10 backdrop-blur-md shrink-0 flex flex-col min-h-0 ${
        dragging ? "chat-shell-resizing" : ""
      }`}
      style={{ height }}
    >
      <div
        role="separator"
        aria-orientation="horizontal"
        aria-label="拖拽调整对话框高度"
        title="拖拽调整高度"
        className="chat-resize-handle group shrink-0 flex items-center justify-center cursor-ns-resize select-none"
        onMouseDown={(e) => {
          e.preventDefault();
          dragStartY.current = e.clientY;
          dragStartH.current = height;
          setDragging(true);
        }}
        onDoubleClick={() => {
          const next = DEFAULT_HEIGHT;
          setHeight(next);
          try {
            localStorage.setItem(HEIGHT_KEY, String(next));
          } catch {
            /* ignore */
          }
        }}
      >
        <span className="chat-resize-bar" />
        <GripHorizontal className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 absolute opacity-70" />
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-4 pt-1 pb-2 space-y-2">
        {showTaskInChat && (
          <AgentTaskResults
            variant="chat"
            taskMode={taskMode}
            notice={taskNotice}
            items={taskItems}
            reviewingId={reviewingId}
            onOpenFinding={onOpenFinding}
            onReview={onReviewFinding}
            onClear={onClearTaskResults}
          />
        )}
        {lastAction && (
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-2">
            <p className="text-[10px] uppercase tracking-wide text-cyan-300/80 mb-1">最近触发动作</p>
            <p className="text-xs text-cyan-200/90">{ACTION_LABELS[lastAction] || lastAction}</p>
            {lastActionResult && (
              <p className="text-[11px] text-slate-300 mt-1 whitespace-pre-wrap leading-relaxed">{lastActionResult}</p>
            )}
          </div>
        )}
        {actions.length > 0 && (
          <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2">
            <summary className="text-[10px] uppercase tracking-wide text-slate-400 cursor-pointer">
              动作历史（最近 {actions.length} 次）
            </summary>
            <div className="mt-2 space-y-2 max-h-28 overflow-y-auto pr-1">
              {actions
                .slice()
                .reverse()
                .map((a, idx) => (
                  <div key={`${a.created_at}-${idx}`} className="text-[11px] border-l border-cyan-500/30 pl-2">
                    <p className="text-cyan-200/90">
                      {ACTION_LABELS[a.action] || a.action} ·{" "}
                      <span className="text-slate-500">
                        {a.created_at
                          ? new Date(a.created_at).toLocaleTimeString("zh-CN", { hour12: false })
                          : "--:--:--"}
                      </span>
                    </p>
                    {a.result && <p className="text-slate-400 whitespace-pre-wrap mt-0.5">{a.result}</p>}
                  </div>
                ))}
            </div>
          </details>
        )}
        {messages.length > 0 ? (
          <div className="space-y-2 pr-1">
            {messages.slice(-30).map((m, idx) => (
              <div
                key={`${m.created_at}-${idx}`}
                className={`chat-bubble text-xs rounded-lg border px-2 py-1.5 ${
                  m.role === "assistant" ? "chat-bubble-assistant" : "chat-bubble-user"
                }`}
              >
                <p className="chat-bubble-label text-[10px] uppercase tracking-wide opacity-80 mb-1">
                  {m.role === "assistant" ? "Agent" : "You"}
                </p>
                <p className="whitespace-pre-wrap leading-relaxed">{m.content}</p>
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>
        ) : (
          <div className="rounded-lg border border-surface-border/50 bg-black/10 px-3 py-2 pr-1">
            <p className="text-[11px] text-slate-400 leading-relaxed">
              {disabled
                ? "扫描进行中：输入不发送（可先写问题，扫描结束后继续）。"
                : "暂无对话：输入指令后回车发送。"}
            </p>
          </div>
        )}
        {notice && <p className="text-xs text-cyan-400/90 px-1">{notice}</p>}
      </div>

      <div className="shrink-0 px-4 pb-3 pt-1 border-t border-cyan-500/5 bg-black/10">
        <div className="flex flex-wrap gap-2 mb-2">
          {SHORTCUTS.map((s) => (
            <button
              key={`${s.kind}-${s.label}`}
              type="button"
              disabled={disabled || busy || (s.kind === "task" && !onRunTask)}
              className="chat-shortcut text-[10px] px-2 py-1 rounded-full border transition-colors disabled:opacity-50"
              onClick={() => {
                if (s.kind === "task") onRunTask?.(s.mode);
                else onCommand(s.text);
              }}
              title={s.kind === "cmd" ? s.text : s.label}
            >
              {s.label}
            </button>
          ))}
        </div>
        <div className="flex gap-2 items-center">
          <input
            className="input flex-1 bg-black/40 border-cyan-500/15 text-sm font-mono placeholder:text-slate-600"
            placeholder="问法示例：先自由审计；只看越权漏洞；只看支付退款流程；检查 modifyPwd 是否可越权改密"
            value={input}
            // Keep focus/click enabled for better UX (submit is blocked in `submit()`).
            disabled={busy}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && submit()}
          />
          <button
            type="button"
            className="btn-primary px-3 bg-cyan-600 hover:bg-cyan-500"
            disabled={disabled || busy || !input.trim()}
            onClick={submit}
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
