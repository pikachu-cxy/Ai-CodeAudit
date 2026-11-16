import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Bot, MessageSquare, Search } from "lucide-react";
import {
  api,
  type AgentAction,
  type AgentChatMessage,
  type AgentTaskItem,
  type AgentTaskMode,
  type ScanSummary,
} from "../../api";
import { navigate } from "../../app/router";
import { useInspector } from "../../app/AppShell";
import type { PageContext } from "../../app/pageTypes";
import { AuditChatBar } from "../../components/AuditChatBar";
import { STATUS_LABELS } from "../../components/ui";
import { useAsyncData } from "../../shared/hooks/useAsyncData";
import { formatDateTime } from "../../shared/format";
import {
  EmptyState,
  ErrorState,
  KeyValueRow,
  LoadingState,
  MonoMeta,
  StatusPill,
} from "../../shared/ui";

interface ChatContextData {
  scan: ScanSummary;
  messages: AgentChatMessage[];
  actions: AgentAction[];
}

interface Props extends PageContext {
  projectId: number | null;
  scanId: number | null;
}

/**
 * Chat still runs on the existing per-scan agent endpoints. There is no
 * global conversation API yet, so the page requires the user to pick a real
 * scan first instead of inventing a session store.
 */
export function ChatPage(props: Props) {
  return <ScanChat key={props.scanId ?? "picker"} {...props} />;
}

function ScanChat({ projectId, scanId, refreshKey }: Props) {
  const [search, setSearch] = useState("");
  const [messages, setMessages] = useState<AgentChatMessage[]>([]);
  const [actions, setActions] = useState<AgentAction[]>([]);
  const [taskItems, setTaskItems] = useState<AgentTaskItem[]>([]);
  const [taskMode, setTaskMode] = useState<string | null>(null);
  const [taskNotice, setTaskNotice] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [chatting, setChatting] = useState(false);
  const [liveReply, setLiveReply] = useState("");
  const [chatProgress, setChatProgress] = useState("");

  const scanPicker = useAsyncData<ScanSummary[]>(
    () => api.listScans({ archived: "false" }),
    [refreshKey],
  );

  const session = useAsyncData<ChatContextData | null>(
    async () => {
      if (!scanId) return null;
      const [scan, history, actionHistory] = await Promise.all([
        api.getScan(scanId),
        api.getAgentChatHistory(scanId, 30),
        api.getAgentChatActions(scanId, 12),
      ]);
      return { scan, messages: history, actions: actionHistory };
    },
    [scanId],
  );

  useEffect(() => {
    if (!session.data) return;
    setMessages(session.data.messages);
    setActions(session.data.actions);
  }, [session.data]);

  const inspector = useMemo(() => {
    if (!scanId || !session.data) return null;
    const scan = session.data.scan;
    return {
      title: scan.name,
      subtitle: `扫描 #${scan.id}`,
      content: (
        <div className="space-y-1">
          <KeyValueRow label="状态"><StatusPill tone={scan.status === "completed" ? "success" : scan.status === "failed" ? "danger" : "warning"}>{STATUS_LABELS[scan.status]}</StatusPill></KeyValueRow>
          <KeyValueRow label="发现数"><MonoMeta>{scan.total_findings}</MonoMeta></KeyValueRow>
          <KeyValueRow label="来源"><MonoMeta>{scan.source}</MonoMeta></KeyValueRow>
          <KeyValueRow label="版本"><MonoMeta>{scan.version_label || "—"}</MonoMeta></KeyValueRow>
          <KeyValueRow label="创建时间"><MonoMeta>{formatDateTime(scan.created_at)}</MonoMeta></KeyValueRow>
          {scan.progress_message && (
            <div className="pt-3">
              <p className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">当前阶段</p>
              <p className="mt-1 text-xs text-[var(--text-secondary)]">{scan.progress_message}</p>
            </div>
          )}
          <div className="pt-4">
            <button
              type="button"
              className="btn-action w-full"
              onClick={() => navigate(`/tasks/${scan.id}`)}
            >
              打开扫描详情 <ArrowUpRight className="ml-1 inline h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      ),
    };
  }, [scanId, session.data]);
  useInspector(inspector);

  const findingUrl = (findingId: number) =>
    projectId
      ? `/projects/${projectId}?scan=${scanId}&finding=${findingId}`
      : `/tasks/${scanId}?finding=${findingId}`;

  const onChatUpdate = (event: "progress" | "reply", text: string) => {
    if (event === "reply") setLiveReply(text);
    else setChatProgress(text);
  };

  const handleCommand = async (text: string) => {
    if (!scanId) return;
    setChatting(true);
    setChatProgress("正在准备回复…");
    setLiveReply("");
    setMessages((current) => [...current, { role: "user", content: text, created_at: new Date().toISOString() }]);
    setNotice(null);
    try {
      const result = await api.streamAgentChat(scanId, { message: text, max_history: 30 }, onChatUpdate);
      setMessages(result.messages);
      if (result.action_history) setActions(result.action_history);
    } catch (e) {
      setNotice(`对话请求失败：${String(e)}`);
    } finally {
      setChatting(false);
      setChatProgress("");
      setLiveReply("");
    }
  };

  const handleRunTask = async (mode: AgentTaskMode) => {
    if (!scanId) return;
    setChatting(true);
    setNotice(null);
    try {
      const result = await api.runAgentTask(scanId, { mode });
      setTaskItems(result.items);
      setTaskMode(result.mode);
      setTaskNotice(result.summary || null);
    } catch (e) {
      setNotice(`任务执行失败：${String(e)}`);
    } finally {
      setChatting(false);
    }
  };

  const pickerRows = (scanPicker.data ?? []).filter((scan) =>
    search.trim() ? scan.name.toLowerCase().includes(search.trim().toLowerCase()) : true,
  );

  return (
    <div className="audit-conversations grid h-full min-h-0 w-full grid-rows-[auto_minmax(0,1fr)] gap-3 p-3 md:grid-cols-[clamp(14rem,25%,19rem)_minmax(0,1fr)] md:grid-rows-1 md:gap-4 md:p-5">
      <aside aria-label="扫描对话列表" className="flex max-h-44 min-h-0 flex-col rounded-xl border border-[var(--conversation-border)] bg-[var(--conversation-panel)] md:max-h-none">
        <div className="shrink-0 space-y-3 border-b border-[var(--conversation-border)] p-3">
          <h1 className="flex items-center gap-2 px-1 text-sm font-semibold"><MessageSquare size={16} /> 审计对话</h1>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
            <input className="h-9 w-full rounded-lg border border-[var(--conversation-border)] bg-transparent pl-9 pr-2 text-sm outline-none focus:border-[var(--conversation-secondary)]" aria-label="搜索扫描任务" placeholder="搜索扫描任务"
              value={search} onChange={(event) => setSearch(event.target.value)} />
          </div>
        </div>
        <div className="min-h-0 overflow-y-auto p-2">
          {scanPicker.loading && <LoadingState label="正在加载扫描任务…" />}
          {scanPicker.error && <ErrorState message={scanPicker.error} onRetry={() => scanPicker.reload()} />}
          {pickerRows.map((scan) => (
            <button key={scan.id} type="button" aria-current={scan.id === scanId ? "true" : undefined}
              className={`mb-0.5 block w-full rounded-lg px-3 py-2.5 text-left hover:bg-[var(--conversation-muted)] ${scan.id === scanId ? "bg-[var(--conversation-muted)] font-semibold" : ""}`}
              onClick={() => navigate(`/chat?scanId=${scan.id}`)}>
              <span className="block truncate text-sm font-medium">{scan.name}</span>
              <span className="mt-1 block text-xs font-normal text-[var(--conversation-secondary)]">#{scan.id} · {formatDateTime(scan.created_at)}</span>
            </button>
          ))}
          {!scanPicker.loading && !scanPicker.error && !pickerRows.length && (
            <p className="px-3 py-2 text-xs text-[var(--text-muted)]">没有匹配的扫描任务</p>
          )}
        </div>
      </aside>

      <main className="flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-[var(--conversation-border)] bg-[var(--conversation-panel)]">
        {scanId ? (
          <>
            <header className="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--conversation-border)] px-4 py-3 sm:px-6">
              <div className="flex min-w-0 items-center gap-2.5">
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--conversation-muted)]"><Bot size={19} /></span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold">审计 Agent</p>
                  <p className="truncate text-xs text-[var(--conversation-secondary)]">{session.data?.scan.name ?? `扫描 #${scanId}`}</p>
                </div>
              </div>
              <button type="button" className="shrink-0 rounded-lg border border-[var(--conversation-border)] px-2.5 py-1.5 text-xs hover:bg-[var(--conversation-muted)]" onClick={() => navigate(`/tasks/${scanId}`)}>
                扫描详情 <ArrowUpRight className="ml-1 inline h-3.5 w-3.5" />
              </button>
            </header>
            {session.loading && <LoadingState label="正在载入对话…" />}
            {session.error && <ErrorState message={session.error} onRetry={() => session.reload()} />}
            <AuditChatBar
              liveReply={liveReply}
              progress={chatProgress}
              disabled={chatting || !session.data}
              onCommand={handleCommand}
              onRunTask={(mode) => void handleRunTask(mode)}
              notice={notice}
              messages={messages}
              actions={actions}
              taskNotice={taskNotice}
              taskItems={taskItems}
              taskMode={taskMode}
              onOpenFinding={(findingId) => navigate(findingUrl(findingId))}
              onClearTaskResults={() => {
                setTaskItems([]);
                setTaskMode(null);
                setTaskNotice(null);
              }}
            />
          </>
        ) : (
          <div className="grid flex-1 place-items-center">
            <EmptyState icon={MessageSquare} title="选择扫描任务" description="从左侧选择一个扫描，开始和审计 Agent 对话。" />
          </div>
        )}
      </main>
    </div>
  );
}
