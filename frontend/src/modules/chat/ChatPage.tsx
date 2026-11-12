import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, MessageSquare, Search } from "lucide-react";
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
  PageHeader,
  SectionCard,
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
export function ChatPage({ projectId, scanId, refreshKey }: Props) {
  const [search, setSearch] = useState("");
  const [messages, setMessages] = useState<AgentChatMessage[]>([]);
  const [actions, setActions] = useState<AgentAction[]>([]);
  const [taskItems, setTaskItems] = useState<AgentTaskItem[]>([]);
  const [taskMode, setTaskMode] = useState<string | null>(null);
  const [taskNotice, setTaskNotice] = useState<string | null>(null);
  const [lastAction, setLastAction] = useState<string | null>(null);
  const [lastActionResult, setLastActionResult] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [chatting, setChatting] = useState(false);

  const scanPicker = useAsyncData<ScanSummary[]>(
    () => (scanId ? Promise.resolve([]) : api.listScans({ archived: "false" })),
    [scanId, refreshKey],
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

  const handleCommand = async (text: string) => {
    if (!scanId) return;
    setChatting(true);
    setNotice(null);
    try {
      const result = await api.agentChat(scanId, { message: text, max_history: 30 });
      setMessages(result.messages);
      if (result.action_history) setActions(result.action_history);
      setLastAction(result.action ?? null);
      setLastActionResult(result.action_result ?? null);
    } catch (e) {
      setNotice(`对话请求失败：${String(e)}`);
    } finally {
      setChatting(false);
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
    <div className="flex h-full min-h-0 w-full flex-col">
      <div className="page-container shrink-0 pb-2">
        <PageHeader
          eyebrow="Workspace / Chat"
          title="审计对话"
          description="复用现有的扫描级 Agent 对话与任务接口。当前没有全局会话后端，因此需要先选择一个真实扫描作为上下文。"
          actions={
            scanId ? (
              <>
                <button type="button" className="btn-action" onClick={() => session.reload()}>
                  重新载入会话
                </button>
                <button type="button" className="btn-action" onClick={() => navigate("/chat")}>
                  切换扫描
                </button>
              </>
            ) : undefined
          }
        />
      </div>

      {!scanId ? (
        <div className="min-h-0 flex-1 overflow-y-auto px-6 pb-6">
          <SectionCard
            title="选择扫描上下文"
            description="对话、工具调用与任务执行都绑定到具体的扫描任务。"
            bodyClassName="p-4 space-y-3"
          >
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                className="input pl-9"
                placeholder="按任务名称搜索"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
            {scanPicker.loading ? (
              <LoadingState label="正在加载扫描任务…" />
            ) : scanPicker.error ? (
              <ErrorState message={scanPicker.error} onRetry={() => scanPicker.reload()} />
            ) : pickerRows.length === 0 ? (
              <EmptyState
                icon={MessageSquare}
                title="暂无可用于对话的扫描"
                description="先创建一个审计项目并运行扫描，之后即可在此进入 Agent 对话。"
              />
            ) : (
              <div className="divide-y divide-[var(--surface-border)]">
                {pickerRows.map((scan) => (
                  <button
                    key={scan.id}
                    type="button"
                    className="flex w-full items-center gap-3 py-2.5 text-left hover:bg-[var(--hover-overlay)] transition-colors"
                    onClick={() => navigate(`/chat?scanId=${scan.id}${projectId ? `&projectId=${projectId}` : ""}`)}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{scan.name}</span>
                      <MonoMeta>#{scan.id} · {formatDateTime(scan.created_at)}</MonoMeta>
                    </span>
                    <StatusPill tone={scan.status === "completed" ? "success" : scan.status === "failed" ? "danger" : "warning"}>
                      {STATUS_LABELS[scan.status]}
                    </StatusPill>
                  </button>
                ))}
              </div>
            )}
          </SectionCard>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="shrink-0 px-6 pb-2">
            {session.loading && <LoadingState label="正在载入会话上下文…" />}
            {session.error && <ErrorState message={session.error} onRetry={() => session.reload()} />}
            {session.data && (
              <div className="flex flex-wrap items-center gap-2 rounded-lg border border-surface-border bg-[var(--bg-muted)] px-3 py-2 text-xs">
                <MessageSquare className="h-3.5 w-3.5 text-cyan-500" />
                <span className="font-medium">{session.data.scan.name}</span>
                <MonoMeta>扫描 #{scanId}</MonoMeta>
                <StatusPill tone={session.data.scan.status === "completed" ? "success" : "warning"}>
                  {STATUS_LABELS[session.data.scan.status]}
                </StatusPill>
                <span className="text-[var(--text-muted)]">
                  对话与任务结果保存在该扫描下；切换扫描会载入新的上下文。
                </span>
              </div>
            )}
          </div>
          <div className="min-h-0 flex-1" />
          <AuditChatBar
            disabled={chatting || session.loading}
            onCommand={(text) => void handleCommand(text)}
            onRunTask={(mode) => void handleRunTask(mode)}
            notice={notice}
            messages={messages}
            lastAction={lastAction}
            lastActionResult={lastActionResult}
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
        </div>
      )}
    </div>
  );
}
