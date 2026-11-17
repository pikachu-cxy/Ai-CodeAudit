import { useEffect, useState, type ReactNode } from "react";
import {
  Ban,
  Bot,
  CheckCircle2,
  Clock3,
  Layers,
  Play,
  RefreshCw,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import {
  api,
  type DeepAuditCapabilities,
  type DeepAuditEvent,
  type DeepAuditFact,
  type DeepAuditFocus,
  type DeepAuditLineup,
  type DeepAuditPlan,
  type DeepAuditPlannerResult,
  type DeepAuditRun,
  type DeepAuditSummary,
} from "../api";
import { formatDateTime } from "../shared/format";
import { AuditGraphPanel, type GraphDestination } from "./DeepAuditGraphs";
import { useAsyncData } from "../shared/hooks/useAsyncData";
import { KeyValueRow, MonoMeta, SectionCard, StatusPill } from "../shared/ui";
import { InlineMessage } from "../shared/ui/forms";

/**
 * Minimal Deep Audit V1 UI. It reuses the existing task / chat surfaces and
 * only reads the new /api/deep-audit/* contract. No new router, no new store,
 * no automatic MCP / Skill authorisation.
 */

const ALL_FOCUS: { key: DeepAuditFocus; label: string }[] = [
  { key: "authz", label: "鉴权与水平越权" },
  { key: "injection", label: "注入及危险数据流" },
  { key: "business_logic", label: "业务逻辑风险" },
];

const FACT_LABELS: Record<string, string> = {
  code_fact: "代码事实",
  vuln_hypothesis: "漏洞假设",
  candidate_finding: "候选漏洞",
};

const EVENT_LABELS: Record<string, string> = {
  task_started: "任务开始",
  task_finished: "任务完成",
  tool_call: "只读工具调用",
  tool_rejected: "工具被拒绝",
  candidate_linked: "候选关联 Finding",
  llm_fallback: "LLM 降级",
};

const ACTIVE_RUN_STATES = ["pending", "planning", "running"];

type Notice = { tone: "success" | "error" | "info"; text: string };

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function num(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function runTone(status: string): "success" | "accent" | "warning" | "danger" | "muted" {
  if (status === "completed") return "success";
  if (status === "failed") return "danger";
  if (status === "cancelled") return "muted";
  if (status === "running" || status === "planning") return "accent";
  return "warning";
}

function taskTone(status: string): "success" | "accent" | "warning" | "danger" | "muted" {
  if (status === "completed") return "success";
  if (status === "failed") return "danger";
  if (status === "skipped") return "muted";
  if (status === "running") return "accent";
  return "warning";
}

function parsePrefixes(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 20);
}

function short(value: string, max = 150): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function payloadPreview(payload: unknown): string {
  try {
    return short(JSON.stringify(payload ?? {}), 220);
  } catch {
    return String(payload ?? "");
  }
}

/* ------------------------------------------------------------------ *
 * Shared launcher: used by the scan detail panel and the Agents page.
 * ------------------------------------------------------------------ */

const PLANNER_FALLBACK: Record<string, string> = {
  llm_not_configured: "LLM 未配置",
  invalid_plan_schema: "模型计划格式无效",
  plan_out_of_scope: "模型计划超出审计范围",
  task_limit_exceeded: "模型计划超过任务数上限",
  planner_prompt_exceeds_budget: "规划上下文超出预算",
  planner_budget_exhausted: "Planner 角色预算耗尽",
  planner_timeout: "模型调用超时",
  planner_provider_error: "模型调用失败",
};

function plannerLabel(result: DeepAuditPlannerResult | undefined) {
  if (!result) return "—";
  if (result.mode === "agent_llm") return "Agent 模型规划";
  const reason = result.fallback_reason;
  return reason ? `内置规则（${PLANNER_FALLBACK[reason] ?? reason}）` : "内置规则";
}

export interface DeepAuditLauncherProps {
  scanId: number;
  lineup?: DeepAuditLineup;
  focus?: DeepAuditFocus[];
  onFocusChange?: (focus: DeepAuditFocus[]) => void;
  onStarted?: (runId: number) => void;
}

export function DeepAuditLauncher({
  scanId,
  lineup,
  focus,
  onFocusChange,
  onStarted,
}: DeepAuditLauncherProps) {
  const caps = useAsyncData<DeepAuditCapabilities>(() => api.deepAuditCapabilities(), []);
  const [ownFocus, setOwnFocus] = useState<DeepAuditFocus[]>([
    "authz",
    "injection",
    "business_logic",
  ]);
  const [prefixText, setPrefixText] = useState("");
  const [maxTasks, setMaxTasks] = useState(6);
  const [previewState, setPreviewState] = useState<{ key: string; data: DeepAuditPlan } | null>(null);
  const [busy, setBusy] = useState<"plan" | "start" | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  const selected = focus ?? ownFocus;
  const changeFocus = onFocusChange ?? setOwnFocus;
  const scope = {
    focus: selected,
    path_prefixes: parsePrefixes(prefixText),
    max_tasks: maxTasks,
    ...lineup,
  };
  const previewKey = JSON.stringify([scanId, scope]);
  const plan = previewState?.key === previewKey ? previewState.data : null;

  const toggleFocus = (key: DeepAuditFocus) =>
    changeFocus(selected.includes(key) ? selected.filter((item) => item !== key) : [...selected, key]);

  const preview = async () => {
    setBusy("plan");
    setNotice(null);
    try {
      const result = await api.deepAuditPlan(scanId, scope);
      setPreviewState({ key: previewKey, data: result });
      setNotice({
        tone: "info",
        text: `Planner 生成 ${result.tasks.length} 条任务（预览未启动 Worker）。`,
      });
    } catch (err) {
      setNotice({ tone: "error", text: `规划预览失败：${errText(err)}` });
    } finally {
      setBusy(null);
    }
  };

  const start = async () => {
    if (!selected.length) {
      setNotice({ tone: "error", text: "至少选择一个审计范围。" });
      return;
    }
    setBusy("start");
    setNotice(null);
    try {
      const result = await api.deepAuditStart(scanId, scope);
      setNotice({
        tone: "success",
        text: `Deep Audit 运行 #${result.run.id} 已启动（${result.run.status}）。Worker 仅能调用只读代码工具。`,
      });
      onStarted?.(result.run.id);
    } catch (err) {
      setNotice({ tone: "error", text: `启动失败：${errText(err)}` });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {ALL_FOCUS.map((item) => (
          <button
            key={item.key}
            type="button"
            className={selected.includes(item.key) ? "filter-chip filter-chip-active" : "filter-chip"}
            onClick={() => toggleFocus(item.key)}
          >
            {item.label}
          </button>
        ))}
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <label className="block space-y-1.5">
          <span className="block text-xs font-medium text-[var(--text-secondary)]">
            路径前缀（可选，逗号或换行分隔）
          </span>
          <input
            className="input"
            value={prefixText}
            onChange={(event) => setPrefixText(event.target.value)}
            placeholder="src/controller, src/service"
          />
        </label>
        <label className="block space-y-1.5">
          <span className="block text-xs font-medium text-[var(--text-secondary)]">最大任务数</span>
          <input
            className="input"
            type="number"
            min={1}
            max={50}
            value={maxTasks}
            onChange={(event) => setMaxTasks(Math.max(1, Math.min(50, Number(event.target.value) || 1)))}
          />
        </label>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="btn-action"
          disabled={busy !== null || !selected.length}
          onClick={() => void preview()}
        >
          预览 Planner 任务
        </button>
        <button
          type="button"
          className="btn-primary inline-flex items-center gap-1.5"
          disabled={busy !== null || !selected.length}
          onClick={() => void start()}
        >
          <Play className="h-3.5 w-3.5" /> 启动 Deep Audit V1
        </button>
        {caps.data && (
          <MonoMeta>
            Worker ×{lineup?.worker_slugs?.length ?? 1}（分批，每批最多两个） · {caps.data.worker_mode} · 只读工具 {caps.data.allowed_tools.length} 个
          </MonoMeta>
        )}
      </div>

      {caps.data && (
        <div className="rounded-lg border border-surface-border bg-[var(--bg-muted)] px-3 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">
          {caps.data.note}
          <div className="mt-2 flex flex-wrap gap-1.5">
            <StatusPill tone="danger">MCP 未授权</StatusPill>
            <StatusPill tone="danger">Skill 未授权</StatusPill>
            <StatusPill tone="warning">证据必需</StatusPill>
            <StatusPill tone="muted">不自动确认</StatusPill>
          </div>
        </div>
      )}
      {caps.error && <InlineMessage tone="error">读取运行时能力失败：{caps.error}</InlineMessage>}
      {notice && <InlineMessage tone={notice.tone}>{notice.text}</InlineMessage>}

      {plan && (
        <div className="space-y-1.5">
          <p className="text-xs text-[var(--text-secondary)]">
            任务预览 · {plannerLabel(plan.planner_result)} · 代码版本 <MonoMeta>{plan.revision || "—"}</MonoMeta> ·{" "}
            <MonoMeta>{plan.tasks.length} 条</MonoMeta>
          </p>
          {plan.tasks.length === 0 ? (
            <InlineMessage tone="info">当前范围下没有新任务（可能已被黑板已有事实覆盖）。</InlineMessage>
          ) : (
            <div className="max-h-56 space-y-1.5 overflow-y-auto pr-1">
              {plan.tasks.map((task) => (
                <div
                  key={task.fingerprint}
                  className="rounded-lg border border-surface-border bg-[var(--bg-raised)] px-3 py-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusPill tone={task.status === "skipped" ? "muted" : "accent"}>
                      {task.task_type}
                    </StatusPill>
                    <MonoMeta>{task.agent_id}</MonoMeta>
                    <MonoMeta>P{task.priority}</MonoMeta>
                    <MonoMeta>{task.status}</MonoMeta>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-[var(--text-secondary)]">
                    {short(task.goal.split("\n")[0] || task.goal, 180)}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * Full blackboard panel, mounted on the scan (task) detail page.
 * ------------------------------------------------------------------ */

export function DeepAuditPanel({
  scanId,
  onFindingsChanged,
  destination,
  onAsset,
}: {
  scanId: number;
  onFindingsChanged?: () => void;
  destination?: GraphDestination;
  onAsset?: (target: GraphDestination) => void;
}) {
  const [open, setOpen] = useState(true);
  const [poll, setPoll] = useState(0);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(destination?.runId ?? null);
  const [tab, setTab] = useState<"details" | "graph">(destination?.taskId ? "graph" : "details");
  const [factFilter, setFactFilter] = useState("");
  const [reviewNote, setReviewNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  const runs = useAsyncData<{ runs: DeepAuditRun[] }>(
    () => (open ? api.deepAuditRuns(scanId) : Promise.resolve({ runs: [] })),
    [scanId, poll, open],
  );

  useEffect(() => {
    if (!runs.data || !open) return;
    const list = runs.data.runs;
    setSelectedRunId((current) =>
      current && list.some((row) => row.id === current) ? current : (list[0]?.id ?? null),
    );
  }, [runs.data, open]);

  const runList = runs.data?.runs ?? [];
  const selectedRun = runList.find((row) => row.id === selectedRunId);
  const active = runList.some((row) => row.is_active || ACTIVE_RUN_STATES.includes(row.status));

  useEffect(() => {
    if (!active || !open) return;
    const timer = window.setInterval(() => setPoll((value) => value + 1), 4000);
    return () => window.clearInterval(timer);
  }, [active, open]);

  const summary = useAsyncData<DeepAuditSummary | null>(
    () => (open && selectedRunId ? api.deepAuditSummary(selectedRunId) : Promise.resolve(null)),
    [selectedRunId, poll, open],
  );
  const facts = useAsyncData<{ facts: DeepAuditFact[]; count: number }>(
    () =>
      open && selectedRunId
        ? api.deepAuditFacts(selectedRunId, factFilter || undefined)
        : Promise.resolve({ facts: [], count: 0 }),
    [selectedRunId, factFilter, poll, open],
  );
  const events = useAsyncData<{ events: DeepAuditEvent[]; count: number }>(
    () =>
      open && selectedRunId
        ? api.deepAuditEvents(selectedRunId, 30)
        : Promise.resolve({ events: [], count: 0 }),
    [selectedRunId, poll, open],
  );

  const data = summary.data;
  const budget = data?.budget_usage ?? {};
  const confirmedIds = new Set((data?.confirmed_findings ?? []).map((item) => item.id));
  const completedTasks = (data?.tasks ?? []).filter((task) =>
    ["completed", "skipped"].includes(task.status),
  );

  const reload = () => setPoll((value) => value + 1);

  const handleConfirm = async (findingId: number) => {
    if (!selectedRunId) return;
    setBusy(`confirm-${findingId}`);
    setNotice(null);
    try {
      await api.deepAuditConfirmFinding(selectedRunId, findingId, reviewNote);
      setNotice({
        tone: "success",
        text: `候选 #${findingId} 已人工确认；状态已写入现有漏洞体系（CONFIRMED / REAL_VULN）。`,
      });
      onFindingsChanged?.();
      reload();
    } catch (err) {
      setNotice({ tone: "error", text: `确认失败：${errText(err)}` });
    } finally {
      setBusy(null);
    }
  };

  const handleRunAction = async (action: "cancel" | "resume") => {
    if (!selectedRunId) return;
    setBusy(action);
    setNotice(null);
    try {
      if (action === "cancel") {
        await api.deepAuditCancel(selectedRunId);
        setNotice({ tone: "info", text: "已请求协作式取消；已完成的事实与证据仍然保留。" });
      } else {
        await api.deepAuditResume(selectedRunId);
        setNotice({ tone: "success", text: "运行已恢复；中断前写入的黑板事实不会丢失。" });
      }
      reload();
    } catch (err) {
      setNotice({ tone: "error", text: `${action === "cancel" ? "取消" : "恢复"}失败：${errText(err)}` });
    } finally {
      setBusy(null);
    }
  };

  return (
    <SectionCard
      title="Deep Audit V1 · 代码事实黑板（可选执行模式）"
      description="Planner → 每批最多两个不同的只读 Worker → 共享事实 / 代码证据 → 现有 Finding。原有 SAST / LLM 审计链路保持不变。"
      actions={
        <div className="flex items-center gap-2">
          <button type="button" className="btn-action" onClick={reload} disabled={!open}>
            <RefreshCw className="mr-1 inline h-3 w-3" />刷新
          </button>
          <button type="button" className="btn-action" onClick={() => setOpen((value) => !value)}>
            {open ? "收起" : "展开"}
          </button>
        </div>
      }
    >
      {!open ? (
        <InlineMessage tone="info">面板已收起；已完成的 Deep Audit 运行与黑板数据均保留在数据库中。</InlineMessage>
      ) : (
        <div className="space-y-4">
          <DeepAuditLauncher
            scanId={scanId}
            onStarted={(runId) => {
              setSelectedRunId(runId);
              reload();
            }}
          />

          {notice && <InlineMessage tone={notice.tone}>{notice.text}</InlineMessage>}
          {runs.error && <InlineMessage tone="error">读取运行列表失败：{runs.error}</InlineMessage>}
          {summary.error && <InlineMessage tone="error">读取黑板摘要失败：{summary.error}</InlineMessage>}

          {runList.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              {runList.map((run) => (
                <button
                  key={run.id}
                  type="button"
                  className={run.id === selectedRunId ? "filter-chip filter-chip-active" : "filter-chip"}
                  onClick={() => setSelectedRunId(run.id)}
                >
                  #{run.id} · {run.status} · {formatDateTime(run.created_at)}
                </button>
              ))}
            </div>
          )}

          {!selectedRunId ? (
            <InlineMessage tone="info">
              该扫描尚无 Deep Audit 运行。选择审计范围后可先预览 Planner 任务，再启动一次只读调查。
            </InlineMessage>
          ) : (
            <>
              <div role="tablist" aria-label="运行详情" className="flex gap-2">
                <button role="tab" aria-selected={tab === "details"} className={tab === "details" ? "filter-chip filter-chip-active" : "filter-chip"} onClick={() => setTab("details")}>任务与黑板</button>
                <button role="tab" aria-selected={tab === "graph"} className={tab === "graph" ? "filter-chip filter-chip-active" : "filter-chip"} onClick={() => setTab("graph")}>审计图</button>
              </div>
              {tab === "graph" && <AuditGraphPanel key={selectedRunId} runId={selectedRunId} poll={poll}
                destination={destination?.runId === selectedRunId ? destination : undefined} onAsset={onAsset} />}
              <div hidden={tab !== "details"} className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Stat label={`运行中 Worker ${data?.active_tasks.length ?? 0} / ${data?.task_concurrency_limit ?? 1}`} value={data?.active_tasks.map(task => task.agent_id).join("、") || data?.current_agent || "—"} icon={Bot} />
                <Stat
                  label="执行状态"
                  value={data?.run.status || "—"}
                  icon={Layers}
                  pillTone={runTone(data?.run.status || "pending")}
                />
                <Stat
                  label="已完成调查 / 任务"
                  value={`${completedTasks.length} / ${data?.tasks.length ?? 0}`}
                  icon={CheckCircle2}
                />
                <Stat
                  label="Token / 耗时"
                  value={`${num(budget.total_tokens)} / ${num(budget.elapsed_seconds).toFixed(1)}s`}
                  icon={Clock3}
                />
              </div>

              <div className="grid gap-x-8 md:grid-cols-2">
                {data?.run.config_snapshot.lineup && (
                  <>
                    <KeyValueRow label="Planner">
                      {data.run.config_snapshot.lineup.planner?.slug ?? "内置"} · {plannerLabel(data.run.config_snapshot.planner_result)}
                    </KeyValueRow>
                    <KeyValueRow label="Worker 阵容">
                      {data.run.config_snapshot.lineup.workers.map((worker) => worker.slug).join("、")}
                    </KeyValueRow>
                  </>
                )}
                <KeyValueRow label="当前任务">
                  {data?.current_task ? (
                    <span className="text-xs">
                      <StatusPill tone="accent">{data.current_task.task_type}</StatusPill>{" "}
                      {short(data.current_task.goal.split("\n")[0] || "", 90)}
                    </span>
                  ) : (
                    <MonoMeta>无运行中任务</MonoMeta>
                  )}
                </KeyValueRow>
                <KeyValueRow label="代码版本"><MonoMeta>{data?.run.repository_revision || "—"}</MonoMeta></KeyValueRow>
                <KeyValueRow label="LLM 轮次 / 工具调用">
                  <MonoMeta>{num(budget.llm_rounds)} / {num(budget.tool_calls)}</MonoMeta>
                </KeyValueRow>
                <KeyValueRow label="Token 明细">
                  <MonoMeta>
                    prompt {num(budget.prompt_tokens)} · completion {num(budget.completion_tokens)} ·
                    估算 {num(budget.estimated_tokens)}
                  </MonoMeta>
                </KeyValueRow>
                <KeyValueRow label="事实 / 候选 / 已确认">
                  <MonoMeta>
                    {Object.values(data?.fact_counts ?? {}).reduce((sum, value) => sum + num(value), 0)} /{" "}
                    {num(data?.fact_counts?.candidate_finding)} / {data?.confirmed_findings.length ?? 0}
                  </MonoMeta>
                </KeyValueRow>
                <KeyValueRow label="预算触发维度">
                  <MonoMeta>{budget.exhausted_dimension || "未触发"}</MonoMeta>
                </KeyValueRow>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  className="btn-action"
                  disabled={busy !== null || !selectedRun?.is_active}
                  onClick={() => void handleRunAction("cancel")}
                >
                  <Ban className="mr-1 inline h-3 w-3" />取消运行
                </button>
                <button
                  type="button"
                  className="btn-action"
                  disabled={busy !== null || !selectedRun || selectedRun.is_active || selectedRun.status === "completed"}
                  onClick={() => void handleRunAction("resume")}
                >
                  恢复中断运行
                </button>
                <label className="flex min-w-[220px] flex-1 items-center gap-2">
                  <span className="shrink-0 text-xs text-[var(--text-secondary)]">复核备注</span>
                  <input
                    className="input"
                    value={reviewNote}
                    onChange={(event) => setReviewNote(event.target.value)}
                    placeholder="人工确认时写入 Finding.review_note"
                    maxLength={500}
                  />
                </label>
              </div>

              <PanelBlock title="调查任务" count={data?.tasks.length ?? 0}>
                {(data?.tasks ?? []).length === 0 ? (
                  <MonoMeta>暂无任务</MonoMeta>
                ) : (
                  <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
                    {(data?.tasks ?? []).map((task) => (
                      <div key={task.id} className="rounded-lg border border-surface-border px-3 py-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusPill tone={taskTone(task.status)}>{task.status}</StatusPill>
                          <MonoMeta>{task.task_type} · P{task.priority} · {task.agent_id}</MonoMeta>
                        </div>
                        <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                          {short(task.goal.split("\n")[0] || task.goal, 160)}
                        </p>
                        {task.result_summary && (
                          <p className="mt-1 text-[11px] text-[var(--text-muted)]">
                            结果：{short(task.result_summary, 160)}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </PanelBlock>

              <PanelBlock
                title="共享事实黑板"
                count={facts.data?.count ?? 0}
                actions={
                  <div className="flex flex-wrap gap-1.5">
                    {["", ...Object.keys(FACT_LABELS)].map((key) => (
                      <button
                        key={key || "all"}
                        type="button"
                        className={factFilter === key ? "filter-chip filter-chip-active" : "filter-chip"}
                        onClick={() => setFactFilter(key)}
                      >
                        {key ? FACT_LABELS[key] : "全部"}
                      </button>
                    ))}
                  </div>
                }
              >
                {facts.error && <InlineMessage tone="error">读取事实失败：{facts.error}</InlineMessage>}
                {(facts.data?.facts ?? []).length === 0 ? (
                  <MonoMeta>暂无事实</MonoMeta>
                ) : (
                  <div className="max-h-72 space-y-1.5 overflow-y-auto pr-1">
                    {(facts.data?.facts ?? []).map((fact) => (
                      <div key={fact.id} className="rounded-lg border border-surface-border px-3 py-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusPill tone={fact.fact_type === "candidate_finding" ? "warning" : "accent"}>
                            {FACT_LABELS[fact.fact_type] ?? fact.fact_type}
                          </StatusPill>
                          <MonoMeta>#{fact.id} · 置信 {fact.confidence.toFixed(2)} · {fact.source}</MonoMeta>
                          {fact.finding_id && <MonoMeta>Finding #{fact.finding_id}</MonoMeta>}
                        </div>
                        <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                          {short(fact.summary, 220)}
                        </p>
                        {fact.evidence.slice(0, 3).map((item) => (
                          <p key={item.id} className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">
                            {item.file_path}:{item.line_start}-{item.line_end} · rev{" "}
                            {item.repository_revision.slice(0, 12)} · hash {item.content_hash.slice(0, 10)}
                          </p>
                        ))}
                      </div>
                    ))}
                  </div>
                )}
              </PanelBlock>

              <PanelBlock title="带证据的候选漏洞" count={data?.candidates.length ?? 0}>
                {(data?.candidates ?? []).length === 0 ? (
                  <MonoMeta>无候选。无代码证据时后端不会创建 Finding。</MonoMeta>
                ) : (
                  <div className="space-y-1.5">
                    {(data?.candidates ?? []).map((fact) => {
                      const first = fact.evidence[0];
                      const findingId = fact.finding_id;
                      const confirmed = findingId !== null && confirmedIds.has(findingId);
                      return (
                        <div key={fact.id} className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-3 py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <StatusPill tone={confirmed ? "success" : "warning"}>
                              {confirmed ? "已人工确认" : "UNREVIEWED / PENDING"}
                            </StatusPill>
                            <MonoMeta>
                              fact #{fact.id} · 证据 {fact.evidence.length} 条 · Finding #{findingId ?? "—"}
                            </MonoMeta>
                          </div>
                          <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
                            {short(fact.summary, 220)}
                          </p>
                          {first && (
                            <p className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">
                              {first.file_path}:{first.line_start} · {short(first.evidence_summary, 110)}
                            </p>
                          )}
                          {findingId !== null && !confirmed && (
                            <button
                              type="button"
                              className="btn-action mt-2 inline-flex items-center gap-1"
                              disabled={busy !== null || fact.evidence.length === 0}
                              onClick={() => void handleConfirm(findingId)}
                            >
                              <ShieldCheck className="h-3 w-3" />
                              {fact.evidence.length === 0 ? "无证据，不可确认" : "人工确认"}
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </PanelBlock>

              <PanelBlock title="已确认漏洞（写入现有 Finding 体系）" count={data?.confirmed_findings.length ?? 0}>
                {(data?.confirmed_findings ?? []).length === 0 ? (
                  <MonoMeta>暂无已确认漏洞。候选必须经人工复核才能成为确认漏洞。</MonoMeta>
                ) : (
                  <div className="space-y-1.5">
                    {(data?.confirmed_findings ?? []).map((finding) => (
                      <div key={finding.id} className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusPill tone="success">CONFIRMED</StatusPill>
                          <MonoMeta>#{finding.id} · {finding.severity} · {finding.rule_id}</MonoMeta>
                        </div>
                        <p className="mt-1 text-xs text-[var(--text-secondary)]">
                          {finding.file_path}:{finding.line_start} · {short(finding.message, 160)}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </PanelBlock>

              <PanelBlock title="只读工具执行轨迹" count={events.data?.count ?? 0}>
                {events.error && <InlineMessage tone="error">读取轨迹失败：{events.error}</InlineMessage>}
                {(events.data?.events ?? []).length === 0 ? (
                  <MonoMeta>暂无工具调用记录</MonoMeta>
                ) : (
                  <div className="max-h-72 space-y-1.5 overflow-y-auto pr-1">
                    {(events.data?.events ?? []).map((event) => {
                      const type = String((event.payload as Record<string, unknown>)?.type ?? event.event_type);
                      const tool = String((event.payload as Record<string, unknown>)?.tool ?? "");
                      return (
                        <div key={event.id} className="rounded-lg border border-surface-border px-3 py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <StatusPill tone={event.level === "warn" ? "warning" : "muted"}>
                              {EVENT_LABELS[type] ?? type}
                            </StatusPill>
                            {tool && <MonoMeta>{tool}</MonoMeta>}
                            <MonoMeta>{formatDateTime(event.created_at)}</MonoMeta>
                          </div>
                          <p className="mt-1 break-all font-mono text-[11px] text-[var(--text-muted)]">
                            {payloadPreview(event.payload)}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                )}
              </PanelBlock>
              </div>
            </>
          )}
        </div>
      )}
    </SectionCard>
  );
}

function Stat({
  label,
  value,
  icon: Icon,
  pillTone,
}: {
  label: string;
  value: string;
  icon: typeof Bot;
  pillTone?: "success" | "accent" | "warning" | "danger" | "muted";
}) {
  return (
    <div className="rounded-lg border border-surface-border bg-[var(--bg-raised)] px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      {pillTone ? (
        <div className="mt-1.5"><StatusPill tone={pillTone}>{value}</StatusPill></div>
      ) : (
        <p className="mt-1.5 truncate text-sm font-medium text-[var(--text-primary)]" title={value}>
          {value}
        </p>
      )}
    </div>
  );
}

function PanelBlock({
  title,
  count,
  actions,
  children,
}: {
  title: string;
  count: number;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-surface-border">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border px-3 py-2">
        <p className="text-xs font-medium text-[var(--text-primary)]">
          {title} <MonoMeta>({count})</MonoMeta>
        </p>
        {actions}
      </div>
      <div className="p-3">{children}</div>
    </section>
  );
}

/* ------------------------------------------------------------------ *
 * Compact trajectory for the existing Chat page.
 * ------------------------------------------------------------------ */

export function DeepAuditTrace({ scanId }: { scanId: number }) {
  const [poll, setPoll] = useState(0);
  const runs = useAsyncData<{ runs: DeepAuditRun[] }>(() => api.deepAuditRuns(scanId), [scanId, poll]);
  const runList = runs.data?.runs ?? [];
  const latestId = runList[0]?.id ?? null;
  const active = runList.some((row) => row.is_active || ACTIVE_RUN_STATES.includes(row.status));

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setPoll((value) => value + 1), 5000);
    return () => window.clearInterval(timer);
  }, [active]);

  const summary = useAsyncData<DeepAuditSummary | null>(
    () => (latestId ? api.deepAuditSummary(latestId) : Promise.resolve(null)),
    [latestId, poll],
  );
  const events = useAsyncData<{ events: DeepAuditEvent[]; count: number }>(
    () => (latestId ? api.deepAuditEvents(latestId, 8) : Promise.resolve({ events: [], count: 0 })),
    [latestId, poll],
  );

  if (!runs.loading && runList.length === 0) {
    return (
      <div className="rounded-lg border border-surface-border bg-[var(--bg-muted)] px-3 py-2 text-xs text-[var(--text-muted)]">
        Deep Audit V1：该扫描尚未启动可选深审模式；可在任务详情或 Agent 配置页启动，原有对话与扫描能力不受影响。
      </div>
    );
  }

  const data = summary.data;
  const budget = data?.budget_usage ?? {};
  return (
    <div className="rounded-lg border border-surface-border bg-[var(--bg-muted)] px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Wrench className="h-3.5 w-3.5 text-cyan-500" />
        <span className="font-medium">Deep Audit 执行轨迹</span>
        {latestId && <MonoMeta>运行 #{latestId}</MonoMeta>}
        {data && <StatusPill tone={runTone(data.run.status)}>{data.run.status}</StatusPill>}
        {data?.current_agent && <MonoMeta>Agent: {data.current_agent}</MonoMeta>}
        {data?.current_task && <MonoMeta>当前任务: {data.current_task.task_type}</MonoMeta>}
        <MonoMeta>
          {num(budget.total_tokens)} tokens · {num(budget.elapsed_seconds).toFixed(1)}s ·{" "}
          {num(budget.tool_calls)} 次工具调用
        </MonoMeta>
        <button type="button" className="btn-action ml-auto" onClick={() => setPoll((value) => value + 1)}>
          刷新轨迹
        </button>
      </div>
      {(events.data?.events ?? []).length > 0 && (
        <div className="mt-2 max-h-28 space-y-1 overflow-y-auto pr-1">
          {(events.data?.events ?? []).map((event) => {
            const payload = event.payload as Record<string, unknown>;
            return (
              <p key={event.id} className="truncate font-mono text-[11px] text-[var(--text-muted)]" title={payloadPreview(payload)}>
                · {EVENT_LABELS[String(payload?.type ?? event.event_type)] ?? String(payload?.type ?? event.event_type)}
                {payload?.tool ? ` [${String(payload.tool)}]` : ""} — {payloadPreview(payload)}
              </p>
            );
          })}
        </div>
      )}
    </div>
  );
}
