import { useState } from "react";
import { Bot, Pencil, Plus, Trash2 } from "lucide-react";
import {
  api,
  type AgentCapabilities,
  type AgentDefinition,
  type AgentPayload,
  type DeepAuditFocus,
  type ScanSummary,
} from "../../api";
import { DeepAuditLauncher } from "../../components/DeepAuditPanel";
import type { PageContext } from "../../app/pageTypes";
import { useAsyncData } from "../../shared/hooks/useAsyncData";
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
import { CapabilityNotice, Field, InlineMessage, Modal } from "../../shared/ui/forms";

const ROLE_LABELS: Record<string, string> = {
  planner: "Planner · 规划",
  worker: "Worker · 执行",
  reviewer: "Reviewer · 复核",
  reporter: "Reporter · 报告",
};

const EMPTY_FORM: AgentPayload = {
  slug: "",
  name: "",
  role: "worker",
  description: "",
  enabled: true,
  model_task: "agent",
  model_override: "",
  system_prompt: "",
  max_tool_rounds: 10,
  max_files: 16,
  max_tokens: 8192,
};

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function AgentsPage(ctx: PageContext) {
  const list = useAsyncData<AgentDefinition[]>(() => api.listAgents(), [ctx.refreshKey]);
  const caps = useAsyncData<AgentCapabilities>(() => api.getAgentCapabilities(), []);
  const scans = useAsyncData<ScanSummary[]>(
    () => api.listScans({ archived: "false" }),
    [ctx.refreshKey],
  );
  const [launchScanId, setLaunchScanId] = useState<number | null>(null);
  const [launchAgentSlug, setLaunchAgentSlug] = useState("");
  const [launchFocus, setLaunchFocus] = useState<DeepAuditFocus[]>([
    "authz",
    "injection",
    "business_logic",
  ]);
  const [editor, setEditor] = useState<{ mode: "create" | "edit"; id?: number } | null>(null);
  const [form, setForm] = useState<AgentPayload>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<AgentDefinition | null>(null);
  const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);

  const set = (patch: Partial<AgentPayload>) => setForm((prev) => ({ ...prev, ...patch }));

  const openCreate = () => {
    setForm(EMPTY_FORM);
    setMessage(null);
    setEditor({ mode: "create" });
  };

  const openEdit = (row: AgentDefinition) => {
    setForm({
      slug: row.slug,
      name: row.name,
      role: row.role,
      description: row.description,
      enabled: row.enabled,
      model_task: row.model_task,
      model_override: row.model_override,
      system_prompt: row.system_prompt,
      max_tool_rounds: row.max_tool_rounds,
      max_files: row.max_files,
      max_tokens: row.max_tokens,
    });
    setMessage(null);
    setEditor({ mode: "edit", id: row.id });
  };

  const save = async () => {
    if (!editor) return;
    setSaving(true);
    setMessage(null);
    try {
      if (editor.mode === "create") {
        await api.createAgent({ ...form, slug: form.slug.trim().toLowerCase() });
      } else if (editor.id !== undefined) {
        const { slug: _slug, ...patch } = form;
        void _slug;
        await api.updateAgent(editor.id, patch);
      }
      setEditor(null);
      list.reload();
      ctx.onDataChanged();
      setMessage({
        tone: "success",
        text: "Agent 配置已保存。启用后可在下方「启动 Deep Audit V1」中选中它，用于收紧唯一通用 Worker 的模型与预算；保存本身不会启动审计。",
      });
    } catch (err) {
      setMessage({ tone: "error", text: `保存失败：${errorText(err)}` });
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    try {
      await api.deleteAgent(deleting.id);
      setDeleting(null);
      list.reload();
      ctx.onDataChanged();
      setMessage({ tone: "success", text: `已删除 Agent 配置 ${deleting.slug}。` });
    } catch (err) {
      setMessage({ tone: "error", text: `删除失败：${errorText(err)}` });
    }
  };

  const capabilities = caps.data;
  const rows = list.data ?? [];

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Platform / Agents"
        title="Agent 配置"
        description="维护 Agent 角色定义、模型绑定与执行预算。启用的定义可被 Deep Audit V1 选中，作用于唯一的通用 Worker；原有扫描与 LLM 链路不受影响。"
        actions={
          <button type="button" className="btn-primary inline-flex items-center gap-1.5" onClick={openCreate}>
            <Plus className="h-3.5 w-3.5" /> 新增 Agent 配置
          </button>
        }
      />

      <CapabilityNotice title="Deep Audit V1 已接入：单 Worker 执行，不是多 Agent 编排" tone="cyan">
        已接入 Planner → <strong>1 个通用 Worker</strong> → 代码事实黑板 → 现有 Finding 体系的可选执行模式。
        启用的 AgentDefinition 只用于调整这个 Worker 的模型、附加提示词与预算上限，<strong>不会增加 Agent 数量</strong>；
        MCP / Skill 均未授予执行权限。无代码证据不会创建 Finding，候选一律 <MonoMeta>UNREVIEWED / PENDING</MonoMeta>，必须人工确认。
      </CapabilityNotice>

      {message && <InlineMessage tone={message.tone}>{message.text}</InlineMessage>}

      <SectionCard
        title="运行时能力边界"
        description="来自 /api/agents/capabilities 的真实运行时信息，不是静态说明。"
      >
        {caps.loading ? (
          <LoadingState label="正在读取运行时能力…" />
        ) : caps.error ? (
          <ErrorState message={caps.error} onRetry={() => caps.reload()} />
        ) : capabilities ? (
          <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
            <KeyValueRow label="运行状态">
              <StatusPill tone="warning">{capabilities.runtime_status}</StatusPill>
            </KeyValueRow>
            <KeyValueRow label="调度器">
              <MonoMeta>{capabilities.scheduler || "—"}</MonoMeta>
            </KeyValueRow>
            <KeyValueRow label="黑板">
              <MonoMeta>{capabilities.blackboard || "—"}</MonoMeta>
            </KeyValueRow>
            <KeyValueRow label="LLM 已配置">
              <StatusPill tone={capabilities.llm_configured ? "success" : "warning"}>
                {capabilities.llm_configured ? "是" : "否"}
              </StatusPill>
            </KeyValueRow>
            <KeyValueRow label="可选角色"><MonoMeta>{capabilities.roles.join(" / ")}</MonoMeta></KeyValueRow>
            <KeyValueRow label="默认模型"><MonoMeta>{capabilities.resolved_models.default}</MonoMeta></KeyValueRow>
            <KeyValueRow label="agent 任务模型"><MonoMeta>{capabilities.resolved_models.agent}</MonoMeta></KeyValueRow>
            <KeyValueRow label="工具轮次上限"><MonoMeta>{capabilities.agent_tool_round_limit}</MonoMeta></KeyValueRow>
            <KeyValueRow label="可用模型绑定"><MonoMeta>{capabilities.model_tasks.join(" / ")}</MonoMeta></KeyValueRow>
            <KeyValueRow label="Worker 数量 / 模式">
              <MonoMeta>
                {capabilities.deep_audit?.worker_count ?? 1} / {capabilities.deep_audit?.worker_mode ?? "—"}
              </MonoMeta>
            </KeyValueRow>
            <KeyValueRow label="MCP / Skill 授权">
              <StatusPill tone="muted">未授予执行权限</StatusPill>
            </KeyValueRow>
            <div className="md:col-span-2 pt-2 text-xs leading-relaxed text-[var(--text-muted)]">
              {capabilities.note}
            </div>
          </div>
        ) : null}
      </SectionCard>

      <SectionCard
        title="启动 Deep Audit V1"
        description="选择一个真实扫描任务和一条已启用的 AgentDefinition。Planner 只做纯数据规划，执行由唯一的只读 Worker 完成；不会自动授权 MCP / Skill。"
      >
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="扫描任务" hint="仅列出未归档的真实扫描任务。">
            <select
              className="input"
              value={launchScanId ?? ""}
              onChange={(event) =>
                setLaunchScanId(event.target.value ? Number(event.target.value) : null)
              }
            >
              <option value="">请选择扫描任务</option>
              {(scans.data ?? []).map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} · {scan.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Agent 定义" hint="只有启用状态的定义可选；留空使用内置默认 Worker。">
            <select
              className="input"
              value={launchAgentSlug}
              onChange={(event) => setLaunchAgentSlug(event.target.value)}
            >
              <option value="">内置默认 Worker</option>
              {(list.data ?? []).filter((row) => row.enabled).map((row) => (
                <option key={row.id} value={row.slug}>
                  {row.name} · {row.slug}
                </option>
              ))}
            </select>
          </Field>
        </div>
        {launchScanId ? (
          <div className="mt-4">
            <DeepAuditLauncher
              scanId={launchScanId}
              agentSlug={launchAgentSlug || undefined}
              focus={launchFocus}
              onFocusChange={setLaunchFocus}
              onStarted={(runId) => {
                setMessage({
                  tone: "success",
                  text: `Deep Audit 运行 #${runId} 已启动。可在该扫描任务详情页查看共享事实、代码证据与候选漏洞。`,
                });
                ctx.onDataChanged();
              }}
            />
          </div>
        ) : (
          <div className="mt-4">
            <InlineMessage tone="info">先选择一个扫描任务，再预览 Planner 任务或直接启动。</InlineMessage>
          </div>
        )}
        {scans.error && <div className="mt-3"><InlineMessage tone="error">读取扫描任务失败：{scans.error}</InlineMessage></div>}
      </SectionCard>

      <SectionCard
        title="Agent 定义"
        description={`共 ${rows.length} 条真实配置记录。`}
        actions={
          <button type="button" className="btn-action" onClick={() => list.reload()} disabled={list.loading}>
            刷新
          </button>
        }
        bodyClassName="p-0"
      >
        {list.loading ? (
          <LoadingState label="正在读取 Agent 配置…" />
        ) : list.error ? (
          <div className="p-4"><ErrorState message={list.error} onRetry={() => list.reload()} /></div>
        ) : rows.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={Bot}
              title="暂无 Agent 配置"
              description="新增的记录会持久化到 agent_definitions 表。此处不会预置任何示例数据。"
              action={<button type="button" className="btn-action" onClick={openCreate}>新增第一条配置</button>}
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-surface-border text-[var(--text-muted)]">
                <tr>
                  <th className="px-4 py-2.5 font-medium">名称 / 标识</th>
                  <th className="px-4 py-2.5 font-medium">角色</th>
                  <th className="px-4 py-2.5 font-medium">模型</th>
                  <th className="px-4 py-2.5 font-medium">预算</th>
                  <th className="px-4 py-2.5 font-medium">状态</th>
                  <th className="px-4 py-2.5 font-medium">更新于</th>
                  <th className="px-4 py-2.5 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--surface-border)]">
                {rows.map((row) => (
                  <tr key={row.id} className="hover:bg-[var(--hover-overlay)]">
                    <td className="px-4 py-3">
                      <p className="font-medium text-[var(--text-primary)]">{row.name}</p>
                      <MonoMeta>{row.slug}</MonoMeta>
                      {row.description && (
                        <p className="mt-1 max-w-xs truncate text-[11px] text-[var(--text-faint)]">{row.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[var(--text-secondary)]">{ROLE_LABELS[row.role] ?? row.role}</td>
                    <td className="px-4 py-3">
                      <MonoMeta>{row.model_task}</MonoMeta>
                      <p className="mt-1 max-w-[180px] truncate text-[11px] text-[var(--text-secondary)]" title={row.effective_model}>
                        → {row.effective_model}
                      </p>
                    </td>
                    <td className="px-4 py-3 text-[var(--text-secondary)]">
                      {row.max_files} 文件 / {row.max_tool_rounds} 轮 / {row.max_tokens} tokens
                    </td>
                    <td className="px-4 py-3">
                      <StatusPill tone={row.enabled ? "success" : "muted"}>
                        {row.enabled ? "已启用配置" : "已停用"}
                      </StatusPill>
                      <div className="mt-1">
                        <StatusPill tone={row.enabled ? "accent" : "muted"}>
                          {row.enabled ? "可选作 Deep Audit Worker" : "停用不可选"}
                        </StatusPill>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[var(--text-muted)]">{formatDate(row.updated_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1.5">
                        <button type="button" className="btn-action inline-flex items-center gap-1" onClick={() => openEdit(row)}>
                          <Pencil className="h-3 w-3" /> 编辑
                        </button>
                        <button type="button" className="btn-action btn-action-danger inline-flex items-center gap-1" onClick={() => setDeleting(row)}>
                          <Trash2 className="h-3 w-3" /> 删除
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      {editor && (
        <Modal
          title={editor.mode === "create" ? "新增 Agent 配置" : `编辑 ${form.slug}`}
          description="保存后写入配置表；启用后可在「启动 Deep Audit V1」中被选中。保存本身不会发起审计任务。"
          onClose={() => setEditor(null)}
          footer={
            <>
              <button type="button" className="btn-action" onClick={() => setEditor(null)} disabled={saving}>
                取消
              </button>
              <button type="button" className="btn-primary" onClick={() => void save()} disabled={saving}>
                {saving ? "保存中…" : "保存配置"}
              </button>
            </>
          }
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="标识 slug" hint="小写字母、数字、- 或 _；创建后不可修改。">
              <input
                className="input"
                value={form.slug}
                disabled={editor.mode === "edit"}
                onChange={(e) => set({ slug: e.target.value })}
                placeholder="code-worker"
              />
            </Field>
            <Field label="名称">
              <input className="input" value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="Code Audit Worker" />
            </Field>
            <Field label="角色">
              <select className="input" value={form.role} onChange={(e) => set({ role: e.target.value })}>
                {(capabilities?.roles ?? Object.keys(ROLE_LABELS)).map((role) => (
                  <option key={role} value={role}>{ROLE_LABELS[role] ?? role}</option>
                ))}
              </select>
            </Field>
            <Field label="模型绑定" hint="映射到现有 llm_model_* 设置，default 表示全局 llm_model。">
              <select className="input" value={form.model_task} onChange={(e) => set({ model_task: e.target.value })}>
                {(capabilities?.model_tasks ?? ["default", "fp", "deep", "agent"]).map((task) => (
                  <option key={task} value={task}>{task}</option>
                ))}
              </select>
            </Field>
            <div className="md:col-span-2">
              <Field label="模型名称覆盖" hint="留空则使用上一步解析出的模型；填了也不会触发任何模型调用。">
                <input className="input" value={form.model_override} onChange={(e) => set({ model_override: e.target.value })} placeholder="留空使用任务默认模型" />
              </Field>
            </div>
            <div className="md:col-span-2">
              <Field label="描述">
                <textarea className="input min-h-[70px]" value={form.description} onChange={(e) => set({ description: e.target.value })} placeholder="这个 Agent 负责的范围（仅作配置说明）" />
              </Field>
            </div>
            <div className="md:col-span-2">
              <Field label="系统提示词" hint="Deep Audit V1 会将此文本作为附加指令传给唯一的通用 Worker；仍受只读工具白名单与硬预算约束。">
                <textarea className="input min-h-[110px] font-mono text-xs" value={form.system_prompt} onChange={(e) => set({ system_prompt: e.target.value })} placeholder="You are a code audit worker…" />
              </Field>
            </div>
            <Field label="最大文件数" hint="1–200">
              <input className="input" type="number" min={1} max={200} value={form.max_files} onChange={(e) => set({ max_files: Number(e.target.value) })} />
            </Field>
            <Field label="最大工具轮次" hint="1–50">
              <input className="input" type="number" min={1} max={50} value={form.max_tool_rounds} onChange={(e) => set({ max_tool_rounds: Number(e.target.value) })} />
            </Field>
            <Field label="最大 tokens" hint="256–200000">
              <input className="input" type="number" min={256} max={200000} value={form.max_tokens} onChange={(e) => set({ max_tokens: Number(e.target.value) })} />
            </Field>
            <label className="flex items-center gap-2 self-end pb-2 text-xs text-[var(--text-secondary)]">
              <input type="checkbox" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              启用此配置记录（可在启动 Deep Audit 时被选中，不会自动执行）
            </label>
          </div>
        </Modal>
      )}

      {deleting && (
        <Modal
          title="删除 Agent 配置"
          onClose={() => setDeleting(null)}
          width="max-w-md"
          footer={
            <>
              <button type="button" className="btn-action" onClick={() => setDeleting(null)}>取消</button>
              <button type="button" className="btn-action btn-action-danger" onClick={() => void remove()}>确认删除</button>
            </>
          }
        >
          <p className="text-sm text-[var(--text-secondary)]">
            将删除 <MonoMeta>{deleting.slug}</MonoMeta> 这条配置记录。已完成的 Deep Audit 运行保留原有配置快照，不会被追溯改写；此操作不删除扫描任务或漏洞数据。
          </p>
        </Modal>
      )}
    </div>
  );
}
