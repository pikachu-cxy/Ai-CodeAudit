import { useState } from "react";
import { Pencil, Plug, Plus, Trash2, Zap } from "lucide-react";
import {
  api,
  type McpCapabilities,
  type McpServer,
  type McpServerPayload,
  type McpTestResult,
} from "../../api";
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

function blankForm(): McpServerPayload {
  return {
    slug: "",
    name: "",
    description: "",
    transport: "http",
    endpoint: "",
    command: "",
    args: [],
    headers: {},
    timeout_seconds: 5,
    enabled: false,
  };
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function parseHeaders(text: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf(":");
    if (index < 1) continue;
    const key = trimmed.slice(0, index).trim();
    if (key) result[key] = trimmed.slice(index + 1).trim();
  }
  return result;
}

function testTone(status: string): "success" | "error" | "info" {
  if (status === "connected") return "success";
  if (status === "not_executed" || status === "blocked" || status === "invalid") return "info";
  return "error";
}

export function McpPage(ctx: PageContext) {
  const list = useAsyncData<McpServer[]>(() => api.listMcpServers(), [ctx.refreshKey]);
  const caps = useAsyncData<McpCapabilities>(() => api.getMcpCapabilities(), []);
  const [editor, setEditor] = useState<{ mode: "create" | "edit"; id?: number } | null>(null);
  const [form, setForm] = useState<McpServerPayload>(blankForm);
  const [argsText, setArgsText] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<number | null>(null);
  const [testResult, setTestResult] = useState<McpTestResult | null>(null);
  const [deleting, setDeleting] = useState<McpServer | null>(null);
  const [message, setMessage] = useState<{ tone: "success" | "error"; text: string } | null>(null);

  const set = (patch: Partial<McpServerPayload>) => setForm((prev) => ({ ...prev, ...patch }));

  const openCreate = () => {
    setForm(blankForm());
    setArgsText("");
    setHeadersText("");
    setMessage(null);
    setEditor({ mode: "create" });
  };

  const openEdit = (row: McpServer) => {
    setForm({
      slug: row.slug,
      name: row.name,
      description: row.description,
      transport: row.transport,
      endpoint: row.endpoint,
      command: row.command,
      args: row.args,
      headers: row.headers,
      timeout_seconds: row.timeout_seconds,
      enabled: row.enabled,
    });
    setArgsText(row.args.join("\n"));
    setHeadersText(Object.entries(row.headers).map(([k, v]) => `${k}: ${v}`).join("\n"));
    setMessage(null);
    setEditor({ mode: "edit", id: row.id });
  };

  const save = async () => {
    if (!editor) return;
    setSaving(true);
    setMessage(null);
    const payload: McpServerPayload = {
      ...form,
      slug: form.slug.trim().toLowerCase(),
      args: argsText.split("\n").map((line) => line.trim()).filter(Boolean),
      headers: parseHeaders(headersText),
      timeout_seconds: Number(form.timeout_seconds),
    };
    try {
      if (editor.mode === "create") {
        await api.createMcpServer(payload);
      } else if (editor.id !== undefined) {
        const { slug: _slug, ...patch } = payload;
        void _slug;
        await api.updateMcpServer(editor.id, patch);
      }
      setEditor(null);
      setTestResult(null);
      list.reload();
      ctx.onDataChanged();
      setMessage({ tone: "success", text: "MCP Server 配置已保存。连接状态需通过「测试连接」真实探测后才会更新。" });
    } catch (err) {
      setMessage({ tone: "error", text: `保存失败：${errorText(err)}` });
    } finally {
      setSaving(false);
    }
  };

  const test = async (row: McpServer) => {
    setTesting(row.id);
    setTestResult(null);
    try {
      const result = await api.testMcpServer(row.id);
      setTestResult(result);
      list.reload();
      ctx.onDataChanged();
    } catch (err) {
      setTestResult({
        ok: false,
        status: "request_failed",
        message: `测试请求失败：${errorText(err)}`,
        latency_ms: null,
        checked_at: null,
        server_info: null,
      });
    } finally {
      setTesting(null);
    }
  };

  const remove = async () => {
    if (!deleting) return;
    try {
      await api.deleteMcpServer(deleting.id);
      setDeleting(null);
      list.reload();
      ctx.onDataChanged();
      setMessage({ tone: "success", text: `已删除 MCP Server ${deleting.slug}。` });
    } catch (err) {
      setMessage({ tone: "error", text: `删除失败：${errorText(err)}` });
    }
  };

  const capabilities = caps.data;
  const rows = list.data ?? [];
  const isStdio = form.transport === "stdio";

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Platform / MCP"
        title="MCP 管理"
        description="注册 MCP Server、保存连接参数并发起真实的 initialize 握手测试。工具执行与 Agent 绑定尚未接入。"
        actions={
          <button type="button" className="btn-primary inline-flex items-center gap-1.5" onClick={openCreate}>
            <Plus className="h-3.5 w-3.5" /> 新增 MCP Server
          </button>
        }
      />

      <CapabilityNotice title="注册表与连接测试可用，工具执行未开放">
        增删改查、凭据类 Header 拦截、SSRF 防护和 HTTP/SSE 的 <MonoMeta>initialize</MonoMeta> 握手测试都是真实行为，结果会落库。
        但当前<strong>不枚举工具、不调用工具、不启动 stdio 进程、不保存任何凭据</strong>，也不会把 Server 绑定到 Agent 或扫描流程。
      </CapabilityNotice>

      {message && <InlineMessage tone={message.tone}>{message.text}</InlineMessage>}
      {testResult && (
        <InlineMessage tone={testTone(testResult.status)}>
          <strong>连接测试 · {testResult.status}</strong>：{testResult.message}
          {testResult.latency_ms !== null && <span className="ml-2">（{testResult.latency_ms} ms）</span>}
          {testResult.server_info?.server_name && <span className="ml-2">服务端：{testResult.server_info.server_name}</span>}
        </InlineMessage>
      )}

      <SectionCard title="连接能力与安全边界" description="来自 /api/mcp/capabilities 的真实配置。">
        {caps.loading ? (
          <LoadingState label="正在读取连接能力…" />
        ) : caps.error ? (
          <ErrorState message={caps.error} onRetry={() => caps.reload()} />
        ) : capabilities ? (
          <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
            <KeyValueRow label="支持的传输方式"><MonoMeta>{capabilities.transports.join(" / ")}</MonoMeta></KeyValueRow>
            <KeyValueRow label="stdio 进程执行">
              <StatusPill tone="muted">未开放</StatusPill>
            </KeyValueRow>
            <KeyValueRow label="凭据存储"><StatusPill tone="muted">不保存</StatusPill></KeyValueRow>
            <KeyValueRow label="跟随重定向"><StatusPill tone="muted">否</StatusPill></KeyValueRow>
            <KeyValueRow label="SSRF 防护"><MonoMeta>{capabilities.ssrf_guard}</MonoMeta></KeyValueRow>
            <KeyValueRow label="探测方式"><MonoMeta>{capabilities.probe}</MonoMeta></KeyValueRow>
            <div className="md:col-span-2 pt-2 text-xs leading-relaxed text-[var(--text-muted)]">{capabilities.note}</div>
          </div>
        ) : null}
      </SectionCard>

      <SectionCard
        title="MCP Server"
        description={`共 ${rows.length} 条真实注册记录。「测试连接」会发起一次真实网络请求。`}
        actions={<button type="button" className="btn-action" onClick={() => list.reload()} disabled={list.loading}>刷新</button>}
        bodyClassName="p-0"
      >
        {list.loading ? (
          <LoadingState label="正在读取 MCP Server…" />
        ) : list.error ? (
          <div className="p-4"><ErrorState message={list.error} onRetry={() => list.reload()} /></div>
        ) : rows.length === 0 ? (
          <div className="p-4">
            <EmptyState
              icon={Plug}
              title="暂无 MCP Server"
              description="这里只显示后端真实返回的记录，不会填充示例服务器或伪造「已连接」状态。"
              action={<button type="button" className="btn-action" onClick={openCreate}>新增第一条记录</button>}
            />
          </div>
        ) : (
          <div className="divide-y divide-[var(--surface-border)]">
            {rows.map((row) => (
              <div key={row.id} className="flex flex-wrap items-start gap-3 px-4 py-3">
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-surface-border bg-[var(--bg-muted)] text-[var(--text-muted)]">
                  <Plug className="h-4 w-4" />
                </span>
                <div className="min-w-[200px] flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium">{row.name}</p>
                    <MonoMeta>{row.slug}</MonoMeta>
                    <StatusPill tone={row.enabled ? "success" : "muted"}>{row.enabled ? "已启用注册" : "未启用"}</StatusPill>
                    <StatusPill tone="muted">{row.transport}</StatusPill>
                  </div>
                  <p className="mt-1 break-all text-[11px] text-[var(--text-muted)]">
                    {row.transport === "stdio" ? row.command || "(未配置命令)" : row.endpoint || "(未配置 endpoint)"}
                  </p>
                  {row.description && <p className="mt-1 text-[11px] text-[var(--text-faint)]">{row.description}</p>}
                  <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-secondary)]">
                    {row.last_test_ok === null ? (
                      <span>尚未进行连接测试</span>
                    ) : (
                      <>
                        <StatusPill tone={row.last_test_ok ? "success" : "warning"}>
                          {row.last_test_ok ? "握手成功" : "未连通"}
                        </StatusPill>
                        <span title={row.last_test_message} className="max-w-[380px] truncate">{row.last_test_message}</span>
                        <span>{formatDate(row.last_test_at)}</span>
                        {row.last_test_latency_ms !== null && <span>{row.last_test_latency_ms} ms</span>}
                      </>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 flex-wrap gap-1.5">
                  <button type="button" className="btn-action inline-flex items-center gap-1" onClick={() => void test(row)} disabled={testing === row.id}>
                    <Zap className="h-3 w-3" /> {testing === row.id ? "测试中…" : "测试连接"}
                  </button>
                  <button type="button" className="btn-action inline-flex items-center gap-1" onClick={() => openEdit(row)}>
                    <Pencil className="h-3 w-3" /> 编辑
                  </button>
                  <button type="button" className="btn-action btn-action-danger inline-flex items-center gap-1" onClick={() => setDeleting(row)}>
                    <Trash2 className="h-3 w-3" /> 删除
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      {editor && (
        <Modal
          title={editor.mode === "create" ? "新增 MCP Server" : `编辑 ${form.slug}`}
          description="仅保存连接描述；保存不会自动发起连接测试。"
          onClose={() => setEditor(null)}
          footer={
            <>
              <button type="button" className="btn-action" onClick={() => setEditor(null)} disabled={saving}>取消</button>
              <button type="button" className="btn-primary" onClick={() => void save()} disabled={saving}>
                {saving ? "保存中…" : "保存配置"}
              </button>
            </>
          }
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="标识 slug" hint="创建后不可修改。">
              <input className="input" value={form.slug} disabled={editor.mode === "edit"} onChange={(e) => set({ slug: e.target.value })} placeholder="internal-mcp" />
            </Field>
            <Field label="名称">
              <input className="input" value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="Internal MCP" />
            </Field>
            <Field label="传输方式" hint="stdio 只保存命令描述，不会执行。">
              <select className="input" value={form.transport} onChange={(e) => set({ transport: e.target.value })}>
                {(capabilities?.transports ?? ["http", "sse", "stdio"]).map((item) => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </select>
            </Field>
            <Field label="超时（秒）" hint="1–30 秒">
              <input className="input" type="number" min={1} max={30} value={form.timeout_seconds} onChange={(e) => set({ timeout_seconds: Number(e.target.value) })} />
            </Field>
            {!isStdio && (
              <div className="md:col-span-2">
                <Field label="Endpoint" hint="http/https 完整地址。连接测试会拦截回环、内网和元数据地址。">
                  <input className="input" value={form.endpoint} onChange={(e) => set({ endpoint: e.target.value })} placeholder="https://mcp.example.com/mcp" />
                </Field>
              </div>
            )}
            {isStdio && (
              <>
                <div className="md:col-span-2">
                  <Field label="命令" hint="仅作为配置保存，平台不会启动该进程。">
                    <input className="input" value={form.command} onChange={(e) => set({ command: e.target.value })} placeholder="node server.js" />
                  </Field>
                </div>
                <div className="md:col-span-2">
                  <Field label="启动参数" hint="每行一个参数。">
                    <textarea className="input min-h-[70px]" value={argsText} onChange={(e) => setArgsText(e.target.value)} placeholder={"--stdio\n--verbose"} />
                  </Field>
                </div>
              </>
            )}
            <div className="md:col-span-2">
              <Field label="自定义请求 Header" hint="每行一个 Key: Value。凭据类 Header（Authorization / X-Api-Key / Cookie / Token 等）会被后端拒绝，不会保存。">
                <textarea className="input min-h-[70px] font-mono text-xs" value={headersText} onChange={(e) => setHeadersText(e.target.value)} placeholder={"X-Client: ai-audit\nX-Env: prod"} />
              </Field>
            </div>
            <div className="md:col-span-2">
              <Field label="描述">
                <textarea className="input min-h-[70px]" value={form.description} onChange={(e) => set({ description: e.target.value })} placeholder="用途说明" />
              </Field>
            </div>
            <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)] md:col-span-2">
              <input type="checkbox" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              启用此注册记录（不会自动连接或执行工具）
            </label>
          </div>
        </Modal>
      )}

      {deleting && (
        <Modal
          title="删除 MCP Server"
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
            将删除 <MonoMeta>{deleting.slug}</MonoMeta> 及其连接测试记录，不会关闭外部进程或远端服务。
          </p>
        </Modal>
      )}
    </div>
  );
}
