import { useState } from "react";
import { KeyRound, ShieldCheck, Trash2, UserRound } from "lucide-react";
import { api, type AccountOverview, type AccountSession, type AuditLogEntry } from "../../api";
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
  StatCard,
  StatusPill,
} from "../../shared/ui";
import { CapabilityNotice, Field, InlineMessage, Modal } from "../../shared/ui/forms";

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

const ACTION_LABELS: Record<string, string> = {
  "agent.create": "新增 Agent 配置",
  "agent.update": "修改 Agent 配置",
  "agent.delete": "删除 Agent 配置",
  "mcp.create": "新增 MCP Server",
  "mcp.update": "修改 MCP Server",
  "mcp.delete": "删除 MCP Server",
  "mcp.test": "MCP 连接测试",
  "account.revoke_session": "撤销会话",
  "account.cleanup_sessions": "清理过期会话",
  "account.change_password": "修改管理员密码",
};

export function AccountsPage(ctx: PageContext) {
  const overview = useAsyncData<AccountOverview>(() => api.getAccountOverview(), [ctx.refreshKey]);
  const sessions = useAsyncData<{ items: AccountSession[]; total: number }>(
    () => api.listAccountSessions(),
    [ctx.refreshKey],
  );
  const logs = useAsyncData<{ items: AuditLogEntry[]; total: number }>(
    () => api.listAuditLogs(30),
    [ctx.refreshKey],
  );

  const [passwordOpen, setPasswordOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [revokeSessions, setRevokeSessions] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "success" | "error" | "info"; text: string } | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  const reloadAll = () => {
    overview.reload();
    sessions.reload();
    logs.reload();
    ctx.onDataChanged();
  };

  const openPassword = () => {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setRevokeSessions(false);
    setMessage(null);
    setPasswordOpen(true);
  };

  const changePassword = async () => {
    if (newPassword !== confirmPassword) {
      setMessage({ tone: "error", text: "两次输入的新密码不一致。" });
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      const result = await api.changeAccountPassword({
        current_password: currentPassword,
        new_password: newPassword,
        revoke_sessions: revokeSessions,
      });
      setPasswordOpen(false);
      reloadAll();
      setMessage({
        tone: "success",
        text: `管理员密码已更新（bcrypt 存入数据库）。${result.sessions_revoked > 0 ? `已撤销 ${result.sessions_revoked} 条刷新会话。` : ""}`,
      });
    } catch (err) {
      setMessage({ tone: "error", text: `修改失败：${errorText(err)}` });
    } finally {
      setSaving(false);
    }
  };

  const revoke = async (id: number) => {
    setBusyId(id);
    try {
      await api.revokeAccountSession(id);
      reloadAll();
      setMessage({ tone: "success", text: "会话已撤销。" });
    } catch (err) {
      setMessage({ tone: "error", text: `撤销失败：${errorText(err)}` });
    } finally {
      setBusyId(null);
    }
  };

  const cleanup = async () => {
    try {
      const result = await api.cleanupAccountSessions();
      reloadAll();
      setMessage({ tone: "success", text: `已清理 ${result.removed} 条过期会话。` });
    } catch (err) {
      setMessage({ tone: "error", text: `清理失败：${errorText(err)}` });
    }
  };

  const data = overview.data;
  const sessionRows = sessions.data?.items ?? [];
  const logRows = logs.data?.items ?? [];

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Platform / Accounts"
        title="账户管理"
        description="查看真实认证状态、管理刷新会话、修改本地管理员密码并追溯平台管理操作。"
        actions={
          <button type="button" className="btn-primary inline-flex items-center gap-1.5" onClick={openPassword}>
            <KeyRound className="h-3.5 w-3.5" /> 修改管理员密码
          </button>
        }
      />

      <CapabilityNotice title="单管理员模型，暂无用户表与 RBAC">
        后端没有用户列表、邀请、角色分配或按用户的数据隔离接口，因此本页<strong>不展示任何虚构的用户条目</strong>。
        但会话管理、密码修改和操作留痕都已接入真实后端：会话来自 <MonoMeta>refresh_tokens</MonoMeta> 表，操作日志来自 <MonoMeta>platform_audit_logs</MonoMeta> 表。
      </CapabilityNotice>

      {message && <InlineMessage tone={message.tone}>{message.text}</InlineMessage>}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="当前身份" value={data?.username ?? (ctx.username || "—")} hint={data?.role === "admin" ? "管理员" : "成员"} />
        <StatCard label="认证开关" value={data?.auth_enabled ? "已启用" : "未启用"} hint="AUTH_ENABLED" />
        <StatCard label="活跃 / 全部会话" value={data ? String(data.session_count) : "—"} hint="refresh_tokens" />
        <StatCard label="密码来源" value={data?.password_source === "database" ? "数据库" : ".env"} hint={data?.password_storage ?? "—"} />
      </div>

      <SectionCard title="认证与安全状态" description="来自 /api/accounts/overview 的真实运行值，不回显任何密码或密钥内容。">
        {overview.loading ? (
          <LoadingState label="正在读取账户状态…" />
        ) : overview.error ? (
          <ErrorState message={overview.error} onRetry={() => overview.reload()} />
        ) : data ? (
          <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
            <div>
              <div className="flex items-center gap-2 pb-2">
                <UserRound className="h-4 w-4 text-cyan-500" />
                <h3 className="text-sm font-medium">身份与登录</h3>
              </div>
              <KeyValueRow label="用户名"><MonoMeta>{data.username}</MonoMeta></KeyValueRow>
              <KeyValueRow label="角色"><StatusPill tone={data.role === "admin" ? "accent" : "default"}>{data.role}</StatusPill></KeyValueRow>
              <KeyValueRow label="SSO"><StatusPill tone={data.sso_enabled ? "success" : "muted"}>{data.sso_enabled ? "已启用" : "未启用"}</StatusPill></KeyValueRow>
              <KeyValueRow label="用户管理"><StatusPill tone="muted">未开放</StatusPill></KeyValueRow>
            </div>
            <div>
              <div className="flex items-center gap-2 pb-2">
                <ShieldCheck className="h-4 w-4 text-cyan-500" />
                <h3 className="text-sm font-medium">令牌与凭据</h3>
              </div>
              <KeyValueRow label="密码存储"><MonoMeta>{data.password_storage}</MonoMeta></KeyValueRow>
              <KeyValueRow label="签名密钥"><StatusPill tone={data.secret_key_configured ? "success" : "warning"}>{data.secret_key_configured ? "长度合规" : "长度不足"}</StatusPill></KeyValueRow>
              <KeyValueRow label="访问令牌有效期"><MonoMeta>{data.token_expire_hours} 小时</MonoMeta></KeyValueRow>
              <KeyValueRow label="刷新令牌有效期"><MonoMeta>{data.refresh_expire_days} 天</MonoMeta></KeyValueRow>
            </div>
            <ul className="md:col-span-2 mt-2 space-y-1 border-t border-surface-border pt-3 text-xs leading-relaxed text-[var(--text-muted)]">
              {data.notes.map((note) => <li key={note}>· {note}</li>)}
            </ul>
          </div>
        ) : null}
      </SectionCard>

      <SectionCard
        title="刷新会话"
        description={`共 ${sessions.data?.total ?? 0} 条真实会话。撤销只删除 refresh token，已签发的 access token 到期前仍有效。`}
        actions={
          <button type="button" className="btn-action" onClick={() => void cleanup()}>
            <Trash2 className="mr-1 inline h-3 w-3" /> 清理过期会话
          </button>
        }
        bodyClassName="p-0"
      >
        {sessions.loading ? (
          <LoadingState label="正在读取会话…" />
        ) : sessions.error ? (
          <div className="p-4"><ErrorState message={sessions.error} onRetry={() => sessions.reload()} /></div>
        ) : sessionRows.length === 0 ? (
          <div className="p-4"><EmptyState title="暂无刷新会话" description="登录后会创建真实的 refresh token 记录。" /></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-surface-border text-[var(--text-muted)]">
                <tr>
                  <th className="px-4 py-2.5 font-medium">用户</th>
                  <th className="px-4 py-2.5 font-medium">令牌片段</th>
                  <th className="px-4 py-2.5 font-medium">来源</th>
                  <th className="px-4 py-2.5 font-medium">创建于</th>
                  <th className="px-4 py-2.5 font-medium">到期于</th>
                  <th className="px-4 py-2.5 font-medium">状态</th>
                  <th className="px-4 py-2.5 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--surface-border)]">
                {sessionRows.map((row) => (
                  <tr key={row.id}>
                    <td className="px-4 py-2.5">{row.username}<div className="text-[11px] text-[var(--text-faint)]">{row.role}</div></td>
                    <td className="px-4 py-2.5"><MonoMeta>{row.token_hint}</MonoMeta></td>
                    <td className="px-4 py-2.5 text-[var(--text-secondary)]">{row.sso_linked ? "SSO 关联" : "本地登录"}</td>
                    <td className="px-4 py-2.5 text-[var(--text-secondary)]">{formatDate(row.created_at)}</td>
                    <td className="px-4 py-2.5 text-[var(--text-secondary)]">{formatDate(row.expire_at)}</td>
                    <td className="px-4 py-2.5"><StatusPill tone={row.expired ? "warning" : "success"}>{row.expired ? "已过期" : "有效"}</StatusPill></td>
                    <td className="px-4 py-2.5 text-right">
                      <button type="button" className="btn-action btn-action-danger" onClick={() => void revoke(row.id)} disabled={busyId === row.id}>
                        {busyId === row.id ? "撤销中…" : "撤销"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <SectionCard
        title="平台管理操作留痕"
        description="最近 30 条真实操作记录（Agent / MCP / 账户变更）。日志不记录密码或凭据。"
        actions={<button type="button" className="btn-action" onClick={() => logs.reload()} disabled={logs.loading}>刷新</button>}
        bodyClassName="p-0"
      >
        {logs.loading ? (
          <LoadingState label="正在读取操作日志…" />
        ) : logs.error ? (
          <div className="p-4"><ErrorState message={logs.error} onRetry={() => logs.reload()} /></div>
        ) : logRows.length === 0 ? (
          <div className="p-4"><EmptyState title="暂无操作记录" description="新增或编辑 Agent / MCP 配置后，这里会出现真实记录。" /></div>
        ) : (
          <div className="divide-y divide-[var(--surface-border)]">
            {logRows.map((row) => (
              <div key={row.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-xs">
                <MonoMeta>{formatDate(row.created_at)}</MonoMeta>
                <StatusPill tone="default">{ACTION_LABELS[row.action] ?? row.action}</StatusPill>
                <span className="text-[var(--text-secondary)]">{row.actor}</span>
                {row.target_id && <MonoMeta>{row.target_type}:{row.target_id}</MonoMeta>}
                <span className="ml-auto max-w-[45%] truncate text-[11px] text-[var(--text-faint)]" title={JSON.stringify(row.detail)}>
                  {JSON.stringify(row.detail)}
                </span>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      {passwordOpen && (
        <Modal
          title="修改本地管理员密码"
          description="新密码经 bcrypt 哈希后写入数据库，覆盖 .env 的 AUTH_PASSWORD，无需重启服务。"
          width="max-w-lg"
          onClose={() => setPasswordOpen(false)}
          footer={
            <>
              <button type="button" className="btn-action" onClick={() => setPasswordOpen(false)} disabled={saving}>取消</button>
              <button type="button" className="btn-primary" onClick={() => void changePassword()} disabled={saving}>
                {saving ? "提交中…" : "确认修改"}
              </button>
            </>
          }
        >
          <div className="space-y-4">
            {message && <InlineMessage tone={message.tone}>{message.text}</InlineMessage>}
            <Field label="当前密码">
              <input className="input" type="password" autoComplete="current-password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
            </Field>
            <Field label="新密码" hint="长度 12–128 个字符，不能与当前密码相同。">
              <input className="input" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            </Field>
            <Field label="确认新密码">
              <input className="input" type="password" autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
            </Field>
            <label className="flex items-start gap-2 text-xs leading-relaxed text-[var(--text-secondary)]">
              <input type="checkbox" className="mt-0.5" checked={revokeSessions} onChange={(e) => setRevokeSessions(e.target.checked)} />
              <span>同时撤销全部刷新会话。勾选后当前浏览器在刷新令牌失效时可能需要重新登录。</span>
            </label>
          </div>
        </Modal>
      )}
    </div>
  );
}
