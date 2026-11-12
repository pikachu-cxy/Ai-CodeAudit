import { useState } from "react";
import { api, setAuthToken, setRefreshToken, setTokenExpiresAt, scheduleRefresh } from "../api";
import { Shield } from "./ui";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  usernameHint?: string | null;
  ssoEnabled?: boolean;
  ssoLoginUrl?: string | null;
  onLoggedIn: (username: string, role?: string) => void;
}

export function LoginPage({ usernameHint, ssoEnabled, ssoLoginUrl, onLoggedIn }: Props) {
  const [username, setUsername] = useState(usernameHint || "admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await api.login(username.trim(), password);
      if (result.access_token) {
        setAuthToken(result.access_token);
        if (result.refresh_token) {
          setRefreshToken(result.refresh_token);
          if (result.expires_in) {
            setTokenExpiresAt(Math.floor(Date.now() / 1000) + result.expires_in);
          }
          scheduleRefresh(result.expires_in);
        }
      }
      onLoggedIn(result.username, result.role || "admin");
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  };

  const handleSsoLogin = () => {
    if (ssoLoginUrl) {
      window.location.href = ssoLoginUrl;
    }
  };

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center p-6 relative">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-md audit-panel p-8 space-y-6">
        <div className="text-center space-y-3">
          <p className="text-[10px] font-mono tracking-[0.3em] text-cyan-500 uppercase">Code Security // Audit</p>
          <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold">安全审计工作台</h1>
            <p className="text-sm text-slate-500 mt-1">登录后访问审计报告与 Agent 面板</p>
          </div>
        </div>

        {ssoEnabled && ssoLoginUrl && (
          <>
            <button
              type="button"
              className="w-full py-2.5 px-4 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 font-medium text-sm hover:bg-cyan-500/20 transition-colors"
              onClick={handleSsoLogin}
            >
              通过 SSO 单点登录
            </button>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-slate-700"></div>
              </div>
              <div className="relative flex justify-center text-xs">
                <span className="px-3 bg-slate-900 text-slate-500">或使用账号密码</span>
              </div>
            </div>
          </>
        )}

        <form className="space-y-4" onSubmit={submit}>
          <label className="block text-xs text-slate-500">
            用户名
            <input
              className="input mt-1"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label className="block text-xs text-slate-500">
            密码
            <input
              className="input mt-1"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          {error && (
            <p className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
              {error}
            </p>
          )}
          <button type="submit" className="btn-primary w-full" disabled={loading}>
            {loading ? "登录中..." : "登录"}
          </button>
        </form>

        <p className="text-[10px] text-slate-600 text-center leading-relaxed">
          登录凭据见仓库根目录 .env 的 AUTH_USERNAME / AUTH_PASSWORD，部署后请立即修改。
        </p>
      </div>
    </div>
  );
}
