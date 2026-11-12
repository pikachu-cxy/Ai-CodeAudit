import { useCallback, useEffect, useState } from "react";
import {
  api,
  clearAllTokens,
  getAuthToken,
  normalizeAuthRole,
  refreshAuth,
  scheduleRefresh,
  setAuthToken,
  setOnUnauthorized,
  setRefreshToken,
  type AuthRole,
} from "../api";

export type AuthState =
  | { status: "loading" }
  | { status: "guest"; usernameHint?: string | null }
  | { status: "authed"; username: string; role: AuthRole };

export function useAuth() {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoLoginUrl, setSsoLoginUrl] = useState<string | null>(null);

  useEffect(() => {
    setOnUnauthorized(() => setAuth({ status: "guest" }));

    const bootstrap = async () => {
      const hash = window.location.hash;
      if (hash && hash.includes("access_token=")) {
        const params = new URLSearchParams(hash.substring(1));
        const token = params.get("access_token");
        const ssoUsername = params.get("username");
        const ssoRefreshToken = params.get("refresh_token");
        const ssoRole = normalizeAuthRole(params.get("role"));
        if (token) {
          setAuthToken(token);
          if (ssoRefreshToken) {
            setRefreshToken(ssoRefreshToken);
            scheduleRefresh();
          }
          window.history.replaceState(
            {},
            "",
            window.location.pathname + window.location.search,
          );
          try {
            const user = await api.me();
            setAuth({
              status: "authed",
              username: user.username || ssoUsername || "",
              role: normalizeAuthRole(user.role ?? ssoRole),
            });
          } catch {
            setAuth(
              ssoUsername
                ? { status: "authed", username: ssoUsername, role: ssoRole }
                : { status: "guest" },
            );
          }
          return;
        }
      }

      try {
        const config = await api.authConfig();
        setSsoEnabled(config.sso_enabled ?? false);
        setSsoLoginUrl(config.sso_login_url ?? null);
        if (!config.auth_enabled) {
          setAuth({
            status: "authed",
            username: config.username_hint || "system",
            role: "admin",
          });
          return;
        }
        if (!getAuthToken()) {
          setAuth({ status: "guest", usernameHint: config.username_hint });
          return;
        }
        try {
          const user = await api.me();
          setAuth({
            status: "authed",
            username: user.username,
            role: normalizeAuthRole(user.role),
          });
          scheduleRefresh();
        } catch {
          const ok = await refreshAuth();
          if (!ok) {
            setAuth({ status: "guest" });
            return;
          }
          try {
            const user = await api.me();
            setAuth({
              status: "authed",
              username: user.username,
              role: normalizeAuthRole(user.role),
            });
          } catch {
            setAuth({ status: "guest" });
          }
        }
      } catch {
        setAuth({ status: "guest" });
      }
    };

    void bootstrap();
  }, []);

  const logout = useCallback(() => {
    clearAllTokens();
    setAuth({ status: "guest" });
  }, []);

  const markAuthed = useCallback((username: string, role: string) => {
    setAuth({ status: "authed", username, role: normalizeAuthRole(role) });
  }, []);

  return { auth, ssoEnabled, ssoLoginUrl, logout, markAuthed };
}
