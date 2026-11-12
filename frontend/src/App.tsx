import { useCallback, useMemo, useState, type ReactNode } from "react";
import { AppShell } from "./app/AppShell";
import { legacyRedirect, navigate, useRoute, type Route } from "./app/router";
import { useAuth } from "./app/useAuth";
import type { PageContext } from "./app/pageTypes";
import { NotFoundPage } from "./app/NotFoundPage";
import { ExternalFindingReviewView } from "./components/ExternalFindingReviewView";
import { ExternalProjectReviewView } from "./components/ExternalProjectReviewView";
import { LoginPage } from "./components/LoginPage";
import { DashboardPage } from "./modules/dashboard/DashboardPage";
import { ChatPage } from "./modules/chat/ChatPage";
import { ProjectsPage } from "./modules/projects/ProjectsPage";
import { NewProjectPage } from "./modules/projects/NewProjectPage";
import { ProjectOverviewPage } from "./modules/projects/ProjectOverviewPage";
import { ScanWorkspace } from "./modules/projects/ScanWorkspace";
import { TasksPage } from "./modules/tasks/TasksPage";
import { AgentsPage } from "./modules/agents/AgentsPage";
import { SkillsPage } from "./modules/skills/SkillsPage";
import { McpPage } from "./modules/mcp/McpPage";
import { LlmPage } from "./modules/llm/LlmPage";
import { SystemPage } from "./modules/system/SystemPage";
import { AccountsPage } from "./modules/accounts/AccountsPage";

/**
 * One-time migration of pre-refactor query URLs. Runs at module evaluation so
 * the very first render already sees the canonical path (no flash of the
 * dashboard before a deep link resolves). External review tokens and SSO
 * callback hashes are deliberately left untouched by `legacyRedirect()`.
 */
const BOOT_REDIRECT = legacyRedirect();
if (BOOT_REDIRECT) {
  window.history.replaceState({}, "", BOOT_REDIRECT + window.location.hash);
}

/** Routes whose content owns its own scroll container / bottom-anchored bar. */
function isFillRoute(route: Route): boolean {
  switch (route.name) {
    case "project":
      return route.scanId !== null;
    case "task":
    case "chat":
    case "llm":
    case "system":
      return true;
    default:
      return false;
  }
}

function renderRoute(route: Route, ctx: PageContext): ReactNode {
  switch (route.name) {
    case "dashboard":
      return <DashboardPage {...ctx} />;
    case "chat":
      return <ChatPage {...ctx} projectId={route.projectId} scanId={route.scanId} />;
    case "projects":
      return <ProjectsPage {...ctx} />;
    case "newProject":
      return <NewProjectPage {...ctx} appendProjectId={route.appendProjectId} />;
    case "project":
      return route.scanId ? (
        <ScanWorkspace
          scanId={route.scanId}
          projectId={route.projectId}
          findingId={route.findingId}
          base="project"
          refreshKey={ctx.refreshKey}
          onDataChanged={ctx.onDataChanged}
        />
      ) : (
        <ProjectOverviewPage {...ctx} projectId={route.projectId} />
      );
    case "tasks":
      return <TasksPage {...ctx} />;
    case "task":
      return (
        <ScanWorkspace
          scanId={route.taskId}
          projectId={null}
          findingId={route.findingId}
          base="task"
          refreshKey={ctx.refreshKey}
          onDataChanged={ctx.onDataChanged}
        />
      );
    case "agents":
      return <AgentsPage {...ctx} />;
    case "skills":
      return <SkillsPage {...ctx} />;
    case "mcp":
      return <McpPage {...ctx} />;
    case "llm":
      return <LlmPage {...ctx} />;
    case "system":
      return <SystemPage {...ctx} />;
    case "accounts":
      return <AccountsPage {...ctx} />;
    case "notFound":
      return <NotFoundPage path={route.path} />;
    default:
      return <NotFoundPage path={window.location.pathname} />;
  }
}

export default function App() {
  const { auth, ssoEnabled, ssoLoginUrl, logout, markAuthed } = useAuth();
  const route = useRoute();
  const [refreshKey, setRefreshKey] = useState(0);

  const onDataChanged = useCallback(() => setRefreshKey((value) => value + 1), []);
  const handleLogout = useCallback(() => {
    logout();
    navigate("/dashboard", true);
  }, [logout]);

  const ctx: PageContext = useMemo(
    () => ({
      refreshKey,
      onDataChanged,
      username: auth.status === "authed" ? auth.username : "",
      isAdmin: auth.status === "authed" && auth.role === "admin",
      onLogout: handleLogout,
    }),
    [refreshKey, onDataChanged, auth, handleLogout],
  );

  const reviewToken = useMemo(() => {
    const value = new URLSearchParams(window.location.search).get("reviewToken");
    return value?.trim() || null;
  }, []);

  const projectReviewToken = useMemo(() => {
    const value = new URLSearchParams(window.location.search).get("projectReviewToken");
    return value?.trim() || null;
  }, []);

  const content = renderRoute(route, ctx);
  const fill = isFillRoute(route);

  if (projectReviewToken) {
    return <ExternalProjectReviewView token={projectReviewToken} />;
  }
  if (reviewToken) {
    return <ExternalFindingReviewView token={reviewToken} />;
  }
  if (auth.status === "loading") {
    return (
      <div className="grid-bg flex min-h-screen items-center justify-center font-mono text-sm text-[var(--text-secondary)]">
        INITIALIZING…
      </div>
    );
  }
  if (auth.status === "guest") {
    return (
      <LoginPage
        usernameHint={auth.usernameHint}
        ssoEnabled={ssoEnabled}
        ssoLoginUrl={ssoLoginUrl}
        onLoggedIn={(username, role) => markAuthed(username, role ?? "")}
      />
    );
  }

  return (
    <AppShell
      route={route}
      username={ctx.username}
      isAdmin={ctx.isAdmin}
      onLogout={handleLogout}
      contentScroll={!fill}
      onRefresh={onDataChanged}
    >
      {content}
    </AppShell>
  );
}
