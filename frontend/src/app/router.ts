import { useEffect, useMemo, useState } from "react";

/**
 * Minimal History-API router. No router library is introduced on purpose.
 * Pathname routes are the canonical form; legacy query-string bookmarks are
 * redirected once at startup by `legacyRedirect()`.
 */
export type Route =
  | { name: "dashboard" }
  | { name: "chat"; projectId: number | null; scanId: number | null }
  | { name: "projects" }
  | { name: "newProject"; appendProjectId: number | null }
  | { name: "project"; projectId: number; scanId: number | null; findingId: number | null }
  | { name: "tasks" }
  | { name: "task"; taskId: number; findingId: number | null }
  | { name: "agents" }
  | { name: "skills" }
  | { name: "mcp" }
  | { name: "llm" }
  | { name: "system" }
  | { name: "accounts" }
  | { name: "notFound"; path: string };

function positiveInt(raw: string | null): number | null {
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : null;
}

export function parseRoute(url: URL | string = window.location.href): Route {
  const parsed = typeof url === "string" ? new URL(url, window.location.origin) : url;
  const parts = parsed.pathname.split("/").filter(Boolean);
  const q = parsed.searchParams;
  const root = (parts[0] || "").toLowerCase();

  switch (root) {
    case "":
    case "dashboard":
      return { name: "dashboard" };
    case "chat":
      return {
        name: "chat",
        projectId: positiveInt(q.get("projectId")),
        scanId: positiveInt(q.get("scanId")),
      };
    case "projects": {
      if (parts[1] === "new") {
        return { name: "newProject", appendProjectId: positiveInt(q.get("appendProjectId")) };
      }
      const projectId = positiveInt(parts[1] ?? null);
      if (projectId) {
        return {
          name: "project",
          projectId,
          scanId: positiveInt(q.get("scan")),
          findingId: positiveInt(q.get("finding")),
        };
      }
      return { name: "projects" };
    }
    case "tasks": {
      const taskId = positiveInt(parts[1] ?? null);
      return taskId
        ? { name: "task", taskId, findingId: positiveInt(q.get("finding")) }
        : { name: "tasks" };
    }
    case "agents":
      return { name: "agents" };
    case "skills":
      return { name: "skills" };
    case "mcp":
      return { name: "mcp" };
    case "llm":
      return { name: "llm" };
    case "system":
      return { name: "system" };
    case "accounts":
      return { name: "accounts" };
    default:
      return { name: "notFound", path: parsed.pathname };
  }
}

export function routeToUrl(route: Route): string {
  switch (route.name) {
    case "dashboard":
      return "/dashboard";
    case "chat": {
      const q = new URLSearchParams();
      if (route.projectId) q.set("projectId", String(route.projectId));
      if (route.scanId) q.set("scanId", String(route.scanId));
      return `/chat${q.size ? `?${q}` : ""}`;
    }
    case "projects":
      return "/projects";
    case "newProject":
      return `/projects/new${route.appendProjectId ? `?appendProjectId=${route.appendProjectId}` : ""}`;
    case "project": {
      const q = new URLSearchParams();
      if (route.scanId) q.set("scan", String(route.scanId));
      if (route.findingId) q.set("finding", String(route.findingId));
      return `/projects/${route.projectId}${q.size ? `?${q}` : ""}`;
    }
    case "tasks":
      return "/tasks";
    case "task":
      return `/tasks/${route.taskId}${route.findingId ? `?finding=${route.findingId}` : ""}`;
    default:
      return `/${route.name}`;
  }
}

/** Push/replace a URL and notify subscribers (History API has no native event). */
export function navigate(url: string, replace = false): void {
  const current = window.location.pathname + window.location.search + window.location.hash;
  if (url === current) return;
  if (replace) {
    window.history.replaceState({}, "", url);
  } else {
    window.history.pushState({}, "", url);
  }
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function useRoute(): Route {
  const [snapshot, setSnapshot] = useState(
    () => window.location.pathname + window.location.search,
  );

  useEffect(() => {
    const onChange = () => setSnapshot(window.location.pathname + window.location.search);
    window.addEventListener("popstate", onChange);
    return () => window.removeEventListener("popstate", onChange);
  }, []);

  return useMemo(() => parseRoute(), [snapshot]);
}

/**
 * Convert pre-refactor query URLs to canonical paths so old bookmarks,
 * report links and browser history keep working.
 *
 * Legacy forms:
 *   /?view=detail&scanId=N&projectId=M[&findingId=K]
 *   /?view=finding&scanId=N&findingId=K&projectId=M
 *   /?view=new[&appendProjectId=M]
 *   /?view=home
 */
export function legacyRedirect(): string | null {
  const url = new URL(window.location.href);
  const q = url.searchParams;

  // External review tokens and SSO callback hashes are handled by the auth gate.
  if (q.has("reviewToken") || q.has("projectReviewToken") || url.hash.includes("access_token=")) {
    return null;
  }

  const view = (q.get("view") || "").trim().toLowerCase();
  const scanId = positiveInt(q.get("scanId"));
  const projectId = positiveInt(q.get("projectId"));
  const findingId = positiveInt(q.get("findingId"));
  const appendProjectId = positiveInt(q.get("appendProjectId"));

  if (view === "new" || appendProjectId) {
    return appendProjectId ? `/projects/new?appendProjectId=${appendProjectId}` : "/projects/new";
  }

  if (scanId) {
    const params = new URLSearchParams();
    if (findingId) params.set("finding", String(findingId));
    const suffix = params.size ? `?${params}` : "";
    return projectId ? `/projects/${projectId}?scan=${scanId}${suffix.replace("?", "&")}` : `/tasks/${scanId}${suffix}`;
  }

  if (projectId && !findingId) return `/projects/${projectId}`;

  // Only rewrite bare legacy roots, never an already-canonical path.
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return "/dashboard";
  }
  return null;
}
