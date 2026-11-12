import { ChevronRight } from "lucide-react";
import { navigate, type Route } from "./router";
import { navItemForPath } from "./navigation";

interface Crumb {
  label: string;
  href?: string;
}

function crumbsFor(route: Route): Crumb[] {
  const root = navItemForPath(window.location.pathname);
  const home: Crumb = { label: root?.label ?? "工作台" };

  switch (route.name) {
    case "project":
      return [
        { label: "项目", href: "/projects" },
        { label: `#${route.projectId}`, href: `/projects/${route.projectId}` },
        ...(route.findingId ? [{ label: `漏洞 #${route.findingId}` }] : []),
      ];
    case "newProject":
      return [{ label: "项目", href: "/projects" }, { label: "新建 / 追加版本" }];
    case "task":
      return [{ label: "任务", href: "/tasks" }, { label: `#${route.taskId}` }];
    case "chat":
      return [{ label: "对话" }, ...(route.projectId ? [{ label: `项目 #${route.projectId}` }] : [])];
    case "notFound":
      return [{ label: "未找到页面" }];
    default:
      return [home];
  }
}

export function Breadcrumbs({ route }: { route: Route }) {
  const crumbs = crumbsFor(route);
  return (
    <nav aria-label="面包屑" className="flex items-center gap-1 text-xs min-w-0">
      <button
        type="button"
        className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-500/80 hover:text-cyan-400 transition-colors shrink-0"
        onClick={() => navigate("/dashboard")}
      >
        CODE SECURITY
      </button>
      {crumbs.map((crumb, index) => (
        <span key={`${crumb.label}-${index}`} className="flex items-center gap-1 min-w-0">
          <ChevronRight className="w-3 h-3 text-[var(--text-faint)] shrink-0" />
          {crumb.href ? (
            <button
              type="button"
              className="truncate text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
              onClick={() => navigate(crumb.href!)}
            >
              {crumb.label}
            </button>
          ) : (
            <span className="truncate text-[var(--text-primary)] font-medium">{crumb.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}
