import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Shield } from "lucide-react";
import { ThemeToggle } from "../components/ThemeToggle";
import { BuildVersion } from "../components/BuildVersion";
import { LogOut } from "lucide-react";
import { NAV_GROUPS, type NavItem, visibleNavItems } from "./navigation";

interface Props {
  currentPath: string;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  username: string;
  isAdmin: boolean;
  onLogout: () => void;
  onNavigate: (path: string) => void;
}

const NARROW_BREAKPOINT = 1180;

export function Sidebar({
  currentPath,
  collapsed,
  onToggleCollapsed,
  username,
  isAdmin,
  onLogout,
  onNavigate,
}: Props) {
  const [narrow, setNarrow] = useState(() => window.innerWidth < NARROW_BREAKPOINT);

  useEffect(() => {
    const onResize = () => setNarrow(window.innerWidth < NARROW_BREAKPOINT);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Narrow viewports force the compact rail so content never gets clipped.
  const compact = collapsed || narrow;
  const items = visibleNavItems();

  const isActive = (item: NavItem) => {
    const root = `/${currentPath.split("/").filter(Boolean)[0] || "dashboard"}`;
    return item.route === root;
  };

  return (
    <aside
      className={`app-sidebar sidebar-shell flex flex-col shrink-0 border-r transition-[width] duration-200 ${
        compact ? "w-[68px]" : "w-[240px]"
      }`}
      aria-label="全局导航"
    >
      <div
        className={`flex items-center gap-2 border-b border-surface-border shrink-0 ${
          compact ? "justify-center px-2 py-4" : "justify-between px-4 py-4"
        }`}
      >
        <button
          type="button"
          onClick={() => onNavigate("/dashboard")}
          className="flex items-center gap-2 min-w-0 text-left"
          title="CODE SECURITY // AUDIT"
        >
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-500">
            <Shield className="h-4 w-4" />
          </span>
          {!compact && (
            <span className="min-w-0">
              <span className="block text-[9px] font-mono uppercase tracking-[0.2em] text-cyan-500/80">
                Code Security
              </span>
              <span className="block text-sm font-bold tracking-tight leading-tight">// AUDIT</span>
            </span>
          )}
        </button>
        {!compact && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            className="rounded-md p-1.5 text-[var(--text-muted)] hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40"
            title="折叠侧边栏"
            aria-label="折叠侧边栏"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Platform config scrolls independently; user block is pinned at bottom. */}
      <nav className="flex-1 min-h-0 overflow-y-auto app-nav-scroll px-2 py-3">
        {NAV_GROUPS.map((group) => {
          const groupItems = items.filter((item) => item.group === group.id);
          if (groupItems.length === 0) return null;
          return (
            <div key={group.id} className="mb-4">
              {!compact && (
                <p className="px-2 pb-1.5 text-[10px] font-mono uppercase tracking-[0.18em] text-[var(--text-faint)]">
                  {group.label}
                </p>
              )}
              <div className="space-y-0.5">
                {groupItems.map((item) => {
                  const Icon = item.icon;
                  const active = isActive(item);
                  return (
                    <button
                      key={item.key}
                      type="button"
                      title={compact ? `${item.label} — ${item.description}` : item.description}
                      onClick={() => onNavigate(item.route)}
                      className={`group flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40 ${
                        compact ? "justify-center" : ""
                      } ${
                        active
                          ? "bg-cyan-500/15 text-cyan-500 font-medium border border-cyan-500/25"
                          : "border border-transparent text-[var(--text-secondary)] hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)]"
                      }`}
                      aria-current={active ? "page" : undefined}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      {!compact && <span className="truncate">{item.label}</span>}
                      {!compact && item.maturity === "skeleton" && (
                        <span className="ml-auto text-[9px] font-mono text-[var(--text-faint)]">预留</span>
                      )}
                      {!compact && item.maturity === "config-only" && (
                        <span className="ml-auto text-[9px] font-mono text-[var(--text-faint)]" title="具备真实配置管理，执行能力未接入">配置</span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      <div className={`shrink-0 border-t border-surface-border ${compact ? "px-2 py-3" : "px-3 py-3"}`}>
        {compact ? (
          <button
            type="button"
            onClick={onToggleCollapsed}
            className="mx-auto mb-2 flex h-8 w-8 items-center justify-center rounded-md text-[var(--text-muted)] hover:bg-[var(--hover-overlay)] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40"
            title="展开侧边栏"
            aria-label="展开侧边栏"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        ) : (
          <div className="mb-2 rounded-lg border border-surface-border bg-[var(--bg-muted)] px-3 py-2">
            <p className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-faint)]">
              Signed in
            </p>
            <p className="truncate text-sm font-medium mt-0.5" title={username}>
              {username || "—"}
            </p>
            <p className="text-[10px] text-[var(--text-muted)] mt-0.5">
              {isAdmin ? "管理员" : "成员"}
            </p>
          </div>
        )}
        <div className={`flex items-center ${compact ? "flex-col gap-1" : "gap-1"}`}>
          <ThemeToggle className="shrink-0" />
          <button
            type="button"
            onClick={onLogout}
            className={`flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--hover-overlay)] hover:text-red-400 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40 ${
              compact ? "justify-center" : "flex-1"
            }`}
            title="退出登录"
          >
            <LogOut className="h-3.5 w-3.5" />
            {!compact && <span>退出登录</span>}
          </button>
        </div>
        {!compact && <BuildVersion />}
      </div>
    </aside>
  );
}
