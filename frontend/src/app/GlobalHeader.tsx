import { PanelRightClose, PanelRightOpen, RefreshCw } from "lucide-react";
import { Breadcrumbs } from "./Breadcrumbs";
import { navItemForPath } from "./navigation";
import type { Route } from "./router";

interface Props {
  route: Route;
  hasInspector: boolean;
  inspectorOpen: boolean;
  onToggleInspector: () => void;
  onRefresh: () => void;
}

export function GlobalHeader({
  route,
  hasInspector,
  inspectorOpen,
  onToggleInspector,
  onRefresh,
}: Props) {
  const item = navItemForPath(window.location.pathname);

  return (
    <header className="app-header flex h-14 shrink-0 items-center justify-between gap-3 border-b border-surface-border bg-[var(--bg-panel)] px-5">
      <div className="min-w-0 flex flex-col gap-0.5">
        <Breadcrumbs route={route} />
        <p className="text-[10px] text-[var(--text-faint)] truncate">
          {item?.description ?? "AI 代码安全审计平台"}
        </p>
      </div>
      <div className="flex items-center gap-1 shrink-0">
        <button
          type="button"
          onClick={onRefresh}
          className="rounded-md p-2 text-[var(--text-secondary)] hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40"
          title="刷新当前页面数据"
          aria-label="刷新当前页面数据"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
        {hasInspector && (
          <button
            type="button"
            onClick={onToggleInspector}
            className={`rounded-md p-2 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40 ${
              inspectorOpen
                ? "text-cyan-500 bg-cyan-500/10"
                : "text-[var(--text-secondary)] hover:bg-[var(--hover-overlay)]"
            }`}
            title={inspectorOpen ? "收起详情面板" : "展开详情面板"}
            aria-label={inspectorOpen ? "收起详情面板" : "展开详情面板"}
          >
            {inspectorOpen ? (
              <PanelRightClose className="h-4 w-4" />
            ) : (
              <PanelRightOpen className="h-4 w-4" />
            )}
          </button>
        )}
      </div>
    </header>
  );
}
