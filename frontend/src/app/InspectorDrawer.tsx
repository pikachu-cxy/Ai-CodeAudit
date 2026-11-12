import { X } from "lucide-react";
import type { ReactNode } from "react";

export interface InspectorConfig {
  title: string;
  subtitle?: string;
  content: ReactNode;
}

/**
 * Optional right-hand panel. It is NOT part of the fixed AppShell structure:
 * a page registers it through `useInspector()` only when it has something
 * meaningful to show.
 */
export function InspectorDrawer({
  config,
  open,
  onClose,
}: {
  config: InspectorConfig;
  open: boolean;
  onClose: () => void;
}) {
  if (!open) return null;
  return (
    <aside
      className="app-inspector flex w-[320px] shrink-0 flex-col border-l border-surface-border bg-[var(--bg-panel)]"
      aria-label={config.title}
    >
      <div className="flex items-center justify-between gap-2 border-b border-surface-border px-4 py-3 shrink-0">
        <div className="min-w-0">
          <p className="text-[10px] font-mono uppercase tracking-[0.18em] text-cyan-500/80">
            Inspector
          </p>
          <h2 className="truncate text-sm font-medium mt-0.5">{config.title}</h2>
          {config.subtitle && (
            <p className="truncate text-[11px] text-[var(--text-muted)] mt-0.5">
              {config.subtitle}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1 text-[var(--text-muted)] hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/40"
          aria-label="关闭详情面板"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto app-nav-scroll p-4">{config.content}</div>
    </aside>
  );
}
