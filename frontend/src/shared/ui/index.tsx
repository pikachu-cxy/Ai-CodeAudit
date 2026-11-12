import type { ReactNode } from "react";
import { AlertCircle, Inbox, Loader2, type LucideIcon } from "lucide-react";

/* ------------------------------------------------------------------ *
 * Shared design-system primitives. Visual language stays close to the
 * existing `.card` / `.btn-*` classes; this file only adds structure.
 * ------------------------------------------------------------------ */

export type Tone = "default" | "accent" | "success" | "warning" | "danger" | "muted";

const TONE_CLASS: Record<Tone, string> = {
  default: "border-surface-border text-[var(--text-secondary)] bg-[var(--bg-raised)]",
  accent: "border-cyan-500/30 text-cyan-500 bg-cyan-500/10",
  success: "border-emerald-500/30 text-emerald-500 bg-emerald-500/10",
  warning: "border-amber-500/30 text-amber-500 bg-amber-500/10",
  danger: "border-red-500/30 text-red-500 bg-red-500/10",
  muted: "border-surface-border text-[var(--text-muted)] bg-[var(--bg-muted)]",
};

export function StatusPill({
  children,
  tone = "default",
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${TONE_CLASS[tone]}`}
    >
      {children}
    </span>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        {eyebrow && (
          <p className="text-[10px] font-mono uppercase tracking-[0.22em] text-cyan-500/80">
            {eyebrow}
          </p>
        )}
        <h1 className="text-xl font-semibold tracking-tight mt-1">{title}</h1>
        {description && (
          <p className="text-sm text-[var(--text-secondary)] mt-1.5 max-w-3xl">{description}</p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 shrink-0">{actions}</div>}
    </header>
  );
}

export function SectionCard({
  title,
  description,
  actions,
  children,
  className = "",
  bodyClassName = "",
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`card flex min-h-0 flex-col ${className}`}>
      {(title || actions) && (
        <div className="flex items-start justify-between gap-3 border-b border-surface-border px-4 py-3 shrink-0">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-medium">{title}</h2>}
            {description && (
              <p className="text-xs text-[var(--text-secondary)] mt-1">{description}</p>
            )}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </div>
      )}
      <div className={`min-h-0 flex-1 p-4 ${bodyClassName}`}>{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = "accent",
  loading = false,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: LucideIcon;
  tone?: Tone;
  loading?: boolean;
}) {
  return (
    <div className="card px-4 py-3.5 flex items-start justify-between gap-3">
      <div className="min-w-0">
        <p className="text-[11px] uppercase tracking-wider text-[var(--text-muted)] font-mono">
          {label}
        </p>
        <p className="text-2xl font-semibold tabular-nums mt-1.5">
          {loading ? <span className="inline-block h-7 w-14 rounded bg-[var(--bg-raised)] animate-pulse" /> : value}
        </p>
        {hint && <p className="text-[11px] text-[var(--text-muted)] mt-1 truncate">{hint}</p>}
      </div>
      {Icon && (
        <span className={`rounded-lg border p-2 shrink-0 ${TONE_CLASS[tone]}`}>
          <Icon className="w-4 h-4" />
        </span>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
}: {
  title: string;
  description?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-surface-border px-6 py-10 text-center">
      <Icon className="w-7 h-7 text-[var(--text-faint)]" />
      <p className="text-sm font-medium mt-1">{title}</p>
      {description && (
        <p className="text-xs text-[var(--text-secondary)] max-w-md leading-relaxed">{description}</p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function LoadingState({ label = "正在加载…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-sm text-[var(--text-secondary)]">
      <Loader2 className="w-4 h-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-red-500/25 bg-red-500/5 px-6 py-8 text-center">
      <AlertCircle className="w-6 h-6 text-red-400" />
      <p className="text-sm font-medium">加载失败</p>
      <p className="text-xs text-[var(--text-secondary)] max-w-lg break-words">{message}</p>
      {onRetry && (
        <button type="button" className="btn-action mt-2" onClick={onRetry}>
          重试
        </button>
      )}
    </div>
  );
}

/**
 * Explicit "not implemented" notice for platform modules without backend.
 * Never renders a clickable save/connect/execute control.
 */
export function PlaceholderNotice({
  title = "暂未开放",
  description,
  planned = [],
}: {
  title?: string;
  description: string;
  planned?: string[];
}) {
  return (
    <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 px-4 py-3.5">
      <div className="flex items-center gap-2">
        <AlertCircle className="w-4 h-4 text-amber-500 shrink-0" />
        <p className="text-sm font-medium">{title}</p>
        <StatusPill tone="muted">UI 预留</StatusPill>
      </div>
      <p className="text-xs text-[var(--text-secondary)] mt-2 leading-relaxed">{description}</p>
      {planned.length > 0 && (
        <ul className="mt-3 grid gap-1.5 sm:grid-cols-2 text-xs text-[var(--text-muted)]">
          {planned.map((item) => (
            <li key={item} className="flex items-start gap-1.5">
              <span className="text-amber-500 mt-0.5">·</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function KeyValueRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5 text-sm">
      <span className="text-[var(--text-secondary)] shrink-0">{label}</span>
      <span className="text-right min-w-0 break-words">{children}</span>
    </div>
  );
}

export function MonoMeta({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[11px] text-[var(--text-muted)]">{children}</span>;
}
