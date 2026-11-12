import { AlertCircle, X } from "lucide-react";
import { createPortal } from "react-dom";
import type { ReactNode } from "react";

/**
 * Portal modal. Keeping it on document.body is mandatory: the app shell uses
 * backdrop-filter, which would otherwise create a containing block for
 * position:fixed descendants and make the dialog unclickable (silent failure).
 */
export function Modal({
  title,
  description,
  onClose,
  children,
  footer,
  width = "max-w-2xl",
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className={`card flex max-h-[88vh] w-full ${width} flex-col shadow-2xl`}>
        <header className="flex shrink-0 items-start justify-between gap-3 border-b border-surface-border px-4 py-3">
          <div className="min-w-0">
            <h2 className="text-sm font-medium">{title}</h2>
            {description && (
              <p className="mt-1 text-xs text-[var(--text-secondary)]">{description}</p>
            )}
          </div>
          <button type="button" className="btn-ghost" onClick={onClose} aria-label="关闭">
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
        {footer && (
          <footer className="flex shrink-0 items-center justify-end gap-2 border-t border-surface-border px-4 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>,
    document.body,
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="block text-xs font-medium text-[var(--text-secondary)]">{label}</span>
      {children}
      {hint && <span className="block text-[11px] leading-relaxed text-[var(--text-faint)]">{hint}</span>}
    </label>
  );
}

/** Honest "configuration exists, execution does not" banner. */
export function CapabilityNotice({
  title,
  children,
  tone = "amber",
}: {
  title: string;
  children: ReactNode;
  tone?: "amber" | "cyan";
}) {
  const accent =
    tone === "cyan"
      ? "border-cyan-500/25 bg-cyan-500/5 text-cyan-500"
      : "border-amber-500/25 bg-amber-500/5 text-amber-500";
  return (
    <div className={`rounded-lg border px-4 py-3 ${accent}`}>
      <div className="flex items-center gap-2">
        <AlertCircle className="h-4 w-4 shrink-0" />
        <p className="text-sm font-medium text-[var(--text-primary)]">{title}</p>
      </div>
      <div className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)]">{children}</div>
    </div>
  );
}

export function InlineMessage({
  tone,
  children,
}: {
  tone: "success" | "error" | "info";
  children: ReactNode;
}) {
  const cls =
    tone === "success"
      ? "border-emerald-500/25 bg-emerald-500/5 text-emerald-400"
      : tone === "error"
        ? "border-red-500/25 bg-red-500/5 text-red-400"
        : "border-cyan-500/25 bg-cyan-500/5 text-cyan-400";
  return (
    <div className={`rounded-lg border px-3 py-2 text-xs leading-relaxed ${cls}`}>{children}</div>
  );
}
