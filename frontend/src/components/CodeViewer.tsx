import { useEffect, useMemo, useRef } from "react";

interface Props {
  content: string;
  windowStart: number;
  highlightStart: number;
  highlightEnd: number;
  scrollToLine?: number | null;
  scrollKey?: number;
  fileLabel?: string;
}

export function CodeViewer({
  content,
  windowStart,
  highlightStart,
  highlightEnd,
  scrollToLine,
  scrollKey = 0,
  fileLabel,
}: Props) {
  const lines = useMemo(() => content.split("\n"), [content]);
  const lineRefs = useRef<Map<number, HTMLDivElement>>(new Map());

  useEffect(() => {
    if (!scrollToLine) return;
    const el = lineRefs.current.get(scrollToLine);
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [scrollToLine, scrollKey, content]);

  return (
    <div className="rounded-xl border border-surface-border overflow-hidden bg-[#0d1117]">
      {fileLabel && (
        <div className="px-4 py-2 text-xs font-mono text-slate-400 border-b border-surface-border bg-surface">
          {fileLabel}
        </div>
      )}
      <div className="max-h-[520px] overflow-auto text-xs font-mono">
        {lines.map((line, idx) => {
          const lineNo = windowStart + idx;
          const inHighlight = lineNo >= highlightStart && lineNo <= highlightEnd;
          const isFocus = scrollToLine === lineNo;
          return (
            <div
              key={lineNo}
              ref={(el) => {
                if (el) lineRefs.current.set(lineNo, el);
                else lineRefs.current.delete(lineNo);
              }}
              className={`flex min-w-full ${
                isFocus
                  ? "bg-accent/25 ring-1 ring-inset ring-accent/50"
                  : inHighlight
                    ? "bg-slate-200/10"
                    : "hover:bg-white/[0.02]"
              }`}
            >
              <span
                className={`select-none w-12 shrink-0 text-right pr-3 py-0.5 border-r border-surface-border/50 ${
                  inHighlight || isFocus ? "text-slate-200" : "text-slate-600"
                }`}
              >
                {lineNo}
              </span>
              <pre className="flex-1 px-3 py-0.5 whitespace-pre-wrap break-all text-slate-200">
                {line || " "}
              </pre>
            </div>
          );
        })}
      </div>
    </div>
  );
}
