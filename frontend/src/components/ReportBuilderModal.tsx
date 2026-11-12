import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Loader2, X } from "lucide-react";
import type {
  ReportFilters,
  ReportFormat,
  ReportGroupBy,
  ReportInclude,
  ReportPreview,
  ReportSort,
  ReportSpec,
} from "../api";
import { api } from "../api";

export type ReportScope = "all" | "selected" | "filtered";

/** 列表页当前筛选条件的快照，用于「按当前筛选」导出。 */
export interface ReportFilterDraft {
  category?: string;
  severity?: string;
  verdict?: string;
  review?: string;
  external?: string;
  tool?: string;
  owasp?: string;
  subtype?: string;
  keyword?: string;
}

const PREF_KEY = "ai-audit:report-prefs";

const DEFAULT_INCLUDE: ReportInclude = {
  snippet: true,
  ai_reason: true,
  remediation: true,
  retest: true,
  poc: false,
  false_positive: true,
};

const DEFAULT_GROUP: ReportGroupBy = "severity";
const DEFAULT_SORT: ReportSort = "severity";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

const INCLUDE_ITEMS: { key: keyof ReportInclude; label: string; hint: string }[] = [
  { key: "snippet", label: "代码片段", hint: "附上命中的源码上下文" },
  { key: "ai_reason", label: "AI 研判理由", hint: "AI 判定为真实漏洞/误报的依据" },
  { key: "remediation", label: "修复建议", hint: "LLM 给出的修复方向" },
  { key: "retest", label: "复测结论", hint: "最近一次复测是否仍然存在" },
  { key: "poc", label: "验证 PoC", hint: "可复现的验证步骤与请求（敏感，请谨慎分发）" },
  { key: "false_positive", label: "包含误报条目", hint: "取消勾选会从报告中剔除误报" },
];

export function draftToFilters(draft: ReportFilterDraft): ReportFilters {
  const filters: ReportFilters = {};
  const one = (v?: string) => {
    const t = (v || "").trim();
    return t ? [t] : undefined;
  };
  const severity = one(draft.severity);
  if (severity) filters.severity = severity;
  const verdict = one(draft.verdict);
  if (verdict) filters.ai_verdict = verdict;
  const review = one(draft.review);
  if (review) filters.review_status = review;
  const external = one(draft.external);
  if (external) filters.external_status = external;
  const tool = one(draft.tool);
  if (tool) filters.tool = tool;
  const owasp = one(draft.owasp);
  if (owasp) filters.owasp = owasp;
  const subtype = one(draft.subtype);
  if (subtype) filters.subtype = subtype;
  const keyword = (draft.keyword || "").trim();
  if (keyword) filters.keyword = keyword;
  if (draft.category && draft.category !== "all") filters.category = [draft.category];
  return filters;
}

export function countDraftFilters(draft: ReportFilterDraft): number {
  const f = draftToFilters(draft);
  return Object.keys(f).length;
}

export function describeDraftFilters(draft: ReportFilterDraft): string[] {
  const f = draftToFilters(draft);
  const parts: string[] = [];
  if (f.category) parts.push(`分类=${f.category[0]}`);
  if (f.severity) parts.push(`危害=${f.severity[0]}`);
  if (f.ai_verdict) parts.push(`AI判定=${f.ai_verdict[0]}`);
  if (f.review_status) parts.push(`人工标记=${f.review_status[0]}`);
  if (f.external_status) parts.push(`外部复核=${f.external_status[0]}`);
  if (f.tool) parts.push(`工具=${f.tool[0]}`);
  if (f.owasp) parts.push(`OWASP=${f.owasp[0]}`);
  if (f.subtype) parts.push(`子类型=${f.subtype[0]}`);
  if (f.keyword) parts.push(`关键词=${f.keyword}`);
  return parts;
}

function loadPrefs(): { include: ReportInclude; group_by: ReportGroupBy; sort: ReportSort } | null {
  try {
    const raw = window.localStorage.getItem(PREF_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<ReportInclude> & {
      group_by?: ReportGroupBy;
      sort?: ReportSort;
    };
    const include: ReportInclude = { ...DEFAULT_INCLUDE };
    (Object.keys(DEFAULT_INCLUDE) as (keyof ReportInclude)[]).forEach((k) => {
      if (typeof parsed[k] === "boolean") include[k] = parsed[k] as boolean;
    });
    return {
      include,
      group_by: parsed.group_by || DEFAULT_GROUP,
      sort: parsed.sort || DEFAULT_SORT,
    };
  } catch {
    return null;
  }
}

function savePrefs(include: ReportInclude, groupBy: ReportGroupBy, sort: ReportSort) {
  try {
    window.localStorage.setItem(
      PREF_KEY,
      JSON.stringify({ ...include, group_by: groupBy, sort: sort })
    );
  } catch {
    /* localStorage 不可用时静默忽略 */
  }
}

interface Props {
  open: boolean;
  scanId: number;
  projectName?: string | null;
  scanName?: string | null;
  scanTotal: number;
  selectedIds: number[];
  filterDraft: ReportFilterDraft;
  onClose: () => void;
}

export function ReportBuilderModal({
  open,
  scanId,
  projectName,
  scanName,
  scanTotal,
  selectedIds,
  filterDraft,
  onClose,
}: Props) {
  const [scope, setScope] = useState<ReportScope>("all");
  const [title, setTitle] = useState("");
  const [include, setInclude] = useState<ReportInclude>(DEFAULT_INCLUDE);
  const [groupBy, setGroupBy] = useState<ReportGroupBy>(DEFAULT_GROUP);
  const [sort, setSort] = useState<ReportSort>(DEFAULT_SORT);
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<ReportFormat | "">("");
  const previewSeq = useRef(0);

  const filterCount = countDraftFilters(filterDraft);
  const filterChips = useMemo(() => describeDraftFilters(filterDraft), [filterDraft]);
  const defaultTitle = `${projectName || scanName || "项目"} 安全审计报告`;

  useEffect(() => {
    if (!open) return;
    const prefs = loadPrefs();
    if (prefs) {
      setInclude(prefs.include);
      setGroupBy(prefs.group_by);
      setSort(prefs.sort);
    } else {
      setInclude(DEFAULT_INCLUDE);
      setGroupBy(DEFAULT_GROUP);
      setSort(DEFAULT_SORT);
    }
    setTitle(defaultTitle);
    setScope(selectedIds.length > 0 ? "selected" : "all");
    setError(null);
    setBusy("");
    // 仅在打开时初始化，避免依赖变化重置用户已做的选择
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Esc 关闭。放在 `if (!open) return null` 之前，保证 Hook 顺序稳定。
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const buildSpec = useCallback((): ReportSpec => {
    const spec: ReportSpec = {
      include,
      group_by: groupBy,
      sort,
    };
    const trimmed = title.trim();
    if (trimmed && trimmed !== defaultTitle) spec.title = trimmed;
    if (scope === "selected") {
      spec.finding_ids = selectedIds;
    } else if (scope === "filtered") {
      spec.filters = draftToFilters(filterDraft);
    }
    return spec;
  }, [include, groupBy, sort, title, defaultTitle, scope, selectedIds, filterDraft]);

  // 实时预览：范围/内容变化后防抖刷新，让用户看到最终条数
  useEffect(() => {
    if (!open) return;
    if (scope === "selected" && selectedIds.length === 0) {
      setPreview(null);
      return;
    }
    const seq = ++previewSeq.current;
    setPreviewLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const data = await api.previewScanReport(scanId, buildSpec());
        if (seq === previewSeq.current) {
          setPreview(data);
          setError(null);
        }
      } catch (e) {
        if (seq === previewSeq.current) {
          setPreview(null);
          setError(String(e));
        }
      } finally {
        if (seq === previewSeq.current) setPreviewLoading(false);
      }
    }, 320);
    return () => window.clearTimeout(timer);
  }, [open, scanId, scope, selectedIds, buildSpec]);

  const persist = useCallback(() => {
    savePrefs(include, groupBy, sort);
  }, [include, groupBy, sort]);

  const run = useCallback(
    async (format: ReportFormat) => {
      setBusy(format);
      setError(null);
      persist();
      try {
        const spec = buildSpec();
        if (format === "html") await api.openScanReportWithSpec(scanId, spec);
        else if (format === "html-download") await api.downloadScanReportHtmlWithSpec(scanId, spec);
        else if (format === "pdf") await api.downloadScanReportPdfWithSpec(scanId, spec);
        else if (format === "md") await api.downloadScanReportMarkdownWithSpec(scanId, spec);
        else await api.downloadScanReportJsonWithSpec(scanId, spec);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy("");
      }
    },
    [buildSpec, scanId, persist]
  );

  if (!open) return null;

  const total = preview?.total ?? null;
  const pdfLimit = preview?.pdf_max_findings ?? 2000;
  const pdfBlocked = total != null && total > pdfLimit;
  const canRun = total != null && total > 0 && !busy;

  const sevText = preview
    ? SEV_ORDER.filter((k) => (preview.by_severity[k] ?? 0) > 0)
        .map((k) => `${k} ${preview.by_severity[k]}`)
        .join(" · ") || "无"
    : "—";

  // 必须 portal 到 document.body：`AuditReportHeader` 的 `.audit-panel` 带
  // `backdrop-blur-sm`（backdrop-filter 会为 fixed 后代创建包含块），
  // 若原地渲染，`fixed inset-0` 会相对 header 定位并被外层 <main> 的
  // `overflow-auto` 裁切 —— 表现就是弹窗露不全、按钮点不到、无法滚动。
  return createPortal(
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="生成漏洞报告"
      onMouseDown={(e) => {
        // 仅点击遮罩本身（而非弹窗内部）才关闭，且生成中不允许关闭
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div className="card flex max-h-[88vh] w-full max-w-3xl flex-col shadow-2xl">
        {/* 头部：固定，不随内容滚动 */}
        <div className="flex shrink-0 items-start justify-between gap-3 p-5 pb-3">
          <div>
            <h3 className="text-lg font-semibold text-white">生成漏洞报告</h3>
            <p className="text-xs text-slate-500 mt-1">
              自定义选择漏洞范围与报告内容。范围默认取列表页已勾选的条目。
            </p>
          </div>
          <button
            type="button"
            className="p-1.5 rounded text-slate-500 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
            onClick={onClose}
            disabled={!!busy}
            title="关闭（Esc）"
            aria-label="关闭"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* 中部：唯一可滚动区域 */}
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain px-5 py-1">
          <section className="space-y-2">
            <p className="text-xs uppercase tracking-wider text-slate-500">1. 报告范围</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <ScopeCard
                active={scope === "all"}
                label="全部漏洞"
                detail={`${scanTotal} 条`}
                onClick={() => setScope("all")}
              />
              <ScopeCard
                active={scope === "selected"}
                label="仅已勾选"
                detail={selectedIds.length > 0 ? `${selectedIds.length} 条` : "尚未勾选"}
                disabled={selectedIds.length === 0}
                onClick={() => setScope("selected")}
              />
              <ScopeCard
                active={scope === "filtered"}
                label="按当前筛选"
                detail={filterCount > 0 ? `${filterCount} 项条件` : "列表未设筛选"}
                disabled={filterCount === 0}
                onClick={() => setScope("filtered")}
              />
            </div>
            {scope === "filtered" && filterChips.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {filterChips.map((c) => (
                  <span
                    key={c}
                    className="text-[11px] px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 font-mono"
                  >
                    {c}
                  </span>
                ))}
              </div>
            )}
          </section>

          <section className="space-y-2">
            <p className="text-xs uppercase tracking-wider text-slate-500">2. 报告内容</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2">
              {INCLUDE_ITEMS.map((item) => (
                <label
                  key={item.key}
                  className="flex items-start gap-2 text-sm text-slate-300 cursor-pointer"
                  title={item.hint}
                >
                  <input
                    type="checkbox"
                    className="mt-1 accent-cyan-500"
                    checked={include[item.key]}
                    onChange={(e) =>
                      setInclude((prev) => ({ ...prev, [item.key]: e.target.checked }))
                    }
                  />
                  <span>
                    {item.label}
                    <span className="block text-[11px] text-slate-600">{item.hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </section>

          <section className="space-y-2">
            <p className="text-xs uppercase tracking-wider text-slate-500">3. 版式</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label className="text-xs text-slate-500 sm:col-span-3">
                报告标题
                <input
                  className="input mt-1"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder={defaultTitle}
                />
              </label>
              <label className="text-xs text-slate-500">
                分组方式
                <select
                  className="input mt-1"
                  value={groupBy}
                  onChange={(e) => setGroupBy(e.target.value as ReportGroupBy)}
                >
                  <option value="severity">按危害级别</option>
                  <option value="owasp">按 OWASP 类型</option>
                  <option value="file">按文件</option>
                  <option value="tool">按扫描器</option>
                  <option value="none">不分组</option>
                </select>
              </label>
              <label className="text-xs text-slate-500">
                排序
                <select
                  className="input mt-1"
                  value={sort}
                  onChange={(e) => setSort(e.target.value as ReportSort)}
                >
                  <option value="severity">危害级别优先</option>
                  <option value="file">文件路径</option>
                  <option value="owasp">OWASP 类型</option>
                  <option value="id">漏洞 ID</option>
                </select>
              </label>
            </div>
          </section>

          <section className="rounded-lg border border-cyan-500/15 bg-black/20 px-4 py-3 space-y-1">
            <div className="flex items-center gap-2 text-sm">
              {previewLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                  <span className="text-slate-400">正在计算范围…</span>
                </>
              ) : (
                <span className="text-slate-300">
                  将包含{" "}
                  <span className="text-white font-semibold">{total ?? "—"}</span> 条
                  {preview && preview.scan_total !== total && (
                    <span className="text-slate-500">（全量 {preview.scan_total} 条）</span>
                  )}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 font-mono">{sevText}</p>
            {pdfBlocked && (
              <p className="text-xs text-amber-300">
                超过 PDF 导出上限 {pdfLimit} 条，请缩小范围或改用 HTML / Markdown。
              </p>
            )}
          </section>

          {error && <p className="text-xs text-danger break-all">{error}</p>}
        </div>

        {/* 底部操作区：固定，不随内容滚动 */}
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-2 border-t border-cyan-500/10 p-5 pt-3">
          <button type="button" className="btn-ghost" onClick={onClose} disabled={!!busy}>
            取消
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={!canRun}
            onClick={() => run("md")}
          >
            {busy === "md" ? "生成中..." : "Markdown"}
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={!canRun}
            onClick={() => run("json")}
          >
            {busy === "json" ? "生成中..." : "JSON"}
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={!canRun}
            onClick={() => run("html")}
          >
            {busy === "html" ? "生成中..." : "预览 HTML"}
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={!canRun}
            onClick={() => run("html-download")}
          >
            {busy === "html-download" ? "生成中..." : "下载 HTML"}
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={!canRun || pdfBlocked}
            onClick={() => run("pdf")}
          >
            {busy === "pdf" ? "生成中..." : "下载 PDF"}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}

function ScopeCard({
  active,
  label,
  detail,
  disabled,
  onClick,
}: {
  active: boolean;
  label: string;
  detail: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`text-left rounded-lg border px-3 py-2 transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
        active
          ? "border-cyan-500/50 bg-cyan-500/10"
          : "border-surface-border/80 bg-black/25 hover:border-cyan-500/30"
      }`}
    >
      <p className={`text-sm font-medium ${active ? "text-cyan-300" : "text-slate-300"}`}>{label}</p>
      <p className="text-[11px] text-slate-500 mt-0.5">{detail}</p>
    </button>
  );
}
