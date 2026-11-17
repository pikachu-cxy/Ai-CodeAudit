import { useEffect, useMemo, useRef, useState } from "react";
import { api, type AuditGraph, type AuditGraphNode } from "../api";
import { useAsyncData } from "../shared/hooks/useAsyncData";
import { CodeViewer } from "./CodeViewer";

const labels: Record<string, string> = {
  project: "项目", module: "模块", endpoint: "接口", handler: "处理器",
  planner: "计划", task: "调查任务", fact: "事实", evidence: "证据", finding: "发现",
  running: "运行中", pending: "排队中", failed: "异常", completed: "完成",
  interrupted: "中断", skipped: "沿用此前结果", uncovered: "未覆盖", unknown: "未知覆盖",
  covered: "已调查", incomplete: "未完成 / 未覆盖", unplanned: "未安排",
  deterministic: "规则调查", deterministic_verified: "已用规则核查",
  deterministic_uncovered: "规则未覆盖", candidate: "候选", confirmed: "已人工确认",
  reused: "沿用已核查结果", audited_no_candidates: "已审计，零候选", invalid_output: "模型输出异常",
  fallback_error: "模型异常，规则回退", fallback_timeout: "模型超时，规则回退",
  budget_exhausted: "预算耗尽", exception: "任务异常", source_changed: "源码版本变化",
};
const translated = (value: unknown) => labels[String(value)] ?? String(value ?? "—");
const text = (node: AuditGraphNode, key: string) => String(node.data[key] ?? "");

export type GraphDestination = { runId: number; taskId?: number; assetId?: string; assetGraphId?: number };

function GraphView({ graph, mode, selected, onSelect, expanded }: {
  graph: AuditGraph; mode: "asset" | "audit"; selected?: string; onSelect: (id: string) => void; expanded?: string;
}) {
  const [zoom, setZoom] = useState(1);
  const viewport = useRef<HTMLDivElement>(null);
  const layout = useMemo(() => {
    const incoming = new Map<string, string[]>();
    for (const edge of graph.edges) {
      if (edge.type !== "references") incoming.set(edge.target, [...(incoming.get(edge.target) ?? []), edge.source]);
    }
    const order = mode === "asset" ? ["project", "module", "endpoint", "handler"] : ["planner", "task", "fact", "evidence", "finding"];
    const featured = new Set(graph.nodes.filter(node => node.type === "endpoint").slice(0, 30).map(node => node.id));
    const selectedNode = graph.nodes.find(node => node.id === selected);
    const moduleId = selectedNode?.type === "module" ? selected : selectedNode?.data.module_id;
    const visible = graph.nodes.filter(node => mode === "asset"
      ? node.type === "handler" ? incoming.get(node.id)?.includes(expanded ?? "") || node.id === selected
        : node.type !== "endpoint" || featured.has(node.id) || node.id === selected || text(node, "module_id") === moduleId
      : ["planner", "task", "finding"].includes(node.type) || (
        node.id === selected || (node.type === "fact"
          ? incoming.get(node.id)?.includes(expanded ?? "") || graph.edges.some(e => e.source === expanded && e.target === node.id)
          : incoming.get(node.id)?.includes(selected ?? "") || incoming.get(node.id)?.some(id =>
            incoming.get(id)?.includes(expanded ?? "") || graph.edges.some(e => e.source === expanded && e.target === id))
        )));
    const points = new Map<string, { x: number; y: number }>();
    let height = 180;
    for (let depth = 0; depth < order.length; depth++) {
      const column = visible.filter(n => n.type === order[depth]);
      if (mode === "asset" && depth >= 2) column.sort((a, b) => text(a, "file").localeCompare(text(b, "file")) || a.label.localeCompare(b.label));
      const occupied = new Set<number>();
      for (const node of column) {
        const parent = (incoming.get(node.id) ?? []).map(id => points.get(id)).find(Boolean);
        let row = parent ? Math.round((parent.y - 24) / 82) : 0;
        while (occupied.has(row)) row++;
        occupied.add(row);
        points.set(node.id, { x: 22 + depth * 248, y: 24 + row * 82 });
        height = Math.max(height, 110 + row * 82);
      }
    }
    return { points, visible, height, width: 24 + order.length * 248 };
  }, [graph, mode, expanded, selected]);

  useEffect(() => {
    const container = viewport.current;
    if (selected && container) {
      const node = Array.from(container.querySelectorAll<HTMLButtonElement>("button[data-node]"))
        .find(button => button.dataset.node === selected);
      if (!node) return;
      const a = node.getBoundingClientRect();
      const b = container.getBoundingClientRect();
      if (a.left < b.left || a.right > b.right) container.scrollLeft += a.left - b.left - 18;
      if (a.top < b.top || a.bottom > b.bottom) container.scrollTop += a.top - b.top - 18;
    }
  }, [selected]);

  return <div className="rounded-xl border border-surface-border overflow-hidden">
    <div className="flex flex-wrap items-center gap-2 p-2 border-b border-surface-border">
      <button className="btn-action" aria-label="缩小" onClick={() => setZoom(z => Math.max(.5, z - .15))}>−</button>
      <button className="btn-action" aria-label="重置缩放" onClick={() => setZoom(1)}>{Math.round(zoom * 100)}%</button>
      <button className="btn-action" aria-label="放大" onClick={() => setZoom(z => Math.min(1.75, z + .15))}>+</button>
      <span className="text-xs text-slate-500">{mode === "asset" ? "实线：有定位依据 · 虚线：目录归类 · 选择模块或接口展开邻居" : "选择任务展开关联事实和证据"}</span>
    </div>
    <div ref={viewport} tabIndex={0} aria-label={mode === "asset" ? "资产图画布" : "审计图画布"} className="overflow-auto max-h-[440px]">
      <div className="relative" style={{ width: layout.width * zoom, height: layout.height * zoom }}>
        <div className="absolute left-0 top-0" style={{ width: layout.width, height: layout.height, transformOrigin: "top left", transform: `scale(${zoom})` }}>
          <svg className="absolute inset-0 pointer-events-none" width={layout.width} height={layout.height} aria-hidden="true">
            {graph.edges.map(edge => {
              const a = layout.points.get(edge.source), b = layout.points.get(edge.target);
              if (!a || !b) return null;
              const start = a.x + 206, end = b.x, mid = (start + end) / 2;
              return <path key={edge.id} d={`M${start} ${a.y + 30} C${mid} ${a.y + 30},${mid} ${b.y + 30},${end} ${b.y + 30}`}
                fill="none" stroke={edge.source === selected || edge.target === selected ? "#06b6d4" : "#8495aa"}
                strokeWidth="1.5" strokeDasharray={edge.verified && edge.type !== "references" ? undefined : "5 5"} />;
            })}
          </svg>
          {layout.visible.map(node => {
            const point = layout.points.get(node.id)!;
            const overlay = graph.overlay?.[node.id];
            const state = node.type === "endpoint" || node.type === "module"
              ? overlay?.some(t => t.status === "running") ? "running"
                : ["incomplete", "confirmed", "candidate", "reused", "deterministic", "audited_no_candidates"].find(s => overlay?.some(t => t.coverage === s)) ?? (graph.run_id ? "unplanned" : "")
              : text(node, node.type === "finding" ? "review_status" : "status");
            return <button key={node.id} data-node={node.id} data-state={state} aria-pressed={selected === node.id}
              className={`absolute h-[62px] w-[206px] rounded-lg border px-3 text-left shadow-sm transition-colors ${selected === node.id ? "border-cyan-500 bg-surface" : state === "running" ? "border-cyan-500/60 bg-surface" : "border-surface-border bg-surface hover:border-slate-400"}`}
              style={{ left: point.x, top: point.y }} onClick={() => onSelect(node.id)} title={node.label}>
              <span className="block truncate text-[11px] text-slate-500">{translated(node.type)}{state ? ` · ${translated(state)}` : ""}{node.type === "task" ? ` · ${text(node, "agent_id")}` : ""}</span>
              <span className="block truncate text-sm font-semibold">{node.label}</span>
            </button>;
          })}
        </div>
      </div>
    </div>
  </div>;
}

export function AssetGraphPanel({ scanId, destination, onTask }: {
  scanId: number; destination?: GraphDestination; onTask: (target: GraphDestination) => void;
}) {
  const [runId, setRunId] = useState(destination?.runId ?? 0);
  const [selected, setSelected] = useState<string | undefined>(destination?.assetId);
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [buildError, setBuildError] = useState("");
  const runs = useAsyncData(() => api.deepAuditRuns(scanId), [scanId, tick]);
  useEffect(() => {
    if (!runs.data?.runs.some(run => run.id === runId && run.is_active)) return;
    const timer = window.setInterval(() => setTick(n => n + 1), 3000);
    return () => window.clearInterval(timer);
  }, [runId, runs.data]);
  const query = useAsyncData(() => api.assetGraph(scanId, runId || undefined), [scanId, runId, tick]);
  const graph = query.data?.run_id === (runId || null) ? query.data : null;
  const node = graph?.nodes.find(node => node.id === selected);
  async function build() {
    setBusy(true); setBuildError("");
    try { await api.buildAssetGraph(scanId); setRunId(0); setTick(n => n + 1); }
    catch (e) { setBuildError(String(e)); }
    finally { setBusy(false); }
  }

  return <section className="card space-y-4 p-4" aria-label="资产图详情">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="font-semibold">源码资产图</h2><p className="text-xs text-slate-500">按源码版本和范围保存结构；切换运行可查看调查覆盖。</p></div>
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-2 text-sm">审计运行
          <select className="input-field" value={runId} onChange={e => { setRunId(+e.target.value); setSelected(undefined); }}>
            <option value={0}>最近快照 · 不叠加运行</option>
            {runs.data?.runs.map(run => <option key={run.id} value={run.id}>运行 #{run.id} · {translated(run.status)}</option>)}
          </select>
        </label>
        <button className="btn-action" onClick={() => void build()} disabled={busy}>{busy ? "生成中…" : "生成当前源码资产图"}</button>
      </div>
    </div>
    {(buildError || query.error) && <p role="status" className="text-sm text-slate-500">{buildError || query.error}</p>}
    {graph && <>
      <p className="break-all font-mono text-xs text-slate-500">快照 #{graph.asset_graph_id} · {graph.repository_revision}{graph.truncated ? " · 展示已达资产数量上限" : ""}</p>
      <GraphView graph={graph} mode="asset" selected={selected} onSelect={setSelected} expanded={selected} />
      {node && <div className="rounded-lg border border-surface-border p-3 space-y-2">
        <strong>{node.label}</strong>
        {node.data.file != null && <p className="font-mono text-xs">{text(node, "file")}:{text(node, "line")} · {text(node, "handler")}</p>}
        {runId > 0 && <div className="flex flex-wrap gap-2">
          {(graph.overlay?.[node.id] ?? []).map(task =>
            <button key={task.id} className="btn-action" onClick={() => onTask({ runId, taskId: task.id })}>
              定位任务 #{task.id} · {task.label} · {translated(task.status === "running" ? task.status : task.coverage)}
            </button>)}
          {!graph.overlay?.[node.id]?.length && <span className="text-xs text-slate-500">此资产未安排直接关联任务</span>}
        </div>}
      </div>}
    </>}
  </section>;
}

export function AuditGraphPanel({ runId, poll, destination, onAsset }: {
  runId: number; poll: number; destination?: GraphDestination; onAsset?: (target: GraphDestination) => void;
}) {
  const query = useAsyncData(() => api.auditGraph(runId), [runId, poll]);
  const initial = destination?.taskId ? `task:${destination.taskId}` : undefined;
  const [selected, setSelected] = useState(initial);
  const [branch, setBranch] = useState(initial);
  const [sourceKey, setSourceKey] = useState<{ id: number; node: string } | null>(null);
  const source = useAsyncData(() => sourceKey ? api.auditEvidenceSource(runId, sourceKey.id) : Promise.resolve(null),
    [runId, sourceKey]);
  const graph = query.data?.run_id === runId ? query.data : null;
  const node = graph?.nodes.find(n => n.id === selected);
  const select = (id: string) => { setSelected(id); setSourceKey(null); if (id.startsWith("task:")) setBranch(id); };
  if (query.error && !graph) return <p role="status" className="p-3 text-sm">图加载失败：{query.error}。可返回任务与黑板查看。</p>;
  if (!graph) return <p className="p-3 text-sm">正在加载审计图…</p>;
  const related = graph.edges.filter(e => e.source === node?.id).map(e => graph.nodes.find(n => n.id === e.target))
    .filter((item): item is AuditGraphNode => Boolean(item));
  return <section aria-label="审计图详情" className="space-y-3">
    <p data-testid="worker-count" className="text-sm">运行中 Worker：{graph.active_tasks?.length ?? 0} / {graph.task_concurrency_limit ?? 1}{graph.truncated ? " · 部分黑板节点已折叠" : ""}</p>
    {query.error && <p role="status" className="text-sm">刷新失败：{query.error}</p>}
    <GraphView graph={graph} mode="audit" selected={selected} onSelect={select} expanded={branch} />
    {node && <div className="rounded-lg border border-surface-border p-4 space-y-2 text-sm">
      <strong className="break-words">{node.label}</strong>
      {node.type === "planner" && <p>来源：{text(node, "source") || "等待计划"} {text(node, "fallback_reason")}</p>}
      {node.type === "task" && <>
        <p>{text(node, "agent_id")} · {translated(node.data.status)} · {translated(node.data.coverage)}</p>
        <p className="text-xs text-slate-500">{text(node, "started_at")} {text(node, "finished_at")}</p>
        {node.data.budget_usage != null && <p className="font-mono text-xs">{JSON.stringify(node.data.budget_usage)}</p>}
        <p className="whitespace-pre-wrap text-xs">{text(node, "summary")}</p>
        {Array.isArray(node.data.asset_ids) && node.data.asset_ids.map((assetId: string) =>
          <button key={assetId} className="btn-action" onClick={() => onAsset?.({ runId, assetId, assetGraphId: graph.asset_graph_id })}>返回资产图定位入口</button>)}
      </>}
      {node.type === "fact" && <p>来源：{text(node, "source")} · 原始运行 #{text(node, "origin_run_id")}，任务 #{text(node, "origin_task_id")}</p>}
      {node.type === "finding" && <p>{translated(node.data.review_status)} · {text(node, "severity")}。请在任务与黑板中复核。</p>}
      {node.type === "evidence" && <>
        <p className="break-all font-mono text-xs">{text(node, "file_path")}:{text(node, "line_start")}–{text(node, "line_end")} · {text(node, "repository_revision")}</p>
        {node.data.evidence_type === "code_slice" &&
          <button className="btn-action" onClick={() => setSourceKey({ id: Number(node.data.id), node: node.id })}>查看证据源码</button>}
        {sourceKey?.node === node.id && source.error && <p role="status">{source.error}</p>}
        {sourceKey?.node === node.id && !source.loading && source.data && <CodeViewer content={source.data.content}
          windowStart={source.data.line_start} highlightStart={source.data.line_start}
          highlightEnd={source.data.line_end} fileLabel={source.data.file_path} />}
      </>}
      {related.length > 0 && <div className="flex flex-wrap gap-2">
        {related.slice(0, 40).map(item => <button className="btn-action max-w-[25rem] truncate" key={item.id} onClick={() => select(item.id)}>
          {translated(item.type)} · {item.label}
        </button>)}
      </div>}
    </div>}
  </section>;
}
