import { ChevronRight, Loader2 } from "lucide-react";
import type { FlowNode } from "../lib/findingUtils";
import { targetLabel } from "../lib/findingUtils";

interface Props {
  nodes: FlowNode[];
  activeNodeId?: string | null;
  resolvingId?: string | null;
  onNodeClick: (node: FlowNode) => void;
}

const KIND_COLORS: Record<FlowNode["kind"], string> = {
  endpoint: "border-blue-500/40 bg-blue-500/10 hover:bg-blue-500/20",
  source: "border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20",
  flow: "border-purple-500/40 bg-purple-500/10 hover:bg-purple-500/20",
  trigger: "border-orange-500/40 bg-orange-500/10 hover:bg-orange-500/20",
  location: "border-slate-200/20 bg-white/5 hover:bg-white/10",
  step: "border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20",
};

export function DataFlowBar({ nodes, activeNodeId, resolvingId, onNodeClick }: Props) {
  if (nodes.length === 0) return null;

  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-500 uppercase tracking-wide">
        数据链路（点击跳转到对应代码，支持跨文件定位）
      </p>
      <div className="flex flex-wrap items-stretch gap-1">
        {nodes.map((node, i) => {
          const clickable = Boolean(node.target);
          const active = node.id === activeNodeId;
          const resolving = node.id === resolvingId;
          const loc = targetLabel(node.target);
          return (
            <div key={node.id} className="flex items-center gap-1">
              <button
                type="button"
                disabled={!clickable || resolving}
                onClick={() => clickable && onNodeClick(node)}
                className={`text-left rounded-lg border px-3 py-2 min-w-[120px] max-w-[240px] transition-colors ${
                  KIND_COLORS[node.kind]
                } ${!clickable ? "opacity-70 cursor-default" : "cursor-pointer"} ${
                  active ? "ring-2 ring-accent/60" : ""
                }`}
                title={node.detail}
              >
                <div className="flex items-center gap-1 mb-0.5">
                  <p className="text-[10px] uppercase text-slate-500">{node.label}</p>
                  {resolving && <Loader2 className="w-3 h-3 animate-spin text-accent" />}
                </div>
                <p className="text-xs text-slate-200 line-clamp-2 break-all">{node.detail}</p>
                {loc && (
                  <p className="text-[10px] text-accent/80 mt-1 font-mono truncate">{loc}</p>
                )}
              </button>
              {i < nodes.length - 1 && (
                <ChevronRight className="w-4 h-4 text-slate-600 shrink-0 hidden sm:block" />
              )}
            </div>
          );
        })}
      </div>
      <p className="text-[10px] text-slate-600">
        含「路径:行号」的节点直接跳转；HTTP 接口节点将在项目中搜索路由映射；其余节点搜索符号定位。
      </p>
    </div>
  );
}
