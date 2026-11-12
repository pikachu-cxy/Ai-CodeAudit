"""Extract and format Semgrep taint/dataflow traces for LLM consumption."""

from __future__ import annotations

import json
from pathlib import Path

from app.services.file_service import read_file_with_context


def parse_finding_metadata(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _loc_from_trace_node(node) -> dict | None:
    """Normalize Semgrep call-trace node to {file, line, label}."""
    if node is None:
        return None
    if isinstance(node, list):
        for item in node:
            loc = _loc_from_trace_node(item)
            if loc:
                return loc
        return None
    if not isinstance(node, dict):
        return None

    # Nested trace: {"Call": [inner, ...]} or {"Partial": [...]}
    for key in ("Call", "Partial", "CliLoc", "Loc"):
        if key in node:
            return _loc_from_trace_node(node[key])

    location = node.get("location") if isinstance(node.get("location"), dict) else node
    path = location.get("path") or location.get("file") or node.get("path")
    line = location.get("start", {}).get("line") if isinstance(location.get("start"), dict) else location.get("line")
    if line is None:
        line = node.get("line")
    label = (
        node.get("abstract_content")
        or node.get("content")
        or node.get("name")
        or node.get("propagated_value")
        or ""
    )
    if not path and not line and not label:
        return None
    try:
        line_i = int(line) if line is not None else 0
    except (TypeError, ValueError):
        line_i = 0
    return {
        "file": str(path) if path else "",
        "line": line_i,
        "label": str(label).strip()[:200],
    }


def extract_flow_steps(metadata: dict | str | None) -> list[dict]:
    """Turn Semgrep or CodeQL flow metadata into ordered steps."""
    meta = metadata if isinstance(metadata, dict) else parse_finding_metadata(metadata)
    trace = meta.get("dataflow_trace")
    steps: list[dict] = []
    seen: set[str] = set()

    def add_step(kind: str, node) -> None:
        loc = _loc_from_trace_node(node)
        if not loc:
            return
        key = f"{loc['file']}:{loc['line']}:{loc['label']}"
        if key in seen:
            return
        seen.add(key)
        steps.append({**loc, "kind": kind})

    if trace and isinstance(trace, dict):
        add_step("source", trace.get("taint_source"))
        for var in trace.get("intermediate_vars") or []:
            if isinstance(var, dict):
                add_step("propagation", var.get("location") or var)
                label = var.get("content") or var.get("abstract_content")
                if label and steps:
                    steps[-1]["label"] = str(label)[:200]
            else:
                add_step("propagation", var)
        add_step("sink", trace.get("taint_sink"))
        if steps:
            return steps

    thread_flows = meta.get("codeql_thread_flows")
    if isinstance(thread_flows, list):
        for tf in thread_flows:
            if not isinstance(tf, dict):
                continue
            for idx, step in enumerate(tf.get("locations") or []):
                if not isinstance(step, dict):
                    continue
                key = f"{step.get('file', '')}:{step.get('line', 0)}:{step.get('label', '')}"
                if key in seen:
                    continue
                seen.add(key)
                kind = "propagation"
                if idx == 0:
                    kind = "source"
                elif idx == len(tf.get("locations") or []) - 1:
                    kind = "sink"
                steps.append(
                    {
                        "file": str(step.get("file") or ""),
                        "line": int(step.get("line") or 0),
                        "label": str(step.get("label") or "")[:200],
                        "kind": kind,
                    }
                )
        if steps:
            return steps

    # AI-reconstructed reverse dataflow (when tools provided no taint trace)
    raw_steps = meta.get("flow_steps")
    if isinstance(raw_steps, list):
        for step in raw_steps:
            if not isinstance(step, dict):
                continue
            file_path = str(step.get("file") or "")
            try:
                line = int(step.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            label = str(step.get("label") or "")[:200]
            kind = str(step.get("kind") or "propagation").lower()
            if kind not in ("source", "propagation", "sink"):
                kind = "propagation"
            key = f"{file_path}:{line}:{label}:{kind}"
            if key in seen:
                continue
            seen.add(key)
            if not file_path and not line and not label:
                continue
            steps.append({"file": file_path, "line": line, "label": label, "kind": kind})
    return steps


def format_flow_chain(steps: list[dict]) -> str:
    if not steps:
        return ""
    parts = []
    for i, step in enumerate(steps):
        file_part = Path(step.get("file", "")).name or step.get("file", "?")
        line = step.get("line") or "?"
        label = step.get("label", "")
        seg = f"{file_part}:{line}"
        if label:
            seg += f" ({label[:60]})"
        parts.append(seg)
    return " → ".join(parts)


def layer_guess(file_path: str, label: str = "") -> str:
    text = f"{file_path} {label}".lower()
    if any(k in text for k in ("controller", "resource", "handler", "router", "endpoint", "api/")):
        return "controller"
    if any(k in text for k in ("service", "manager", "facade")):
        return "service"
    if any(k in text for k in ("mapper", "dao", "repository", "mapper.xml")):
        return "mapper"
    if any(k in text for k in ("filter", "interceptor", "middleware", "guard")):
        return "middleware"
    return "code"


def build_architecture_flow(steps: list[dict]) -> str:
    """Summarize steps as Controller → Service → Mapper style chain when possible."""
    if not steps:
        return ""
    layers: list[str] = []
    for step in steps:
        layer = layer_guess(step.get("file", ""), step.get("label", ""))
        file_part = Path(step.get("file", "")).name or "?"
        line = step.get("line") or "?"
        token = f"{layer}@{file_part}:{line}"
        if not layers or layers[-1].split("@")[0] != layer:
            layers.append(token)
        else:
            layers[-1] = token
    return " → ".join(layers)


def gather_flow_context(project_path: Path, steps: list[dict], max_chars: int = 4000) -> str:
    """Read source snippets along the dataflow path."""
    if not steps:
        return ""
    chunks: list[str] = []
    used = 0
    for step in steps:
        file_path = step.get("file")
        line = int(step.get("line") or 1)
        if not file_path:
            continue
        try:
            ctx = read_file_with_context(project_path, file_path, line, line, context_lines=12)
            rel = ctx.get("relative_path") or file_path
            body = ctx.get("content", "")
            block = f"--- {rel}:{line} ({step.get('kind', 'step')}) ---\n{body}"
            if used + len(block) > max_chars:
                break
            chunks.append(block)
            used += len(block)
        except Exception:
            continue
    return "\n\n".join(chunks)


def enrich_finding_flow(finding_dict: dict, project_path: Path) -> dict:
    """Attach flow summaries and code context to a finding payload for LLM."""
    meta = parse_finding_metadata(finding_dict.get("metadata_json"))
    steps = extract_flow_steps(meta)
    chain = format_flow_chain(steps)
    arch = build_architecture_flow(steps)
    context = gather_flow_context(project_path, steps)
    return {
        **finding_dict,
        "data_flow_steps": steps,
        "data_flow_chain": chain,
        "architecture_flow": arch,
        "flow_code_context": context,
        "has_taint_trace": bool(steps),
    }


def extract_codeql_thread_paths(metadata: dict | str | None) -> list[list[dict]]:
    """
    Extract raw CodeQL threadFlows as ordered step lists.

    Expect metadata_json shaped like:
      { "codeql_thread_flows": [ { "locations": [ {file,line,label}, ... ] }, ... ] }
    """
    meta = metadata if isinstance(metadata, dict) else parse_finding_metadata(metadata)
    thread_flows = meta.get("codeql_thread_flows")
    if not isinstance(thread_flows, list):
        return []

    paths: list[list[dict]] = []
    for tf in thread_flows:
        if not isinstance(tf, dict):
            continue
        locs = tf.get("locations")
        if not isinstance(locs, list) or not locs:
            continue
        steps: list[dict] = []
        for s in locs:
            if not isinstance(s, dict):
                continue
            file = str(s.get("file") or "")
            line = int(s.get("line") or 0)
            label = str(s.get("label") or "")
            if not file and not line and not label:
                continue
            steps.append({"file": file, "line": line, "label": label})
        if steps:
            paths.append(steps)
    return paths


def build_project_codeql_flow_graph(
    findings: list[dict],
    project_path: Path,
    *,
    max_paths: int = 25,
    max_nodes: int = 200,
    max_edges: int = 400,
) -> dict:
    """
    Build a lightweight project-level flow graph from all CodeQL threadFlows.

    Output is a summary dict suitable for injecting into LLM prompt.
    """
    nodes: dict[str, dict] = {}  # key=file:line -> {file,line,label, in_deg, out_deg}
    edges: dict[str, int] = {}  # key=from_key->to_key -> count
    path_summaries: list[str] = []

    def node_key(step: dict) -> str:
        return f"{step.get('file','')}:{step.get('line',0)}"

    total_paths = 0
    for f in findings:
        meta = parse_finding_metadata(f.get("metadata_json"))
        paths = extract_codeql_thread_paths(meta)
        for steps in paths:
            total_paths += 1
            if len(path_summaries) >= max_paths:
                break

            # Condense consecutive duplicate nodes
            condensed: list[dict] = []
            last_key: str | None = None
            for s in steps:
                k = node_key(s)
                if k == last_key:
                    continue
                condensed.append(s)
                last_key = k

            if not condensed:
                continue

            # Nodes + edges
            for i, s in enumerate(condensed):
                k = node_key(s)
                if k not in nodes and len(nodes) < max_nodes:
                    nodes[k] = {
                        "file": s.get("file") or "",
                        "line": s.get("line") or 0,
                        "label": (s.get("label") or "")[:80],
                        "in_deg": 0,
                        "out_deg": 0,
                    }
                if i + 1 < len(condensed) and len(edges) < max_edges:
                    to_s = condensed[i + 1]
                    from_k = node_key(s)
                    to_k = node_key(to_s)
                    ek = f"{from_k}->{to_k}"
                    edges[ek] = edges.get(ek, 0) + 1

            # Path summary: src -> sink (with intermediate condensed nodes shortened)
            def short(step: dict) -> str:
                base = Path(step.get("file") or "").name or "?"
                line = step.get("line") or 0
                lbl = (step.get("label") or "").strip()
                lbl_part = f" ({lbl[:25]})" if lbl else ""
                return f"{base}:{line}{lbl_part}"

            src = condensed[0]
            sink = condensed[-1]
            chain_nodes = [short(x) for x in condensed[:5]]  # first 5 nodes only
            chain_str = " -> ".join(chain_nodes)
            tail = "" if len(condensed) <= 5 else f" -> ... -> {short(sink)}"
            path_summaries.append(f"{short(src)} -> ... -> {short(sink)}; 预览链: {chain_str}{tail}".strip())
        if len(path_summaries) >= max_paths:
            break

    # Compute degrees
    for ek, cnt in edges.items():
        from_k, to_k = ek.split("->", 1)
        if from_k in nodes:
            nodes[from_k]["out_deg"] += cnt
        if to_k in nodes:
            nodes[to_k]["in_deg"] += cnt

    # Hubs: highest total degree
    hubs = sorted(
        nodes.items(),
        key=lambda kv: (kv[1].get("in_deg", 0) + kv[1].get("out_deg", 0)),
        reverse=True,
    )[:10]
    hub_lines = []
    for _k, n in hubs:
        base = Path(n.get("file") or "").name or "?"
        hub_lines.append(f"{base}:{n.get('line',0)} (in={n.get('in_deg',0)}, out={n.get('out_deg',0)}) {n.get('label','')[:40]}")

    # Top edges
    top_edges = sorted(edges.items(), key=lambda kv: kv[1], reverse=True)[:20]
    edge_lines = []
    for ek, cnt in top_edges:
        from_k, to_k = ek.split("->", 1)
        from_file, from_line = from_k.rsplit(":", 1)
        to_file, to_line = to_k.rsplit(":", 1)
        edge_lines.append(f"{Path(from_file).name}:{from_line} -> {Path(to_file).name}:{to_line} (x{cnt})")

    return {
        "codeql_path_total": total_paths,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "path_summaries": path_summaries,
        "hub_nodes": hub_lines,
        "top_edges": edge_lines,
    }


def format_project_codeql_flow_summary(graph: dict) -> str:
    if not graph:
        return "无可用的 CodeQL 项目级线程流数据。"
    parts = []
    parts.append(f"CodeQL 线程流汇总：paths={graph.get('codeql_path_total')} nodes={graph.get('node_count')} edges={graph.get('edge_count')}")
    if graph.get("hub_nodes"):
        parts.append("Top hubs：\n- " + "\n- ".join(graph["hub_nodes"][:10]))
    if graph.get("top_edges"):
        parts.append("Top edges：\n- " + "\n- ".join(graph["top_edges"][:20]))
    if graph.get("path_summaries"):
        parts.append("Top paths（源->sink 预览）：\n- " + "\n- ".join(graph["path_summaries"][:10]))
    return "\n\n".join(parts)[:2600]
