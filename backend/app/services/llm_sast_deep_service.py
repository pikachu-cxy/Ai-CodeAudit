"""LLM deep audit for SAST findings using Semgrep dataflow traces and cross-layer context."""

import json
import logging
from pathlib import Path

from app.config import settings
from app.models import AiVerdict
from app.services.llm_audit_service import parse_finding_metadata
from app.services.llm_provider import chat_completion, effective_llm_timeout, extract_json_from_llm_text, is_llm_configured, llm_not_configured_message
from app.services.llm_service import normalize_fp_results, verdict_from_str
from app.services.sast_flow_service import (
    build_project_codeql_flow_graph,
    enrich_finding_flow,
    extract_flow_steps,
    format_flow_chain,
    format_project_codeql_flow_summary,
)

logger = logging.getLogger(__name__)

SAST_DEEP_SYSTEM_PROMPT = """你是一名资深应用安全专家，基于 Semgrep SAST 结果与**污点数据流**进行深度安全研判。

你将收到：
- SAST 规则（Semgrep 或 CodeQL）、严重度、告警位置与代码片段
- 若存在污点分析：source → propagation → sink 的跨文件/跨函数链路
- 链路沿途相关源码上下文

任务（对每条 SAST finding）：
1. 结合数据流判断告警是否**真实可利用**（REAL_VULN）、**误报**（FALSE_POSITIVE）或**待确认**（UNCERTAIN）
2. 重点分析：注入、反序列化、SSRF、路径穿越、敏感数据流、认证绕过等**复杂链式漏洞**
3. 若存在污点流，说明从入口（如 Controller/HTTP）到危险点（Sink）的完整攻击路径
4. 若 Semgrep 仅命中模式但流被 sanitizer/鉴权切断，应判误报并说明断点
5. 若发现 Semgrep 未覆盖但流上存在更高危组合（如不可信数据进入 ObjectInputStream/readValue），在 `chained_risk` 中说明

输出严格 JSON 数组，每项：
{
  "finding_id": <number>,
  "verdict": "real_vuln" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reason": "中文分析，150字以内，含数据流结论",
  "message_zh": "中文漏洞描述",
  "data_flow_summary": "source → ... → sink 一句话",
  "exploit_scenario": "可利用时的攻击场景（无则空字符串）",
  "chained_risk": "流上额外风险或未覆盖问题（无则空字符串）"
}
只输出 JSON。"""


async def analyze_sast_with_flow(findings: list[dict], project_path: Path) -> list[dict]:
    if not is_llm_configured():
        return [
            {
                "finding_id": f["id"],
                "verdict": AiVerdict.SKIPPED.value,
                "confidence": 0.0,
                "reason": llm_not_configured_message(),
            }
            for f in findings
        ]

    # Build project-level CodeQL flow graph summary for global context (priority for LLM).
    # It only uses findings that carry `codeql_thread_flows`.
    try:
        project_graph = build_project_codeql_flow_graph(findings, project_path)
        project_graph_summary = format_project_codeql_flow_summary(project_graph)
    except Exception:
        project_graph = {}
        project_graph_summary = "无可用的 CodeQL 项目级线程流数据。"

    enriched = [enrich_finding_flow(f, project_path) for f in findings]
    payload = []
    for item in enriched:
        rel = item.get("file_path", "")
        try:
            rel = str(Path(rel).relative_to(project_path))
        except ValueError:
            pass
        payload.append(
            {
                "finding_id": item["id"],
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "message": item.get("message"),
                "file": rel,
                "line": item.get("line_start"),
                "code_snippet": (item.get("code_snippet") or "")[:1500],
                "has_taint_trace": item.get("has_taint_trace"),
                "data_flow_chain": item.get("data_flow_chain"),
                "architecture_flow": item.get("architecture_flow"),
                "flow_code_context": (item.get("flow_code_context") or "")[:3500],
            }
        )

    user_content = json.dumps(payload, ensure_ascii=False, indent=2)
    try:
        text = await chat_completion(
            [
                {"role": "system", "content": SAST_DEEP_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"项目级 CodeQL 数据流图谱摘要（用于全局理解与优先级）：\n{project_graph_summary}\n\n"
                        f"请对以下 {len(payload)} 条 SAST 发现做数据流驱动的深度研判：\n\n{user_content}"
                    ),
                },
            ],
            task="deep",
            temperature=0.1,
            max_tokens=settings.llm_audit_max_tokens,
            timeout=effective_llm_timeout(3, task="deep"),
        )
        text = extract_json_from_llm_text(text)
        results = json.loads(text)
        if isinstance(results, dict):
            results = results.get("findings", [results])
        return results if isinstance(results, list) else []
    except Exception as exc:
        logger.exception("SAST deep LLM audit failed")
        return [
            {
                "finding_id": f["id"],
                "verdict": AiVerdict.UNCERTAIN.value,
                "confidence": 0.0,
                "reason": f"深度研判失败: {exc}",
            }
            for f in findings
        ]


def apply_sast_deep_results(findings_db, results: list[dict]) -> int:
    by_id = normalize_fp_results(results)
    updated = 0
    for f in findings_db:
        r = by_id.get(f.id)
        if not r:
            continue
        meta = parse_finding_metadata(f.metadata_json)
        steps = extract_flow_steps(meta)
        if not meta.get("data_flow_chain") and steps:
            meta["data_flow_chain"] = format_flow_chain(steps)
        if r.get("data_flow_summary"):
            meta["data_flow_summary"] = r["data_flow_summary"]
        if r.get("exploit_scenario"):
            meta["exploit_scenario_llm"] = r["exploit_scenario"]
        if r.get("chained_risk"):
            meta["chained_risk"] = r["chained_risk"]
        meta["sast_deep_reviewed"] = True
        f.metadata_json = json.dumps(meta, ensure_ascii=False)
        f.ai_verdict = verdict_from_str(r.get("verdict", ""))
        reason_parts = [r.get("reason", "")]
        if r.get("data_flow_summary"):
            reason_parts.append(f"数据流: {r['data_flow_summary']}")
        if r.get("chained_risk"):
            reason_parts.append(f"链式风险: {r['chained_risk']}")
        f.ai_reason = "\n".join(p for p in reason_parts if p)
        f.ai_confidence = r.get("confidence")
        if r.get("message_zh"):
            f.message_zh = r["message_zh"]
        updated += 1
    return updated
