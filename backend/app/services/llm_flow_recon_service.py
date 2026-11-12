"""Agentic dataflow reconstruction for SAST findings lacking tool-provided taint traces."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.config import settings
from app.models import AiVerdict
from app.services.agent_tools import TOOL_SPECS, execute_agent_tool, parse_agent_response
from app.services.llm_audit_service import parse_finding_metadata
from app.services.llm_provider import chat_completion, effective_llm_timeout, is_llm_configured, llm_not_configured_message
from app.services.llm_service import verdict_from_str
from app.services.sast_flow_service import format_flow_chain

logger = logging.getLogger(__name__)

FLOW_RECON_SYSTEM_PROMPT = """你是资深应用安全专家，任务是对安全告警做**反向数据流追认**（工具未给出完整污点流，或来自 LLM 端点审计的初步发现）。

你会看到：告警规则/类型、严重度、sink 文件/行号与代码片段；LLM 发现可能附带初步 data_flow 或 discovery_reason，可作为线索但须用工具验证。

调查顺序（按需调整）：
1. 先 read_file 读懂 sink 所在函数：危险调用是什么？参数从哪来？
2. search_code 追参数赋值、调用方、URL/请求构造；Controller 类可用 list_controllers 定位相关端点
3. 尽量追到 HTTP/Controller/外部输入；若被 allowlist/鉴权/硬编码切断，标出断点
4. **调查 3–6 轮后必须给出 flow_verdict**；证据不完整也输出 uncertain，禁止空转或重复无效 JSON

重点漏洞类型提示：
- SSRF：用户可控 URL/host/path → HTTP 客户端（RestTemplate/WebClient/OkHttp/URL.openConnection 等）
- 注入：可控字符串进入 SQL/命令/模板
- 路径穿越：可控路径进入文件读写

可用工具：
{tool_specs}

响应格式（只输出 JSON，无 markdown）：
调用工具:
{{"action":"tool","tool":"read_file","arguments":{{"path":"...","start_line":1,"end_line":120}}}}

完成追认（证据充分时）:
{{
  "action": "flow_verdict",
  "verdict": "real_vuln" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reason": "中文结论，说明是否存在 source→sink，150字内",
  "data_flow_summary": "source → ... → sink 一句话",
  "flow_steps": [
    {{"file":"相对路径","line":12,"label":"简述","kind":"source"}},
    {{"file":"相对路径","line":40,"label":"简述","kind":"propagation"}},
    {{"file":"相对路径","line":88,"label":"危险调用","kind":"sink"}}
  ],
  "break_point": "若误报，流在何处被切断；真实漏洞则空字符串",
  "exploit_scenario": "可利用时的攻击场景；否则空字符串",
  "message_zh": "中文漏洞描述"
}}

规则：
- flow_steps 至少包含 sink；有 source 时必须标 kind=source
- 找不到完整流且无法证伪 → uncertain，不要硬判 real_vuln
- 文件路径尽量用项目相对路径
"""


def _rel_path(project_path: Path, file_path: str) -> str:
    try:
        return str(Path(file_path).resolve().relative_to(project_path.resolve()))
    except Exception:
        return file_path


def _normalize_flow_steps(raw_steps: list, project_path: Path, finding: dict) -> list[dict]:
    steps: list[dict] = []
    for item in raw_steps or []:
        if not isinstance(item, dict):
            continue
        file_path = str(item.get("file") or "").strip()
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        kind = str(item.get("kind") or "propagation").strip().lower()
        if kind not in ("source", "propagation", "sink"):
            kind = "propagation"
        label = str(item.get("label") or "")[:200]
        if not file_path and not line and not label:
            continue
        if file_path:
            file_path = _rel_path(project_path, file_path)
        steps.append({"file": file_path, "line": line, "label": label, "kind": kind})

    if not steps:
        sink_file = _rel_path(project_path, str(finding.get("file_path") or ""))
        steps.append(
            {
                "file": sink_file,
                "line": int(finding.get("line_start") or 0),
                "label": "告警 sink",
                "kind": "sink",
            }
        )
    return steps


def _parse_flow_verdict(text: str) -> dict | None:
    from app.services.llm_provider import extract_json_from_llm_text

    raw = extract_json_from_llm_text(text)
    if raw:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            action = str(data.get("action") or "").lower()
            if action == "flow_verdict":
                return data
            if data.get("verdict") and (data.get("flow_steps") is not None or data.get("data_flow_summary")):
                data["action"] = "flow_verdict"
                return data

    parsed = parse_agent_response(text)
    if not parsed:
        return None
    if parsed.get("action") == "flow_verdict":
        return parsed
    # Some models wrap verdict fields under answer/content JSON
    if parsed.get("action") == "answer":
        content = str(parsed.get("content") or "").strip()
        if content.startswith("{") and "verdict" in content:
            try:
                data = json.loads(extract_json_from_llm_text(content) or content)
            except json.JSONDecodeError:
                return None
            if isinstance(data, dict) and data.get("verdict"):
                data["action"] = "flow_verdict"
                return data
    return None


def _flow_recon_max_rounds() -> int:
    base = int(settings.llm_agent_max_tool_rounds or 10)
    return max(12, min(base + 10, 28))


def _build_investigation_digest(messages: list[dict], *, max_chars: int = 8000) -> str:
    """Condense tool rounds for final synthesis when the full history is too long."""
    parts: list[str] = []
    for msg in messages[1:]:  # skip system
        role = str(msg.get("role") or "")
        content = str(msg.get("content") or "").strip()
        if not content:
            continue
        if role == "assistant" and len(content) > 2500:
            content = content[:2500] + "\n…(截断)"
        elif role == "user" and len(content) > 3500:
            content = content[:3500] + "\n…(截断)"
        parts.append(f"### {role}\n{content}")
    digest = "\n\n".join(parts)
    if len(digest) > max_chars:
        digest = digest[-max_chars:]
    return digest


def _collect_investigation_steps(messages: list[dict], project_path: Path) -> list[dict]:
    """Extract file/line hints from agent tool calls during recon."""
    steps: list[dict] = []
    seen: set[str] = set()

    def add(file_path: str, line: int, label: str, kind: str = "propagation") -> None:
        if not file_path:
            return
        rel = _rel_path(project_path, file_path)
        key = f"{rel}:{line}:{kind}"
        if key in seen:
            return
        seen.add(key)
        steps.append({"file": rel, "line": max(1, line), "label": label[:120], "kind": kind})

    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        parsed = parse_agent_response(str(msg.get("content") or ""))
        if not parsed or parsed.get("action") != "tool":
            continue
        tool = str(parsed.get("tool") or "")
        args = parsed.get("arguments") or {}
        if tool == "read_file":
            add(str(args.get("path") or ""), int(args.get("start_line") or 1), "代码调查")
        elif tool == "read_files_batch":
            for item in args.get("files") or []:
                if not isinstance(item, dict):
                    continue
                add(str(item.get("path") or ""), int(item.get("start_line") or 1), "批量代码调查")
        elif tool == "search_code":
            hint = str(args.get("file_hint") or "").strip()
            if hint:
                add(hint, 1, f"搜索: {str(args.get('query') or '')[:40]}")
        elif tool in ("list_endpoints", "list_controllers"):
            flt = str(args.get("filter") or "")[:40]
            if flt and "." in flt:
                add(flt, 1, "端点调查", "source")

    return steps


def _salvage_flow_from_messages(
    messages: list[dict],
    finding: dict,
    meta: dict,
    project_path: Path,
) -> dict | None:
    """Best-effort flow from tool investigation history when synthesis fails."""
    inv_steps = _collect_investigation_steps(messages, project_path)
    sink_file = _rel_path(project_path, str(finding.get("file_path") or ""))
    sink_line = int(finding.get("line_start") or 0)
    sink = {
        "file": sink_file,
        "line": sink_line,
        "label": "告警 sink",
        "kind": "sink",
    }

    endpoint = str(meta.get("api_endpoint") or meta.get("endpoint") or "").strip()
    if endpoint:
        inv_steps.insert(
            0,
            {
                "file": sink_file,
                "line": max(1, sink_line - 20) if sink_line else 1,
                "label": endpoint[:120],
                "kind": "source",
            },
        )

    steps = inv_steps if inv_steps else []
    if not any(s.get("kind") == "sink" for s in steps):
        steps.append(sink)
    elif steps[-1].get("kind") != "sink":
        steps.append(sink)

    if len(steps) <= 1 and not endpoint:
        return None

    summary = format_flow_chain(steps)
    discovery = str(meta.get("data_flow") or meta.get("data_flow_summary") or "").strip()
    if discovery and discovery not in summary:
        summary = f"{discovery} → {summary}" if summary else discovery

    return {
        "finding_id": finding.get("id"),
        "verdict": AiVerdict.UNCERTAIN.value,
        "confidence": 0.4,
        "reason": "轮次用尽；已根据调查过程中读取的代码路径整理初步数据流，完整 source→sink 未验证",
        "data_flow_summary": summary,
        "flow_steps": steps,
        "break_point": "Agent 轮次内未完成完整追认",
        "exploit_scenario": "",
        "message_zh": "",
        "salvaged_from_messages": True,
    }


def _salvage_flow_from_discovery(finding: dict, meta: dict, project_path: Path) -> dict | None:
    """Build a best-effort flow_verdict from LLM discovery notes when agent times out."""
    summary = str(
        meta.get("data_flow_summary")
        or meta.get("data_flow_chain")
        or meta.get("data_flow")
        or meta.get("discovery_data_flow")
        or meta.get("discovery_data_flow_summary")
        or ""
    ).strip()
    reason = str(meta.get("discovery_reason") or finding.get("ai_reason") or "").strip()
    if not summary and not reason:
        return None

    steps: list[dict] = []
    if isinstance(meta.get("flow_steps"), list) and meta["flow_steps"]:
        steps = _normalize_flow_steps(meta["flow_steps"], project_path, finding)
    elif summary:
        sink_file = _rel_path(project_path, str(finding.get("file_path") or ""))
        sink_line = int(finding.get("line_start") or 0)

        # If we only have an abstract data_flow chain (e.g. "a -> b -> c"),
        # synthesize a best-effort source/propagation/sink structure.
        # Note: this is still uncertain because we haven't verified via tools.
        parts = [s.strip() for s in summary.split("->")]
        if len(parts) <= 1:
            # Support common arrows
            for sep in ["→", "=>", "➜", "->"]:
                if sep in summary:
                    parts = [s.strip() for s in summary.split(sep)]
                    break
        parts = [p for p in parts if p]

        if len(parts) >= 2:
            source_label = parts[0][:180]
            mid_labels = parts[1:-1]
            sink_label = parts[-1][:180]
            steps = [
                {"file": sink_file, "line": sink_line, "label": source_label, "kind": "source"},
            ]
            for i, mid in enumerate(mid_labels[:6]):
                steps.append(
                    {
                        "file": sink_file,
                        "line": sink_line,
                        "label": mid[:180] or f"传播 {i + 1}",
                        "kind": "propagation",
                    }
                )
            steps.append(
                {"file": sink_file, "line": sink_line, "label": sink_label or "告警 sink", "kind": "sink"}
            )
        else:
            steps = [
                {
                    "file": sink_file,
                    "line": sink_line,
                    "label": summary[:120],
                    "kind": "sink",
                }
            ]

    return {
        "finding_id": finding.get("id"),
        "verdict": AiVerdict.UNCERTAIN.value,
        "confidence": 0.45,
        "reason": reason[:500] if reason else "基于 LLM 端点审计初步数据流，Agent 追认未能在轮次内完成验证",
        "data_flow_summary": summary or format_flow_chain(steps),
        "flow_steps": steps,
        "break_point": "Agent 轮次内未完成工具验证",
        "exploit_scenario": str(meta.get("exploit_scenario") or meta.get("attack_scenario") or "")[:500],
        "message_zh": "",
        "salvaged_from_discovery": True,
    }


async def _force_flow_verdict_synthesis(
    messages: list[dict],
    finding: dict,
    project_path: Path,
    *,
    reason: str,
) -> dict | None:
    """One-shot synthesis when the agent loop stalls or hits the round cap."""
    digest = _build_investigation_digest(messages)
    tail = {
        "role": "user",
        "content": (
            f"{reason}\n"
            "禁止再调用工具。请根据以下全部调查记录，**立即**输出 action=flow_verdict 的 JSON。\n"
            "证据不足时 verdict=uncertain，但仍须填写 flow_steps（至少 sink，有线索则补 source/propagation）"
            "与 data_flow_summary。\n\n"
            f"--- 调查记录 ---\n{digest}"
        ),
    }
    synth_messages = messages + [tail]

    last_err: Exception | None = None
    for use_json_mode in (True, False):
        try:
            text = await chat_completion(
                synth_messages,
                task="deep",
                temperature=0.1,
                max_tokens=min(settings.llm_audit_max_tokens, 4096),
                timeout=effective_llm_timeout(5, task="deep"),
                json_mode=use_json_mode,
            )
        except Exception as exc:
            last_err = exc
            logger.warning(
                "Flow recon synthesis failed finding=%s json_mode=%s: %s",
                finding.get("id"),
                use_json_mode,
                exc,
            )
            continue

        verdict = _parse_flow_verdict(text)
        if not verdict or verdict.get("action") != "flow_verdict":
            continue
        steps = _normalize_flow_steps(verdict.get("flow_steps") or [], project_path, finding)
        if len(steps) <= 1:
            inv = _collect_investigation_steps(messages, project_path)
            if inv:
                sink_file = _rel_path(project_path, str(finding.get("file_path") or ""))
                merged = inv + [
                    {
                        "file": sink_file,
                        "line": int(finding.get("line_start") or 0),
                        "label": "告警 sink",
                        "kind": "sink",
                    }
                ]
                steps = _normalize_flow_steps(merged, project_path, finding)
        return {
            "finding_id": finding.get("id"),
            "verdict": str(verdict.get("verdict") or "uncertain"),
            "confidence": verdict.get("confidence", 0.5),
            "reason": str(verdict.get("reason") or ""),
            "data_flow_summary": str(verdict.get("data_flow_summary") or format_flow_chain(steps)),
            "flow_steps": steps,
            "break_point": str(verdict.get("break_point") or ""),
            "exploit_scenario": str(verdict.get("exploit_scenario") or ""),
            "message_zh": str(verdict.get("message_zh") or ""),
            "synthesized": True,
        }

    if last_err:
        logger.warning("Flow recon synthesis exhausted finding=%s: %s", finding.get("id"), last_err)
    return None


async def reconstruct_finding_flow(
    finding: dict,
    project_path: Path,
    *,
    progress_callback=None,
    cancel_check=None,
) -> dict:
    """Run reverse dataflow agent for one finding. Returns flow_verdict-shaped dict.

    progress_callback(round_no, max_rounds, detail) may be sync or async.
    cancel_check() may raise to abort.
    """
    finding_id = finding.get("id")
    if not is_llm_configured():
        return {
            "finding_id": finding_id,
            "verdict": AiVerdict.SKIPPED.value,
            "confidence": 0.0,
            "reason": llm_not_configured_message(),
            "data_flow_summary": "",
            "flow_steps": [],
            "break_point": "",
            "exploit_scenario": "",
        }

    rel = _rel_path(project_path, str(finding.get("file_path") or ""))
    meta = parse_finding_metadata(finding.get("metadata_json"))
    is_llm = str(finding.get("tool") or "").lower() == "llm"
    seed = {
        "finding_id": finding_id,
        "tool": finding.get("tool"),
        "category": finding.get("category"),
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "message": finding.get("message"),
        "file": rel,
        "line": finding.get("line_start"),
        "code_snippet": (finding.get("code_snippet") or "")[:2000],
        "hint": (
            "LLM 端点审计发现，请从 sink 反向追认并验证 source→sink"
            if is_llm
            else "工具未提供完整污点流，请从 sink 反向追认 source→sink"
        ),
    }
    if finding.get("ai_reason"):
        seed["discovery_reason"] = (finding.get("ai_reason") or "")[:1500]
    if meta.get("data_flow"):
        seed["discovery_data_flow"] = str(meta["data_flow"])[:2000]
    if meta.get("discovery_reason") and "discovery_reason" not in seed:
        seed["discovery_reason"] = str(meta["discovery_reason"])[:1500]
    if meta.get("endpoint") or meta.get("http_method"):
        seed["endpoint"] = meta.get("endpoint") or ""
        seed["http_method"] = meta.get("http_method") or ""

    system = FLOW_RECON_SYSTEM_PROMPT.format(tool_specs=TOOL_SPECS)
    messages: list[dict] = [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": (
                "请对以下告警做反向数据流追认，先工具调查，再输出 flow_verdict：\n"
                f"{json.dumps(seed, ensure_ascii=False, indent=2)}"
            ),
        },
    ]

    max_rounds = _flow_recon_max_rounds()
    last_text = ""
    stale_rounds = 0
    tool_rounds = 0

    async def _emit(round_no: int, detail: str) -> None:
        if not progress_callback:
            return
        maybe = progress_callback(round_no, max_rounds, detail)
        if hasattr(maybe, "__await__"):
            await maybe

    for round_no in range(max_rounds):
        if cancel_check:
            cancel_check()
        await _emit(round_no + 1, "调用模型分析…")
        try:
            last_text = await chat_completion(
                messages,
                task="deep",
                temperature=0.15,
                max_tokens=min(settings.llm_audit_max_tokens, 3072),
                timeout=effective_llm_timeout(4, task="deep"),
            )
        except Exception as exc:
            logger.exception("Flow recon LLM call failed finding=%s: %s", finding_id, exc)
            return {
                "finding_id": finding_id,
                "verdict": AiVerdict.UNCERTAIN.value,
                "confidence": 0.0,
                "reason": f"数据流追认失败: {exc}",
                "data_flow_summary": "",
                "flow_steps": [],
                "break_point": "",
                "exploit_scenario": "",
            }

        if cancel_check:
            cancel_check()

        verdict = _parse_flow_verdict(last_text)
        if verdict and verdict.get("action") == "flow_verdict":
            steps = _normalize_flow_steps(verdict.get("flow_steps") or [], project_path, finding)
            await _emit(round_no + 1, "已得出结论")
            return {
                "finding_id": finding_id,
                "verdict": str(verdict.get("verdict") or "uncertain"),
                "confidence": verdict.get("confidence", 0.5),
                "reason": str(verdict.get("reason") or ""),
                "data_flow_summary": str(verdict.get("data_flow_summary") or format_flow_chain(steps)),
                "flow_steps": steps,
                "break_point": str(verdict.get("break_point") or ""),
                "exploit_scenario": str(verdict.get("exploit_scenario") or ""),
                "message_zh": str(verdict.get("message_zh") or ""),
            }

        parsed = parse_agent_response(last_text)
        if parsed and parsed.get("action") == "tool":
            remaining = max_rounds - round_no - 1
            tool_rounds += 1
            if remaining <= 2 or tool_rounds >= max(8, max_rounds - 4):
                messages.append({"role": "assistant", "content": last_text})
                synth = await _force_flow_verdict_synthesis(
                    messages,
                    finding,
                    project_path,
                    reason=(
                        f"已调查 {tool_rounds} 轮工具，剩余 {remaining} 轮"
                        " — 请根据已有证据立即输出 flow_verdict，禁止再调用工具"
                    ),
                )
                if synth:
                    await _emit(round_no + 1, "调查充分，合成结论")
                    return synth

            stale_rounds = 0
            tool_name = parsed.get("tool") or ""
            tool_args = parsed.get("arguments") or {}
            await _emit(round_no + 1, f"工具 {tool_name}")
            tool_result = execute_agent_tool(project_path, tool_name, tool_args)
            logger.info("Flow recon tool round %s finding=%s: %s", round_no + 1, finding_id, tool_name)
            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"工具 `{tool_name}` 返回:\n{tool_result}\n\n"
                        "请继续调查，或证据充分时输出 action=flow_verdict。"
                    ),
                }
            )
            continue

        stale_rounds += 1
        remaining = max_rounds - round_no - 1
        if remaining <= 1 or stale_rounds >= 3:
            synth = await _force_flow_verdict_synthesis(
                messages,
                finding,
                project_path,
                reason=(
                    f"已达轮次上限（剩余 {remaining} 轮）"
                    if remaining <= 1
                    else f"连续 {stale_rounds} 轮未得到有效 flow_verdict"
                ),
            )
            if synth:
                await _emit(round_no + 1, "强制合成结论")
                return synth

        messages.append({"role": "assistant", "content": last_text})
        nudge = (
            "请仅输出合法 JSON：action=flow_verdict 给出结论（证据不足用 uncertain），或 action=tool 继续调查。"
            if stale_rounds < 2
            else "请**立即**输出 action=flow_verdict（禁止 tool）。根据已有证据给出结论，不完整也填 uncertain。"
        )
        messages.append({"role": "user", "content": nudge})

    synth = await _force_flow_verdict_synthesis(
        messages,
        finding,
        project_path,
        reason="调查轮次已用尽，请根据全部调查记录输出最终 flow_verdict",
    )
    if synth:
        return synth

    salvaged = _salvage_flow_from_messages(messages, finding, meta, project_path)
    if salvaged:
        return salvaged

    salvaged = _salvage_flow_from_discovery(finding, meta, project_path)
    if salvaged:
        return salvaged

    inv_steps = _collect_investigation_steps(messages, project_path)
    fallback_steps = _normalize_flow_steps(inv_steps, project_path, finding)
    fallback_summary = format_flow_chain(fallback_steps)
    return {
        "finding_id": finding_id,
        "verdict": AiVerdict.UNCERTAIN.value,
        "confidence": 0.3,
        "reason": (
            "数据流追认达到轮次上限，模型未能输出完整结论"
            + ("；已保留调查过程中定位的代码位置" if len(fallback_steps) > 1 else "")
        ),
        "data_flow_summary": fallback_summary,
        "flow_steps": fallback_steps,
        "break_point": "轮次上限",
        "exploit_scenario": "",
        "message_zh": "",
        "raw_tail": (last_text or "")[:500],
    }


def apply_flow_recon_result(finding_db, result: dict) -> bool:
    """Write reconstructed flow + verdict onto ORM finding. Returns True if applied."""
    if not result:
        return False
    meta = parse_finding_metadata(finding_db.metadata_json)
    if finding_db.tool == "llm":
        if finding_db.ai_reason and not meta.get("discovery_reason"):
            meta["discovery_reason"] = finding_db.ai_reason
        if finding_db.ai_verdict and not meta.get("discovery_verdict"):
            meta["discovery_verdict"] = (
                finding_db.ai_verdict.value
                if hasattr(finding_db.ai_verdict, "value")
                else str(finding_db.ai_verdict)
            )
        if finding_db.ai_confidence is not None and "discovery_confidence" not in meta:
            meta["discovery_confidence"] = finding_db.ai_confidence
    steps = result.get("flow_steps") if isinstance(result.get("flow_steps"), list) else []
    summary = str(result.get("data_flow_summary") or "")
    if not summary and steps:
        summary = format_flow_chain(steps)

    meta["flow_reconstructed"] = True
    meta["sast_deep_reviewed"] = True
    meta["flow_steps"] = steps
    if summary:
        meta["data_flow_summary"] = summary
        meta["data_flow_chain"] = summary
    if result.get("break_point"):
        meta["flow_break_point"] = result["break_point"]
    if result.get("exploit_scenario"):
        meta["exploit_scenario_llm"] = result["exploit_scenario"]

    finding_db.metadata_json = json.dumps(meta, ensure_ascii=False)
    finding_db.ai_verdict = verdict_from_str(result.get("verdict", ""))
    reason_parts = [str(result.get("reason") or "").strip()]
    if summary:
        only_sink = (
            len(steps) == 1
            and str(steps[0].get("label") or "") == "告警 sink"
            and not result.get("salvaged_from_messages")
            and not result.get("synthesized")
        )
        if only_sink:
            reason_parts.append("仅定位到告警 sink，完整数据流未能重建")
        else:
            reason_parts.append(f"重构数据流: {summary}")
    if result.get("break_point"):
        reason_parts.append(f"断点: {result['break_point']}")
    finding_db.ai_reason = "\n".join(p for p in reason_parts if p)
    try:
        finding_db.ai_confidence = float(result.get("confidence")) if result.get("confidence") is not None else None
    except (TypeError, ValueError):
        finding_db.ai_confidence = None
    if result.get("message_zh"):
        finding_db.message_zh = result["message_zh"]
    return True
