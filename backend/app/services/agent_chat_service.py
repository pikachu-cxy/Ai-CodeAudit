from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Finding, ScanEvent, ScanTask, dt_iso
from app.services.agent_tools import TOOL_SPECS, execute_agent_tool, parse_agent_response
from app.services.endpoint_discovery_service import discover_controller_units, list_endpoints_summary
from app.services.llm_provider import chat_completion, effective_llm_timeout, is_llm_configured, llm_not_configured_message
from app.services.scan_service import explain_llm_no_findings

logger = logging.getLogger(__name__)

AGENT_CHAT_PHASE = "agent_chat"
AGENT_USER_TOOL = "agent_user"
AGENT_ASSISTANT_TOOL = "agent_assistant"
AGENT_ACTION_TOOL = "agent_action"

SYSTEM_PROMPT = """你是该安全审计平台内置的**代码审计 Copilot Agent**。

能力：
1) 理解当前扫描结果（SAST / LLM / CodeQL），但**不局限于已有告警**
2) 通过工具主动阅读源码、搜索符号、枚举 HTTP 端点，发现静态工具未覆盖的风险
3) 充分发挥安全专业知识：越权/IDOR、业务逻辑、**AI/LLM 应用安全（Prompt 注入、用户输入直入 messages）**、注入、敏感数据泄露等
4) 给出可执行结论：文件:行号、数据流、攻击场景、修复建议

工作方式：
- 用户问及具体漏洞、模块、接口时，**优先调用工具读代码**，不要仅凭摘要猜测
- 需要同时查看多个相关文件（如 controller + service + util）时，优先使用 `read_files_batch`
- 从端点追到 Service / Agent / Prompt 构建函数，不要停在 Controller 层
- 若存在同名 Controller 多模块实现，对比差异（如 mch vs mgr）
- 对“很多时候是缺了什么”的漏洞，主动检查负向约束：
  1. 是否缺频控/冷却/锁定（验证码、密码重置、登录）
  2. 是否信任客户端金额/积分/价格，而不是服务端重算
  3. JWT/session 是否缺 jti / revocation / session version / 并发策略
  4. URL/回调/文件路径是否缺 allowlist / 协议 / 私网限制
- 信息足够后输出 action=answer；仍需代码证据时继续 action=tool

回答风格：中文、先结论后依据、条目化、不输出 markdown 表格。
"""

AGENT_TOOL_PROMPT = f"""你还可以使用以下工具探索代码库（不依赖 SAST 结果）：
{TOOL_SPECS}
"""

_LLM_DIAGNOSIS_HINTS = (
    "llm没有发现",
    "llm 没有发现",
    "llm没发现",
    "llm 没发现",
    "为什么llm",
    "为啥llm",
    "why llm",
)


def _is_llm_diagnosis_question(text: str) -> bool:
    q = (text or "").strip().lower()
    if not q:
        return False
    if "llm" not in q:
        return False
    return any(token in q for token in _LLM_DIAGNOSIS_HINTS) or (
        ("为什么" in q or "为啥" in q or "原因" in q or "没发现" in q or "没有发现" in q)
    )


def _format_llm_diagnosis(diag: dict) -> str:
    summary = str(diag.get("summary") or "LLM 审计暂无新增发现。").strip()
    code = str(diag.get("code") or "").strip()
    llm_findings = int(diag.get("llm_findings") or 0)
    suggestions = [str(x).strip() for x in list(diag.get("suggestions") or []) if str(x).strip()]
    evidence_rows = list(diag.get("evidence") or [])

    lines = [f"结论：{summary}"]
    if code:
        lines.append(f"原因码：`{code}`")
    lines.append(f"当前 LLM 新增发现：{llm_findings} 条")

    if evidence_rows:
        lines.append("")
        lines.append("依据：")
        for item in evidence_rows[-4:]:
            phase = str(item.get("phase") or "unknown")
            level = str(item.get("level") or "info")
            message = str(item.get("message") or "").strip()
            if message:
                lines.append(f"1. [{phase}/{level}] {message}")

    if suggestions:
        lines.append("")
        lines.append("建议：")
        for tip in suggestions[:3]:
            lines.append(f"1. {tip}")

    lines.append("")
    lines.append("如需我继续深挖代码层原因，可以继续指定模块、入口文件或直接让我补做源码分析。")
    return "\n".join(lines)


async def append_chat_event(session: AsyncSession, scan_id: int, role: str, content: str) -> None:
    tool = AGENT_USER_TOOL if role == "user" else AGENT_ASSISTANT_TOOL
    session.add(
        ScanEvent(
            scan_id=scan_id,
            level="info",
            phase=AGENT_CHAT_PHASE,
            tool=tool,
            message=content[:8000],
        )
    )
    await session.commit()


async def list_chat_messages(session: AsyncSession, scan_id: int, limit: int = 20) -> list[dict]:
    limit = max(1, min(limit, 100))
    rows = (
        await session.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id, ScanEvent.phase == AGENT_CHAT_PHASE)
            .order_by(ScanEvent.id.desc())
            .limit(limit)
        )
    ).scalars().all()
    rows = list(reversed(rows))
    messages: list[dict] = []
    for e in rows:
        role = "assistant" if e.tool == AGENT_ASSISTANT_TOOL else "user"
        messages.append(
            {
                "role": role,
                "content": e.message,
                "created_at": dt_iso(e.created_at) or "",
            }
        )
    return messages


async def append_action_event(session: AsyncSession, scan_id: int, action: str, result: str | None) -> None:
    payload = {"action": action, "result": result or ""}
    session.add(
        ScanEvent(
            scan_id=scan_id,
            level="info",
            phase=AGENT_CHAT_PHASE,
            tool=AGENT_ACTION_TOOL,
            message=json.dumps(payload, ensure_ascii=False),
        )
    )
    await session.commit()


async def list_action_events(session: AsyncSession, scan_id: int, limit: int = 12) -> list[dict]:
    limit = max(1, min(limit, 100))
    rows = (
        await session.execute(
            select(ScanEvent)
            .where(
                ScanEvent.scan_id == scan_id,
                ScanEvent.phase == AGENT_CHAT_PHASE,
                ScanEvent.tool == AGENT_ACTION_TOOL,
            )
            .order_by(ScanEvent.id.desc())
            .limit(limit)
        )
    ).scalars().all()
    rows = list(reversed(rows))
    out: list[dict] = []
    for e in rows:
        action = ""
        result = ""
        try:
            data = json.loads(e.message or "{}")
            if isinstance(data, dict):
                action = str(data.get("action") or "")
                result = str(data.get("result") or "")
        except Exception:
            pass
        if not action:
            continue
        out.append(
            {
                "action": action,
                "result": result,
                "created_at": dt_iso(e.created_at) or "",
            }
        )
    return out


async def _build_scan_context(session: AsyncSession, scan_id: int) -> str:
    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return "扫描不存在。"

    findings = (
        await session.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id.desc()).limit(100))
    ).scalars().all()
    by_tool: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in findings:
        by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
        by_verdict[f.ai_verdict.value] = by_verdict.get(f.ai_verdict.value, 0) + 1
        by_category[f.category.value] = by_category.get(f.category.value, 0) + 1

    top_findings = []
    for f in findings[:8]:
        top_findings.append(
            {
                "id": f.id,
                "tool": f.tool,
                "category": f.category.value,
                "severity": f.severity.value,
                "rule_id": f.rule_id,
                "message": f.message_zh or f.message,
                "file": Path(f.file_path).name,
                "line": f.line_start,
                "ai_verdict": f.ai_verdict.value,
            }
        )

    endpoint_hint: dict = {}
    project_path = Path(scan.project_path)
    if project_path.is_dir():
        try:
            units = discover_controller_units(project_path)
            sensitive = list_endpoints_summary(project_path, limit=15)
            endpoint_hint = {
                "controller_count": len(units),
                "top_sensitive_endpoints": sensitive[:10],
            }
        except Exception:
            endpoint_hint = {"error": "端点索引失败"}

    context = {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "status": scan.status.value,
            "progress": scan.progress,
            "progress_message": scan.progress_message,
            "total_findings": scan.total_findings,
            "project_path": scan.project_path,
        },
        "by_tool": by_tool,
        "by_verdict": by_verdict,
        "by_category": by_category,
        "top_findings": top_findings,
        "endpoint_index": endpoint_hint,
        "note": "SAST 结果可能不完整；可用工具直接读源码补盲。",
    }
    return json.dumps(context, ensure_ascii=False, indent=2)


async def answer_scan_chat(
    session: AsyncSession,
    scan_id: int,
    user_message: str,
    *,
    max_history: int = 12,
    action_result: str | None = None,
) -> str:
    if _is_llm_diagnosis_question(user_message):
        try:
            diag = await explain_llm_no_findings(session, scan_id)
            return _format_llm_diagnosis(diag)
        except ValueError:
            return "扫描不存在。"

    if not is_llm_configured():
        if action_result:
            return f"{action_result}\n\n（{llm_not_configured_message()}）"
        return llm_not_configured_message()

    scan = await session.get(ScanTask, scan_id)
    if not scan:
        return "扫描不存在。"

    project_path = Path(scan.project_path)
    history = await list_chat_messages(session, scan_id, limit=max_history)
    context = await _build_scan_context(session, scan_id)
    action_prefix = f"系统动作执行结果：{action_result}\n\n" if action_result else ""

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": AGENT_TOOL_PROMPT},
        {"role": "system", "content": f"当前扫描上下文（JSON）:\n{context}"},
    ]
    for m in history[-max_history:]:
        messages.append({"role": m["role"], "content": m["content"]})
    messages.append({"role": "user", "content": action_prefix + user_message})

    # Note: previously this was user-configurable (llm_agent_max_tool_rounds).
    # We keep a high internal ceiling only to prevent infinite loops.
    max_rounds = 200
    last_text = ""

    for round_no in range(max_rounds):
        try:
            last_text = await chat_completion(
                messages,
                task="agent",
                temperature=0.15,
                max_tokens=min(settings.llm_audit_max_tokens, 3000),
                timeout=effective_llm_timeout(4, task="agent"),
            )
        except Exception as exc:
            fallback = f"对话 Agent 调用失败: {exc}"
            if action_result:
                return f"{action_result}\n\n{fallback}"
            return fallback

        parsed = parse_agent_response(last_text)
        if not parsed:
            return last_text or "已收到。"

        if parsed["action"] == "answer":
            content = (parsed.get("content") or "").strip()
            return content or last_text

        if parsed["action"] == "tool" and project_path.is_dir():
            tool_name = parsed.get("tool") or ""
            tool_args = parsed.get("arguments") or {}
            tool_result = await asyncio.to_thread(
                execute_agent_tool,
                project_path,
                tool_name,
                tool_args,
                scan_id=scan_id,
            )
            logger.info("Agent tool round %s: %s %s", round_no + 1, tool_name, tool_args)

            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": f"工具 `{tool_name}` 返回:\n{tool_result}\n\n请继续调查或输出最终 answer JSON。",
                }
            )
            continue

        return last_text or "已收到。"

    return (
        (last_text + "\n\n（对话调查已达到内部安全上限。若需要继续，请重试或提供更具体的入口/函数名。）")
        if last_text
        else "对话调查已达到内部安全上限，请重试。"
    )
