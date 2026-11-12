"""Generate verification PoC for confirmed vulnerabilities via LLM."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.services.file_service import read_file_with_context
from app.services.llm_audit_service import parse_finding_metadata
from app.services.llm_provider import chat_completion, effective_llm_timeout, extract_json_from_llm_text, is_llm_configured, llm_not_configured_message

logger = logging.getLogger(__name__)

POC_SYSTEM_PROMPT = """你是一名资深渗透测试工程师，为**已确认的真实漏洞**编写可在授权环境中验证的 PoC。

要求：
1. PoC 必须具体、可执行，优先给出 curl / httpie / Python requests 之一
2. 使用占位符：{BASE_URL}、{TOKEN_A}、{TOKEN_B}、{TARGET_ID} 等，并在 prerequisites 中说明如何获取
3. 结合提供的接口路径、参数与代码上下文，不要编造项目中不存在的接口
4. 若信息不足无法写出可靠 PoC，在 steps 中说明缺失信息，并给出尽可能接近的验证思路
5. 必须包含安全提示：仅在获得书面授权的目标环境测试

输出严格 JSON 对象（不要数组）：
{
  "poc_type": "curl" | "httpie" | "python" | "burp" | "manual",
  "title": "PoC 简短标题",
  "prerequisites": "前置条件（账号、权限、环境变量等）",
  "steps": "分步验证说明（中文）",
  "poc_content": "可直接复制执行的 PoC 正文（含占位符）",
  "expected_result": "成功利用时的预期现象",
  "safety_note": "安全与合规提示"
}
只输出 JSON，不要其他文字。"""


def get_stored_poc(finding) -> dict | None:
    meta = parse_finding_metadata(finding.metadata_json)
    poc = meta.get("verification_poc")
    return poc if isinstance(poc, dict) else None


def save_poc_to_finding(finding, poc: dict) -> None:
    meta = parse_finding_metadata(finding.metadata_json)
    meta["verification_poc"] = {
        **poc,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    finding.metadata_json = json.dumps(meta, ensure_ascii=False)


def merge_http_request_into_poc(
    finding,
    http_request: dict,
    poc_content: str | None = None,
) -> dict:
    """Persist a user-edited HTTP request draft without regenerating LLM PoC."""
    meta = parse_finding_metadata(finding.metadata_json)
    poc = meta.get("verification_poc")
    if not isinstance(poc, dict):
        poc = {}
    poc["http_request"] = {
        "method": http_request.get("method") or "GET",
        "url": http_request.get("url") or "",
        "headers": http_request.get("headers") or {},
        "body": http_request.get("body") or "",
    }
    if poc_content is not None:
        poc["poc_content"] = poc_content
    poc["updated_at"] = datetime.now(timezone.utc).isoformat()
    meta["verification_poc"] = poc
    finding.metadata_json = json.dumps(meta, ensure_ascii=False)
    return poc


async def generate_verification_poc(finding, project_path: Path) -> dict:
    """Generate PoC dict for a finding. Raises on missing LLM or parse errors."""
    if not is_llm_configured():
        raise ValueError(llm_not_configured_message())

    meta = parse_finding_metadata(finding.metadata_json)
    rel_path = finding.file_path
    try:
        rel_path = str(Path(finding.file_path).relative_to(project_path))
    except ValueError:
        pass

    code_context = ""
    try:
        ctx = read_file_with_context(
            project_path,
            finding.file_path,
            finding.line_start or 1,
            finding.line_end or finding.line_start or 1,
            context_lines=30,
        )
        code_context = (ctx.get("content") or "")[:3500]
    except Exception:
        code_context = (finding.code_snippet or "")[:2000]

    payload = {
        "title": finding.message,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "category": finding.category.value if hasattr(finding.category, "value") else finding.category,
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "file": rel_path,
        "line": finding.line_start,
        "api_endpoint": meta.get("api_endpoint"),
        "endpoint_code_ref": meta.get("endpoint_code_ref"),
        "data_source": meta.get("data_source"),
        "data_flow": meta.get("data_flow"),
        "trigger_point": meta.get("trigger_point"),
        "attack_scenario": meta.get("attack_scenario"),
        "ai_reason": finding.ai_reason,
        "code_context": code_context,
    }

    user_content = json.dumps(payload, ensure_ascii=False, indent=2)

    try:
        text = await chat_completion(
            [
                {"role": "system", "content": POC_SYSTEM_PROMPT},
                {"role": "user", "content": f"请为以下漏洞生成验证 PoC：\n\n{user_content}"},
            ],
            temperature=0.2,
            max_tokens=4096,
            timeout=effective_llm_timeout(2),
        )
        text = extract_json_from_llm_text(text)
        result = json.loads(text)
        if not isinstance(result, dict):
            raise ValueError("LLM 返回格式无效")
        return result
    except Exception as exc:
        logger.exception("PoC generation failed for finding %s", finding.id)
        raise ValueError(f"PoC 生成失败: {exc}") from exc
