import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.config import settings
from app.models import AiVerdict
from app.services.llm_provider import (
    chat_completion,
    effective_llm_timeout,
    extract_json_from_llm_text,
    is_llm_configured,
    llm_not_configured_message,
)
from app.services.sast_flow_service import enrich_finding_flow

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是一名资深应用安全工程师，负责对 SAST 工具（Semgrep）扫描结果进行误报审计。

对每条漏洞给出分类：
- REAL_VULN：确认可利用或高概率真实漏洞
- FALSE_POSITIVE：明确误报，需说明数据来源/防护措施/不可达原因
- UNCERTAIN：信息不足，需人工复核

若用户提供了 known_suppressions（历史误报抑制库），优先对照 rule_id、file_path、fingerprint_relaxed：
- 若与已知抑制项明显匹配，优先判 FALSE_POSITIVE 并在 reason 中引用历史原因

输出严格 JSON 数组，每项格式：
{
  "finding_id": <number>,
  "verdict": "real_vuln" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reason": "中文简要分析，100字以内",
  "message_zh": "将原始英文漏洞描述翻译为简洁准确的中文"
}
只输出 JSON，不要其他文字。"""

TRANSLATE_PROMPT = """你是一名应用安全工程师。将 Semgrep 漏洞英文描述翻译为简洁准确的中文，保留 CWE、函数名等技术术语。
输出严格 JSON 数组：[{"finding_id": <number>, "message_zh": "中文描述"}, ...]
只输出 JSON，不要其他文字。"""

ProgressCallback = Callable[[str, int], Awaitable[None]]
FP_BATCH_SIZE = 8


async def test_llm_connection() -> dict:
    from app.services.llm_provider import test_llm_connection as _test

    return await _test()


def _skipped_results(findings: list[dict]) -> list[dict]:
    return [
        {
            "finding_id": f["id"],
            "verdict": AiVerdict.SKIPPED.value,
            "confidence": 0.0,
            "reason": llm_not_configured_message(),
        }
        for f in findings
    ]


def _uncertain_results(findings: list[dict], reason: str) -> list[dict]:
    return [
        {
            "finding_id": f["id"],
            "verdict": AiVerdict.UNCERTAIN.value,
            "confidence": 0.0,
            "reason": reason,
        }
        for f in findings
    ]


def _finding_payload(finding: dict, project_path: Path) -> dict:
    rel_path = finding.get("file_path", "")
    try:
        rel_path = str(Path(rel_path).relative_to(project_path))
    except ValueError:
        pass
    return {
        "finding_id": finding["id"],
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "message": finding.get("message"),
        "file": rel_path,
        "line": finding.get("line_start"),
        "code_snippet": (finding.get("code_snippet") or "")[:1500],
        "has_taint_trace": finding.get("has_taint_trace"),
        "data_flow_chain": finding.get("data_flow_chain"),
        "architecture_flow": finding.get("architecture_flow"),
        "flow_code_context": (finding.get("flow_code_context") or "")[:3500],
    }


async def _enrich_finding(finding: dict, project_path: Path) -> dict:
    try:
        return await asyncio.to_thread(enrich_finding_flow, finding, project_path)
    except Exception:
        logger.exception("enrich_finding_flow failed for finding %s", finding.get("id"))
        return finding


async def _analyze_payload_batch(batch: list[dict], *, known_suppressions: list[dict] | None = None) -> list[dict]:
    user_payload: dict = {"findings": batch}
    if known_suppressions:
        user_payload["known_suppressions"] = known_suppressions
    user_content = json.dumps(user_payload, ensure_ascii=False, indent=2)
    text = await chat_completion(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"请分析以下 {len(batch)} 条 SAST 发现。"
                    "如果给出了数据流链路与链路源码上下文，请优先基于链路判断是否真实漏洞。"
                    "若提供了 known_suppressions，请优先参考历史误报记录：\n\n"
                    f"{user_content}"
                ),
            },
        ],
        task="fp",
        temperature=0.1,
        max_tokens=4096,
        timeout=effective_llm_timeout(2, task="fp"),
    )
    text = extract_json_from_llm_text(text)
    results = json.loads(text)
    if isinstance(results, dict):
        results = results.get("findings", [results])
    if not isinstance(results, list):
        results = [results]
    return results


async def analyze_findings(
    findings: list[dict],
    project_path: Path,
    *,
    on_progress: ProgressCallback | None = None,
    batch_size: int = FP_BATCH_SIZE,
    known_suppressions: list[dict] | None = None,
) -> list[dict]:
    """Batch analyze findings with LLM. Each finding dict must have 'id' key."""
    if not is_llm_configured():
        return _skipped_results(findings)

    if on_progress:
        await on_progress(f"误报审计：准备中 / 已提交 {len(findings)} 条", 75)

    enriched: list[dict] = []
    for index, finding in enumerate(findings, start=1):
        enriched.append(await _enrich_finding(finding, project_path))
        if on_progress and (index == len(findings) or index % 5 == 0):
            await on_progress(f"误报审计：分析数据流 {index}/{len(findings)}", 75)

    payload = [_finding_payload(item, project_path) for item in enriched]
    size = max(1, batch_size)
    total_batches = max(1, (len(payload) + size - 1) // size)
    all_results: list[dict] = []

    for batch_index in range(0, len(payload), size):
        batch = payload[batch_index : batch_index + size]
        batch_no = batch_index // size + 1
        percent = min(90, 75 + int(batch_no / total_batches * 15))
        if on_progress:
            await on_progress(
                f"误报审计：{batch_no}/{total_batches} 批（本批 {len(batch)} 条）",
                percent,
            )
        try:
            all_results.extend(await _analyze_payload_batch(batch, known_suppressions=known_suppressions))
        except Exception as exc:
            logger.exception("LLM analysis failed for batch %s/%s", batch_no, total_batches)
            all_results.extend(
                _uncertain_results(
                    [{"id": item["finding_id"]} for item in batch],
                    f"LLM 分析失败: {exc}",
                )
            )

    return all_results


def verdict_from_str(raw: str) -> AiVerdict:
    mapping = {
        "real_vuln": AiVerdict.REAL_VULN,
        "real": AiVerdict.REAL_VULN,
        "false_positive": AiVerdict.FALSE_POSITIVE,
        "fp": AiVerdict.FALSE_POSITIVE,
        "uncertain": AiVerdict.UNCERTAIN,
    }
    return mapping.get((raw or "").lower().replace("-", "_"), AiVerdict.UNCERTAIN)


def normalize_fp_results(results: list[dict]) -> dict[int, dict]:
    by_id: dict[int, dict] = {}
    for r in results:
        fid = r.get("finding_id")
        if fid is None:
            continue
        try:
            by_id[int(fid)] = r
        except (TypeError, ValueError):
            continue
    return by_id


def apply_fp_results(findings_db, results: list[dict]) -> int:
    """Apply LLM false-positive audit results to ORM findings. Returns count updated."""
    by_id = normalize_fp_results(results)
    updated = 0
    for f in findings_db:
        r = by_id.get(f.id)
        if not r:
            continue
        f.ai_verdict = verdict_from_str(r.get("verdict", ""))
        f.ai_reason = r.get("reason")
        f.ai_confidence = r.get("confidence")
        if r.get("message_zh"):
            f.message_zh = r["message_zh"]
        updated += 1
    return updated


async def translate_finding_messages(findings: list[dict]) -> dict[int, str]:
    """Translate English Semgrep messages to Chinese. Each dict needs 'id' and 'message'."""
    if not findings or not is_llm_configured():
        return {}

    payload = [{"finding_id": f["id"], "message": f.get("message", "")} for f in findings]
    user_content = json.dumps(payload, ensure_ascii=False, indent=2)

    try:
        text = await chat_completion(
            [
                {"role": "system", "content": TRANSLATE_PROMPT},
                {"role": "user", "content": f"请翻译以下 {len(payload)} 条漏洞描述：\n\n{user_content}"},
            ],
            temperature=0.1,
            max_tokens=4096,
            timeout=effective_llm_timeout(2),
        )
        text = extract_json_from_llm_text(text)
        results = json.loads(text)
        if isinstance(results, dict):
            results = results.get("findings", [results])
        out: dict[int, str] = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            fid = item.get("finding_id")
            zh = item.get("message_zh")
            if fid is not None and zh:
                try:
                    out[int(fid)] = zh
                except (TypeError, ValueError):
                    pass
        return out
    except Exception as exc:
        logger.exception("LLM translation failed")
        return {}
