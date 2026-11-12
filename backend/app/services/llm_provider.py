"""Unified LLM provider: OpenAI-compatible HTTP API (API Key)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time

from openai import AsyncOpenAI

from app.config import settings

logger = logging.getLogger(__name__)

PROVIDER_OPENAI = "openai"
_LEGACY_CURSOR_CLI = "cursor_cli"


def normalize_provider(raw: str | None) -> str:
    name = (raw or "").strip().lower()
    if name in (_LEGACY_CURSOR_CLI, PROVIDER_OPENAI):
        return PROVIDER_OPENAI
    return PROVIDER_OPENAI


def llm_provider_name() -> str:
    return normalize_provider(settings.llm_provider or PROVIDER_OPENAI)


def resolve_provider(task: str | None = None) -> str:
    """Resolve provider for a task. Legacy cursor_cli values map to openai."""
    key = (task or "").strip().lower()
    overrides = {
        "fp": settings.llm_provider_fp,
        "deep": settings.llm_provider_deep,
        "agent": settings.llm_provider_agent,
    }
    if key in overrides:
        chosen = (overrides[key] or "").strip()
        if chosen:
            return normalize_provider(chosen)
    return llm_provider_name()


def providers_in_use() -> list[str]:
    return [PROVIDER_OPENAI]


def task_for_provider(provider: str) -> str | None:
    target = normalize_provider(provider)
    for task in (None, "fp", "deep", "agent"):
        if resolve_provider(task) == target:
            return task
    return None


def is_llm_configured() -> bool:
    return bool(settings.llm_api_key)


def llm_not_configured_message() -> str:
    return "LLM API 未配置，请在设置中填写 API Base 与 API Key"


def effective_llm_timeout(multiplier: float = 1.0, *, task: str | None = None) -> float:
    _ = task
    return max(30.0, float(settings.llm_timeout) * multiplier)


def resolve_model(task: str | None = None, *, explicit: str | None = None) -> str:
    """Resolve model for a task. explicit wins, then task override, then llm_model."""
    if explicit and explicit.strip():
        return explicit.strip()
    key = (task or "").strip().lower()
    overrides = {
        "fp": settings.llm_model_fp,
        "deep": settings.llm_model_deep,
        "agent": settings.llm_model_agent,
    }
    if key in overrides:
        chosen = (overrides[key] or "").strip()
        if chosen:
            return chosen
    return (settings.llm_model or "gpt-4o-mini").strip() or "gpt-4o-mini"


def _openai_client() -> AsyncOpenAI | None:
    if not settings.llm_api_key:
        return None
    return AsyncOpenAI(
        api_key=settings.llm_api_key,
        base_url=settings.llm_api_base,
        timeout=settings.llm_timeout,
    )


def extract_json_from_llm_text(text: str) -> str:
    """Pull JSON array/object from LLM output that may include prose or markdown fences."""
    text = (text or "").strip()
    if not text:
        return ""

    if "```" in text:
        for segment in text.split("```"):
            chunk = segment.strip()
            if chunk.lower().startswith("json"):
                chunk = chunk[4:].lstrip()
            if chunk.startswith("[") or chunk.startswith("{"):
                return chunk

    array_idx = text.find("[")
    object_idx = text.find("{")
    candidates = [idx for idx in (array_idx, object_idx) if idx >= 0]
    if candidates:
        return text[min(candidates):]
    return text


def _salvage_partial_json_array(raw: str) -> list | None:
    """Parse complete objects from a truncated JSON array (common when output hits token limit)."""
    text = raw.strip()
    if not text.startswith("["):
        return None
    decoder = json.JSONDecoder()
    items: list = []
    idx = 1
    while idx < len(text):
        while idx < len(text) and text[idx] in " \t\n\r,":
            idx += 1
        if idx >= len(text) or text[idx] == "]":
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            if isinstance(obj, dict):
                items.append(obj)
            idx = end
        except json.JSONDecodeError:
            break
    return items or None


def _salvage_partial_json_object(raw: str) -> dict | None:
    """Try to recover findings from a truncated `{"audit_summary":..., "findings":[...` object."""
    text = raw.strip()
    if not text.startswith("{"):
        return None
    for key in ('"findings"', '"issues"'):
        pos = text.find(key)
        if pos < 0:
            continue
        bracket = text.find("[", pos)
        if bracket < 0:
            continue
        items = _salvage_partial_json_array(text[bracket:])
        if items:
            summary = ""
            sm = re.search(r'"audit_summary"\s*:\s*"((?:[^"\\]|\\.)*)"', text)
            if sm:
                summary = sm.group(1)
            return {"audit_summary": summary, "findings": items}
    return None


def _salvage_truncated_finding_blob(raw: str) -> dict | None:
    """Recover one finding when JSON was cut off inside the first object."""
    if '"title"' not in raw:
        return None
    patterns = {
        "category": re.compile(r'"category"\s*:\s*"([^"]*)"'),
        "severity": re.compile(r'"severity"\s*:\s*"([^"]*)"'),
        "title": re.compile(r'"title"\s*:\s*"([^"]*)"'),
        "description": re.compile(r'"description"\s*:\s*"(.*?)(?:"|,|\n|\r|})', re.DOTALL),
        "file": re.compile(r'"file"\s*:\s*"([^"]*)"'),
        "api_endpoint": re.compile(r'"api_endpoint"\s*:\s*"([^"]*)"'),
        "line_start": re.compile(r'"line_start"\s*:\s*(\d+)'),
    }
    fields: dict[str, object] = {}
    for key, pat in patterns.items():
        m = pat.search(raw)
        if m:
            fields[key] = m.group(1).strip()
    title = str(fields.get("title") or "").strip()
    if not title:
        return None
    line_raw = fields.get("line_start")
    try:
        line_start = int(line_raw) if line_raw is not None else 1
    except (TypeError, ValueError):
        line_start = 1
    return {
        "category": str(fields.get("category") or "authorization"),
        "severity": str(fields.get("severity") or "MEDIUM"),
        "title": title,
        "description": str(fields.get("description") or title)[:500],
        "file": str(fields.get("file") or ""),
        "line_start": line_start,
        "line_end": line_start,
        "api_endpoint": str(fields.get("api_endpoint") or ""),
        "confidence": 0.65,
    }


def parse_llm_structured_response(text: str) -> dict | list | None:
    """Parse LLM JSON output; salvage complete items when the response was truncated."""
    raw = extract_json_from_llm_text(text)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        salvaged = _salvage_partial_json_array(raw)
        if salvaged is not None:
            logger.warning("Salvaged %d item(s) from truncated LLM JSON array", len(salvaged))
            return salvaged
        salvaged_obj = _salvage_partial_json_object(raw)
        if salvaged_obj is not None:
            logger.warning(
                "Salvaged %d finding(s) from truncated LLM JSON object",
                len(salvaged_obj.get("findings", [])),
            )
            return salvaged_obj
        one = _salvage_truncated_finding_blob(raw)
        if one is not None:
            logger.warning("Salvaged 1 finding from mid-object truncated LLM JSON")
            return [one]
        return None


async def chat_completion(
    messages: list[dict],
    *,
    model: str | None = None,
    task: str | None = None,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    timeout: float | None = None,
    json_mode: bool = False,
) -> str:
    """Run a chat completion and return assistant text."""
    wait = timeout if timeout is not None else effective_llm_timeout(task=task)
    effective_model = resolve_model(task, explicit=model)

    client = _openai_client()
    if not client:
        raise RuntimeError(llm_not_configured_message())

    create_kwargs: dict = {
        "model": effective_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        create_kwargs["response_format"] = {"type": "json_object"}

    def _timeout_error(cause: BaseException | None = None) -> TimeoutError:
        task_label = task or "default"
        msg = (
            f"LLM 请求超时（>{wait:.0f}s，model={effective_model}，task={task_label}）"
        )
        err = TimeoutError(msg)
        if cause is not None:
            err.__cause__ = cause
        return err

    try:
        response = await asyncio.wait_for(
            client.chat.completions.create(**create_kwargs),
            timeout=wait,
        )
    except (asyncio.TimeoutError, TimeoutError) as exc:
        # Never retry after timeout — json_mode fallback would double the wait.
        raise _timeout_error(exc) from exc
    except Exception as exc:
        if json_mode and create_kwargs.pop("response_format", None) is not None:
            logger.warning("JSON mode not supported by provider, retrying without: %s", exc)
            try:
                response = await asyncio.wait_for(
                    client.chat.completions.create(**create_kwargs),
                    timeout=wait,
                )
            except (asyncio.TimeoutError, TimeoutError) as te:
                raise _timeout_error(te) from te
        else:
            raise
    return (response.choices[0].message.content or "").strip()


def format_llm_exception(exc: BaseException) -> str:
    """Human-readable LLM error; TimeoutError() often has empty str()."""
    msg = str(exc).strip()
    if msg:
        return msg
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return f"LLM 请求超时（>{settings.llm_timeout}s）"
    return type(exc).__name__


async def test_llm_connection() -> dict:
    """Ping the configured OpenAI-compatible API."""
    if not is_llm_configured():
        return {
            "ok": False,
            "message": llm_not_configured_message(),
            "provider": PROVIDER_OPENAI,
        }

    model = settings.llm_model
    started = time.perf_counter()
    try:
        reply = await chat_completion(
            [{"role": "user", "content": "请只回复一个词：OK"}],
            max_tokens=16,
            temperature=0,
            timeout=effective_llm_timeout(),
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": True,
            "message": f"API 连接成功，模型回复: {reply[:80]}",
            "model": model,
            "api_base": settings.llm_api_base,
            "provider": PROVIDER_OPENAI,
            "latency_ms": latency_ms,
        }
    except asyncio.TimeoutError:
        return {
            "ok": False,
            "message": f"API 请求超时（>{settings.llm_timeout}秒）",
            "model": model,
            "api_base": settings.llm_api_base,
            "provider": PROVIDER_OPENAI,
        }
    except Exception as exc:
        logger.exception("LLM API test failed")
        return {
            "ok": False,
            "message": str(exc),
            "model": model,
            "api_base": settings.llm_api_base,
            "provider": PROVIDER_OPENAI,
        }
