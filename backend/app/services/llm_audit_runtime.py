"""In-process cancel/pause signals for long-running LLM endpoint audits."""

from __future__ import annotations

_cancel_requested: set[int] = set()


class LlmAuditCancelled(Exception):
    """Raised when user requests pause/cancel during LLM endpoint audit."""


def request_llm_audit_cancel(scan_id: int) -> None:
    _cancel_requested.add(scan_id)


def clear_llm_audit_cancel(scan_id: int) -> None:
    _cancel_requested.discard(scan_id)


def is_llm_audit_cancel_requested(scan_id: int) -> bool:
    return scan_id in _cancel_requested


def check_llm_audit_cancel(scan_id: int) -> None:
    if is_llm_audit_cancel_requested(scan_id):
        raise LlmAuditCancelled("用户已暂停 LLM 端点审计")
