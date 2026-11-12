"""Structured audit journal for LLM endpoint-driven audits."""

from __future__ import annotations

import json
from typing import Any

from app.database import async_session
from app.models import ScanEvent

LLM_AUDIT_PHASE = "llm_audit"


async def log_llm_audit_journal(
    scan_id: int,
    event_type: str,
    payload: dict[str, Any],
    *,
    level: str = "info",
    file_path: str | None = None,
) -> None:
    body = {
        "type": event_type,
        **payload,
    }
    async with async_session() as session:
        session.add(
            ScanEvent(
                scan_id=scan_id,
                level=level,
                phase=LLM_AUDIT_PHASE,
                tool=event_type,
                file_path=file_path,
                message=json.dumps(body, ensure_ascii=False),
            )
        )
        await session.commit()


def parse_journal_message(message: str) -> dict[str, Any] | None:
    try:
        data = json.loads(message)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None
