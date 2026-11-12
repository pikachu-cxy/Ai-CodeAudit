"""Shared helpers for the Phase 2 platform-management modules.

These modules only manage configuration records and their audit trail. Nothing
here schedules an Agent, launches an MCP process, or changes the scan pipeline.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PlatformAuditLog, dt_iso


def loads_object(raw: str | None) -> dict[str, str]:
    """Parse a stored JSON object, tolerating legacy / corrupted values."""
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def loads_list(raw: str | None) -> list[str]:
    """Parse a stored JSON string list, tolerating legacy / corrupted values."""
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


async def log_action(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | int | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append one audit row. Caller owns the commit/rollback."""
    db.add(
        PlatformAuditLog(
            actor=str(actor or "unknown")[:100],
            action=str(action)[:64],
            target_type=str(target_type)[:32],
            target_id=None if target_id is None else str(target_id)[:64],
            detail=dumps(detail or {}),
        )
    )
    await db.flush()


def serialize_audit_log(row: PlatformAuditLog) -> dict[str, Any]:
    try:
        detail: Any = json.loads(row.detail or "{}")
    except (TypeError, ValueError):
        detail = {}
    return {
        "id": row.id,
        "actor": row.actor,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "detail": detail,
        "created_at": dt_iso(row.created_at),
    }
