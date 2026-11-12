"""Derive LLM endpoint audit coverage from journal events and scan status."""

from __future__ import annotations

import json
from typing import Any

from app.config import settings

LLM_AUDIT_PHASE = "llm_audit"

# Map LLM focus area -> OWASP id for A04 business_logic cross-check
FOCUS_TO_OWASP: dict[str, str] = {
    "authz": "A01",
    "business_logic": "A04",
    "ai_prompt": "A03",
    "injection": "A03",
    "rce_command": "A03",
    "deserialization": "A08",
    "ssrf": "A10",
    "sensitive_data": "A02",
}

LLM_AUDIT_FOCUS_ALLOWED = (
    "authz",
    "business_logic",
    "ai_prompt",
    "injection",
    "rce_command",
    "deserialization",
    "ssrf",
    "sensitive_data",
)

LLM_AUDIT_FOCUS_LABELS = {
    "authz": "越权 / 鉴权",
    "business_logic": "业务逻辑",
    "ai_prompt": "AI / Prompt 注入",
    "injection": "注入类（SQL/命令/表达式等）",
    "rce_command": "命令执行 / RCE（端点反推）",
    "deserialization": "不安全反序列化（端点反推）",
    "ssrf": "SSRF / 外联",
    "sensitive_data": "敏感数据泄露",
}


def _parse_journal_payload(message: str | None) -> dict[str, Any] | None:
    if not message:
        return None
    try:
        data = json.loads(message)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None


def extract_llm_meta_from_events(events: list[Any]) -> dict[str, Any]:
    """Parse llm_audit phase events into coverage meta (no DB)."""
    audited_focus: set[str] = set()
    overall_status = "not_run"
    ran = False

    for ev in events:
        payload = _parse_journal_payload(getattr(ev, "message", None))
        if not payload:
            continue
        event_type = str(payload.get("type") or getattr(ev, "tool", "") or "")
        if event_type == "bootstrap_done":
            areas = payload.get("focus_areas")
            if isinstance(areas, list):
                for a in areas:
                    audited_focus.add(str(a).strip().lower())
        elif event_type == "complete":
            ran = True
            overall_status = "completed"
        elif event_type == "cancelled":
            ran = True
            overall_status = "cancelled"

    return {
        "audited_focus": sorted(audited_focus),
        "status": overall_status,
        "ran": ran,
    }


def build_llm_audit_coverage(
    *,
    scan_status: str | None = None,
    llm_audit_meta: dict[str, Any] | None = None,
    configured_focus: list[str] | None = None,
) -> dict[str, Any]:
    configured = configured_focus if configured_focus is not None else list(
        settings.llm_audit_focus_areas or []
    )
    configured_set = {str(x).strip().lower() for x in configured if str(x).strip()}

    meta = llm_audit_meta or {}
    audited_set = {str(x).strip().lower() for x in (meta.get("audited_focus") or [])}
    overall_status = str(meta.get("status") or "not_run")
    ran = bool(meta.get("ran"))

    status_str = str(scan_status or "")
    if status_str == "llm_auditing":
        overall_status = "running"
        ran = True
    elif not ran and status_str in ("completed", "failed"):
        # LLM may not have run; keep not_run unless journal says otherwise
        pass

    # Do NOT invent audited focus from settings when journal lacks bootstrap evidence.
    # Missing focus_areas → keep audited_set empty (partial honesty over false greens).

    focus_out: list[dict[str, Any]] = []
    for focus_id in LLM_AUDIT_FOCUS_ALLOWED:
        label = LLM_AUDIT_FOCUS_LABELS.get(focus_id, focus_id)
        if focus_id in audited_set:
            status = "audited"
            note = "本次 LLM 端点审计已覆盖"
        elif focus_id in configured_set:
            if overall_status == "running":
                status = "configured"
                note = "已配置，审计进行中"
            elif ran:
                status = "skipped"
                note = "本次审计未纳入该重点（journal 无 focus 证据）" if not audited_set else "本次审计未纳入该重点"
            else:
                status = "configured"
                note = "已在设置中启用，本次未执行 LLM 审计"
        else:
            status = "not_run"
            note = "未在设置中启用"

        focus_out.append({
            "id": focus_id,
            "label": label,
            "status": status,
            "note": note,
        })

    return {
        "ran": ran or overall_status == "running",
        "status": overall_status,
        "focus_areas": focus_out,
        "audited_focus": sorted(audited_set),
    }


async def batch_load_llm_audit_meta(
    db: Any,
    scan_ids: list[int],
) -> dict[int, dict[str, Any]]:
    """Batch load journal-derived LLM meta for many scans (single query)."""
    if not scan_ids:
        return {}

    from sqlalchemy import select

    from app.models import ScanEvent

    stmt = (
        select(ScanEvent)
        .where(
            ScanEvent.scan_id.in_(scan_ids),
            ScanEvent.phase == LLM_AUDIT_PHASE,
        )
        .order_by(ScanEvent.id.asc())
    )
    result = await db.execute(stmt)
    rows = result.scalars().all()

    by_scan: dict[int, list[Any]] = {sid: [] for sid in scan_ids}
    for row in rows:
        if row.scan_id in by_scan:
            by_scan[row.scan_id].append(row)

    return {sid: extract_llm_meta_from_events(by_scan[sid]) for sid in scan_ids}
