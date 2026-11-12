"""Account management: real identity/security posture, sessions and audit trail.

There is still no ``User`` table, no invitations and no per-project RBAC. This
module deliberately reports that instead of inventing user rows. What it DOES
manage is real: refresh-token sessions, the local admin password and the
platform-management audit log.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies.auth import require_admin
from app.models import PlatformAuditLog, RefreshToken, dt_iso
from app.services.account_service import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    change_password,
    get_password_override,
    password_storage_kind,
)
from app.services.auth_service import (
    get_refresh_token_expire_days,
    get_token_expire_hours,
)
from app.services.platform_service import log_action, serialize_audit_log

router = APIRouter(
    prefix="/api/accounts",
    tags=["accounts"],
    dependencies=[Depends(require_admin)],
)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str
    revoke_sessions: bool = False


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@router.get("/overview")
async def overview(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> dict:
    override = await get_password_override(db)
    count = (
        await db.execute(select(func.count()).select_from(RefreshToken))
    ).scalar_one()
    return {
        "username": user.get("username") or "—",
        "role": user.get("role") or "admin",
        "auth_enabled": bool(settings.auth_enabled),
        "sso_enabled": bool(settings.sso_enabled),
        "password_source": "database" if override else "env",
        "password_storage": password_storage_kind(override),
        "secret_key_configured": len((settings.auth_secret_key or "").strip()) >= 32,
        "token_expire_hours": await get_token_expire_hours(db),
        "refresh_expire_days": await get_refresh_token_expire_days(db),
        "session_count": int(count),
        "user_management_enabled": False,
        "notes": [
            "当前为单管理员模型，没有用户表、邀请或角色分配接口。",
            "修改密码会写入数据库（system_settings），覆盖 .env 的 AUTH_PASSWORD，无需重启服务。",
            "撤销会话只删除 refresh token；已签发的 access token 会在到期前继续有效。",
        ],
    }


@router.get("/sessions")
async def list_sessions(
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(RefreshToken).order_by(RefreshToken.created_at.desc()).limit(200)
    )
    now = datetime.now(timezone.utc)
    items = []
    for row in result.scalars().all():
        expires = _as_utc(row.expire_at)
        items.append(
            {
                "id": row.id,
                "username": row.username,
                "role": row.role,
                "token_hint": f"{str(row.local_refresh_token or '')[:6]}…",
                "sso_linked": bool(row.sso_refresh_token),
                "created_at": dt_iso(row.created_at),
                "expire_at": dt_iso(row.expire_at),
                "expired": bool(expires and expires < now),
            }
        )
    return {"items": items, "total": len(items)}


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> dict:
    result = await db.execute(
        delete(RefreshToken).where(RefreshToken.id == session_id)
    )
    if not result.rowcount:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "会话不存在或已被撤销")
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="account.revoke_session",
        target_type="session",
        target_id=session_id,
    )
    await db.commit()
    return {"ok": True, "id": session_id}


@router.post("/sessions/cleanup")
async def cleanup_sessions(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> dict:
    # Python-side comparison: MySQL/SQLite return naive DATETIME values (see
    # scan_service._as_utc and the /api/auth/refresh incident).
    result = await db.execute(select(RefreshToken))
    now = datetime.now(timezone.utc)
    stale = [
        row
        for row in result.scalars().all()
        if (_as_utc(row.expire_at) or now) < now
    ]
    for row in stale:
        await db.delete(row)
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="account.cleanup_sessions",
        target_type="session",
        detail={"removed": len(stale)},
    )
    await db.commit()
    return {"ok": True, "removed": len(stale)}


@router.post("/password")
async def update_password(
    body: PasswordChangeIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> dict:
    if not settings.auth_enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "认证未启用（AUTH_ENABLED=false），没有可修改的本地密码",
        )
    try:
        result = await change_password(
            db,
            current=body.current_password,
            new=body.new_password,
            revoke_sessions=body.revoke_sessions,
        )
    except ValueError as exc:
        message = str(exc)
        code = (
            status.HTTP_400_BAD_REQUEST
            if "当前密码" in message
            else status.HTTP_422_UNPROCESSABLE_ENTITY
        )
        raise HTTPException(code, message)
    # Never write either password into the audit trail.
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="account.change_password",
        target_type="account",
        target_id=user.get("username"),
        detail={"sessions_revoked": result["sessions_revoked"]},
    )
    await db.commit()
    return {
        "ok": True,
        **result,
        "min_length": MIN_PASSWORD_LENGTH,
        "max_length": MAX_PASSWORD_LENGTH,
    }


@router.get("/audit-logs")
async def audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(PlatformAuditLog)
        .order_by(PlatformAuditLog.id.desc())
        .limit(limit)
    )
    items = [serialize_audit_log(row) for row in result.scalars().all()]
    return {"items": items, "total": len(items)}
