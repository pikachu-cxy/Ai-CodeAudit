"""Account management: DB-backed admin password + real session introspection.

The platform still has a single local admin. Phase 2 adds a *verifiable*
password change that persists a bcrypt hash in ``system_settings`` instead of
rewriting ``.env`` at runtime. ``AUTH_PASSWORD`` remains the bootstrap value and
is used only while no DB override exists.
"""
from __future__ import annotations

import bcrypt
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import RefreshToken
from app.services.auth_service import (
    get_system_setting,
    hash_password,
    set_system_setting,
    verify_password,
)

PASSWORD_HASH_KEY = "auth_password_hash"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")


async def get_password_override(db: AsyncSession) -> str | None:
    """Return the DB-stored bcrypt hash, or ``None`` to fall back to ``.env``."""
    value = await get_system_setting(db, PASSWORD_HASH_KEY)
    text = (value or "").strip()
    return text or None


async def verify_local_password(db: AsyncSession, plain: str) -> bool:
    override = await get_password_override(db)
    if override:
        if not override.startswith(_BCRYPT_PREFIXES):
            return False
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), override.encode("utf-8"))
        except ValueError:
            return False
    return verify_password(plain)


def password_storage_kind(override: str | None) -> str:
    raw = override if override is not None else (settings.auth_password or "")
    return "bcrypt" if (raw or "").strip().startswith(_BCRYPT_PREFIXES) else "plaintext"


async def change_password(
    db: AsyncSession,
    *,
    current: str,
    new: str,
    revoke_sessions: bool = False,
) -> dict[str, object]:
    """Validate + persist a new admin password. Raises ValueError on bad input."""
    if not await verify_local_password(db, current):
        raise ValueError("当前密码不正确")
    if not (MIN_PASSWORD_LENGTH <= len(new) <= MAX_PASSWORD_LENGTH):
        raise ValueError(
            f"新密码长度需为 {MIN_PASSWORD_LENGTH}–{MAX_PASSWORD_LENGTH} 个字符"
        )
    if new == current:
        raise ValueError("新密码不能与当前密码相同")

    await set_system_setting(db, PASSWORD_HASH_KEY, hash_password(new))
    revoked = 0
    if revoke_sessions:
        result = await db.execute(delete(RefreshToken))
        revoked = int(result.rowcount or 0)
    return {
        "password_source": "database",
        "password_storage": "bcrypt",
        "sessions_revoked": revoked,
    }
