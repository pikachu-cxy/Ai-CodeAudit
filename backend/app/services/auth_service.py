"""Authentication: JWT login and password verification."""

import logging
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
_warned_insecure_secret = False


def _secret_key() -> str:
    global _warned_insecure_secret
    key = (settings.auth_secret_key or "").strip()
    if len(key) < 32:
        raise RuntimeError("AUTH_SECRET_KEY must be configured with at least 32 random characters")
    return key


def verify_password(plain_password: str, *, stored_hash: str | None = None) -> bool:
    """Verify the local admin password.

    ``stored_hash`` is a DB-backed bcrypt override (Account Management).
    ``None`` keeps the original behaviour: read AUTH_PASSWORD from settings.
    """
    raw = settings.auth_password if stored_hash is None else stored_hash
    stored = (raw or "").strip()
    if not stored or not plain_password:
        return False
    if stored.startswith("$2a$") or stored.startswith("$2b$"):
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored.encode("utf-8"))
        except ValueError:
            return False
    return secrets.compare_digest(plain_password, stored)


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


ROLE_ADMIN = "admin"
ROLE_USER = "user"


def local_auth_username() -> str:
    return (settings.auth_username or "admin").strip()


def resolve_local_login_role() -> str:
    """Local password login is always break-glass admin."""
    return ROLE_ADMIN


def role_for_legacy_token(username: str) -> str:
    """Old JWTs without role claim: only AUTH_USERNAME maps to admin."""
    if str(username).strip() == local_auth_username():
        return ROLE_ADMIN
    return ROLE_USER


def normalize_role(role: str | None) -> str:
    value = (role or "").strip().lower()
    return ROLE_ADMIN if value == ROLE_ADMIN else ROLE_USER


def _role_token_from_value(raw) -> set[str]:
    roles: set[str] = set()
    if raw is None:
        return roles
    if isinstance(raw, str):
        for part in raw.replace(";", ",").split(","):
            name = part.strip().lower()
            if name:
                roles.add(name)
        return roles
    if isinstance(raw, dict):
        for key in ("name", "code", "role", "id"):
            val = raw.get(key)
            if isinstance(val, str) and val.strip():
                roles.add(val.strip().lower())
                return roles
        return roles
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            roles |= _role_token_from_value(item)
    return roles


def extract_sso_roles(userinfo: dict) -> set[str]:
    """Parse role names from SSO userinfo (roles/role and common object shapes)."""
    roles: set[str] = set()
    if not isinstance(userinfo, dict):
        return roles
    for key in ("roles", "role", "authorities", "groups"):
        if key in userinfo:
            roles |= _role_token_from_value(userinfo.get(key))
    if not roles:
        logger.debug(
            "SSO userinfo has no recognizable role fields; keys=%s",
            sorted(userinfo.keys()),
        )
    return roles


def role_from_sso_userinfo(userinfo: dict) -> str:
    roles = extract_sso_roles(userinfo)
    if ROLE_ADMIN in roles:
        return ROLE_ADMIN
    return ROLE_USER


def authenticate_user(
    username: str, password: str, *, stored_hash: str | None = None
) -> dict | None:
    expected = local_auth_username()
    if username.strip() != expected:
        return None
    if not verify_password(password, stored_hash=stored_hash):
        return None
    return {"username": expected, "role": ROLE_ADMIN}


def create_access_token(
    username: str,
    expire_hours: float | None = None,
    *,
    role: str | None = None,
) -> str:
    hours = expire_hours if expire_hours is not None else settings.auth_token_expire_hours
    expire = datetime.now(timezone.utc) + timedelta(hours=hours)
    resolved = normalize_role(role) if role is not None else role_for_legacy_token(username)
    payload = {"sub": username, "exp": expire, "role": resolved}
    return jwt.encode(payload, _secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        username_str = str(username)
        raw_role = payload.get("role")
        if raw_role is None or str(raw_role).strip() == "":
            role = role_for_legacy_token(username_str)
        else:
            role = normalize_role(str(raw_role))
        return {"username": username_str, "role": role}
    except jwt.PyJWTError:
        return None


# ============ SSO OAuth2 Integration ============

def build_sso_authorize_url(state: str) -> str:
    """Build SSO OAuth2 authorization URL for redirect."""
    base = settings.sso_base_url.rstrip("/")
    params = (
        f"response_type=code"
        f"&client_id={settings.sso_client_id}"
        f"&redirect_uri={settings.sso_redirect_uri}"
        f"&scope=openid+profile"
        f"&state={state}"
    )
    return f"{base}/oauth/authorize?{params}"


async def exchange_sso_code(code: str) -> dict:
    """Exchange SSO authorization code for access token."""
    import httpx
    base = settings.sso_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{base}/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.sso_redirect_uri,
                "client_id": settings.sso_client_id,
                "client_secret": settings.sso_client_secret,
            },
        )
        if resp.status_code != 200:
            logger.error("SSO token exchange failed: %s %s", resp.status_code, resp.text)
            raise ValueError(f"SSO token exchange failed: {resp.status_code}")
        return resp.json()


async def get_sso_userinfo(access_token: str) -> dict:
    """Get user info from SSO using access token."""
    import httpx
    base = settings.sso_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{base}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code != 200:
            logger.error("SSO userinfo failed: %s %s", resp.status_code, resp.text)
            raise ValueError(f"SSO userinfo failed: {resp.status_code}")
        return resp.json()


# ============ Refresh Token Store (Database-backed) ============

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RefreshToken, SystemSetting


async def store_refresh_token(
    db: AsyncSession,
    local_refresh_token: str,
    username: str,
    sso_refresh_token: str | None = None,
    *,
    role: str | None = None,
) -> None:
    expire_at = datetime.now(timezone.utc) + timedelta(days=settings.auth_refresh_token_expire_days)
    resolved = normalize_role(role) if role is not None else role_for_legacy_token(username)
    row = RefreshToken(
        local_refresh_token=local_refresh_token,
        username=username,
        sso_refresh_token=sso_refresh_token,
        role=resolved,
        expire_at=expire_at,
    )
    db.add(row)
    await db.flush()


async def lookup_refresh_token(db: AsyncSession, local_refresh_token: str) -> dict | None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.local_refresh_token == local_refresh_token)
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    # MySQL / SQLite 的 DATETIME 取回来是不带时区的朴素时间，直接拿它跟
    # `datetime.now(timezone.utc)` 比会抛 `TypeError: can't compare offset-naive
    # and offset-aware datetimes`，刷新令牌这条路径整体 500。库里存的一律是 UTC，
    # 补上时区即可（同 `scan_service._as_utc` 的写法）。
    expire_at = row.expire_at
    if expire_at.tzinfo is None:
        expire_at = expire_at.replace(tzinfo=timezone.utc)
    if expire_at < datetime.now(timezone.utc):
        await db.delete(row)
        await db.flush()
        return None
    stored_role = getattr(row, "role", None)
    role = normalize_role(stored_role) if stored_role else role_for_legacy_token(row.username)
    return {
        "username": row.username,
        "sso_refresh_token": row.sso_refresh_token,
        "role": role,
        "expire_at": row.expire_at,
    }


async def revoke_refresh_token(db: AsyncSession, local_refresh_token: str) -> None:
    await db.execute(
        delete(RefreshToken).where(RefreshToken.local_refresh_token == local_refresh_token)
    )
    await db.flush()


async def cleanup_expired_refresh_tokens(db: AsyncSession) -> int:
    result = await db.execute(
        delete(RefreshToken).where(RefreshToken.expire_at < datetime.now(timezone.utc))
    )
    await db.flush()
    return result.rowcount


# ============ System Settings (Database-backed) ============

async def get_system_setting(db: AsyncSession, key: str, default: str | None = None) -> str | None:
    result = await db.execute(
        select(SystemSetting).where(SystemSetting.setting_key == key)
    )
    row = result.scalar_one_or_none()
    if row:
        return row.setting_value
    return default


async def set_system_setting(db: AsyncSession, key: str, value: str) -> None:
    result = await db.execute(
        select(SystemSetting).where(SystemSetting.setting_key == key)
    )
    row = result.scalar_one_or_none()
    if row:
        row.setting_value = value
    else:
        db.add(SystemSetting(setting_key=key, setting_value=value))
    await db.flush()


async def get_token_expire_hours(db: AsyncSession) -> float:
    val = await get_system_setting(db, "auth_token_expire_hours")
    if val is not None:
        try:
            return max(0.5, min(float(val), 168))
        except (ValueError, TypeError):
            pass
    return float(settings.auth_token_expire_hours)


async def get_refresh_token_expire_days(db: AsyncSession) -> int:
    val = await get_system_setting(db, "auth_refresh_token_expire_days")
    if val is not None:
        try:
            return max(1, min(int(val), 365))
        except (ValueError, TypeError):
            pass
    return settings.auth_refresh_token_expire_days


async def refresh_sso_token(sso_refresh_token: str) -> dict:
    """Call SSO /oauth/token with refresh_token grant. Returns new access_token + refresh_token."""
    import httpx
    base = settings.sso_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{base}/oauth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": sso_refresh_token,
                "client_id": settings.sso_client_id,
                "client_secret": settings.sso_client_secret,
            },
        )
        if resp.status_code != 200:
            logger.error("SSO refresh failed: %s %s", resp.status_code, resp.text)
            raise ValueError(f"SSO refresh failed: {resp.status_code}")
        return resp.json()
