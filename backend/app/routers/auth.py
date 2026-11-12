import secrets
import time
from collections import defaultdict, deque
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies.auth import require_auth
from app.schemas import AuthConfigOut, LoginRequest, LoginResponse, UserOut
from app.services.account_service import get_password_override
from app.services.auth_service import (
    ROLE_ADMIN,
    authenticate_user,
    build_sso_authorize_url,
    create_access_token,
    exchange_sso_code,
    get_sso_userinfo,
    get_token_expire_hours,
    lookup_refresh_token,
    refresh_sso_token,
    revoke_refresh_token,
    role_for_legacy_token,
    role_from_sso_userinfo,
    store_refresh_token,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
_LOGIN_FAILURES: dict[str, deque[float]] = defaultdict(deque)
_LOGIN_WINDOW_SECONDS = 60.0
_LOGIN_MAX_FAILURES = 5


def _login_rate_limited(client_id: str) -> bool:
    now = time.monotonic()
    bucket = _LOGIN_FAILURES[client_id]
    while bucket and now - bucket[0] > _LOGIN_WINDOW_SECONDS:
        bucket.popleft()
    return len(bucket) >= _LOGIN_MAX_FAILURES


def _record_login_failure(client_id: str) -> None:
    now = time.monotonic()
    bucket = _LOGIN_FAILURES[client_id]
    bucket.append(now)
    if len(_LOGIN_FAILURES) > 10000:
        stale = [k for k, v in _LOGIN_FAILURES.items() if not v or now - v[-1] > _LOGIN_WINDOW_SECONDS]
        for key in stale[:1000]:
            _LOGIN_FAILURES.pop(key, None)


@router.get("/config", response_model=AuthConfigOut)
async def auth_config():
    sso_login = None
    if settings.sso_enabled and settings.sso_base_url:
        sso_login = "/api/auth/sso/login"
    return AuthConfigOut(
        auth_enabled=settings.auth_enabled,
        username_hint=settings.auth_username if settings.auth_enabled else None,
        sso_enabled=settings.sso_enabled,
        sso_login_url=sso_login,
    )


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    client_id = request.client.host if request.client else "unknown"
    if _login_rate_limited(client_id):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "登录尝试过于频繁，请稍后重试")
    if not settings.auth_enabled:
        return LoginResponse(
            access_token="",
            token_type="bearer",
            username=settings.auth_username or "system",
            role=ROLE_ADMIN,
            auth_enabled=False,
        )

    stored_hash = await get_password_override(db)
    user = authenticate_user(body.username, body.password, stored_hash=stored_hash)
    if not user:
        _record_login_failure(client_id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
    _LOGIN_FAILURES.pop(client_id, None)

    username = user["username"]
    role = user.get("role") or ROLE_ADMIN
    expire_hours = await get_token_expire_hours(db)
    token = create_access_token(username, expire_hours=expire_hours, role=role)
    local_refresh = secrets.token_urlsafe(32)
    await store_refresh_token(
        db, local_refresh, username, sso_refresh_token=None, role=role
    )
    await db.commit()
    return LoginResponse(
        access_token=token,
        refresh_token=local_refresh,
        token_type="bearer",
        expires_in=int(expire_hours * 3600),
        username=username,
        role=role,
        auth_enabled=True,
    )


@router.get("/me", response_model=UserOut)
async def me(user: dict = Depends(require_auth)):
    return UserOut(
        username=user["username"],
        role=user.get("role") or ROLE_ADMIN,
        auth_enabled=settings.auth_enabled,
    )


# ============ SSO OAuth2 Routes ============

@router.get("/sso/login")
async def sso_login():
    if not settings.sso_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO 未启用")
    state = secrets.token_urlsafe(32)
    url = build_sso_authorize_url(state)
    response = RedirectResponse(url=url)
    response.set_cookie(
        "sso_oauth_state",
        state,
        max_age=600,
        httponly=True,
        secure=settings.sso_redirect_uri.lower().startswith("https://"),
        samesite="lax",
    )
    return response


@router.get("/sso/callback")
async def sso_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(""),
    db: AsyncSession = Depends(get_db),
):
    if not settings.sso_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO 未启用")

    expected_state = request.cookies.get("sso_oauth_state")
    if not expected_state or not state or not secrets.compare_digest(state, expected_state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO state 无效或已过期")

    try:
        token_data = await exchange_sso_code(code)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))

    sso_access_token = token_data.get("access_token", "")
    sso_refresh_token = token_data.get("refresh_token")
    if not sso_access_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO 未返回 access_token")

    try:
        userinfo = await get_sso_userinfo(sso_access_token)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))

    username = userinfo.get("name") or userinfo.get("email") or userinfo.get("sub", "")
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO 未返回用户信息")

    role = role_from_sso_userinfo(userinfo)
    expire_hours = await get_token_expire_hours(db)
    local_token = create_access_token(username, expire_hours=expire_hours, role=role)
    local_refresh = secrets.token_urlsafe(32)
    await store_refresh_token(
        db,
        local_refresh,
        username,
        sso_refresh_token=sso_refresh_token,
        role=role,
    )
    await db.commit()

    frontend_url = settings.frontend_base_url or ""
    if frontend_url:
        callback_url = (
            f"{frontend_url.rstrip('/')}/auth/callback"
            f"#access_token={local_token}"
            f"&refresh_token={local_refresh}"
            f"&username={quote(str(username), safe='')}"
            f"&role={role}"
        )
        response = RedirectResponse(url=callback_url)
        response.delete_cookie("sso_oauth_state")
        return response

    response = JSONResponse({
        "access_token": local_token,
        "refresh_token": local_refresh,
        "token_type": "bearer",
        "expires_in": int(expire_hours * 3600),
        "username": username,
        "role": role,
        "auth_enabled": True,
    })
    response.delete_cookie("sso_oauth_state")
    return response


# ============ Refresh Token ============

class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh")
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    entry = await lookup_refresh_token(db, body.refresh_token)
    if not entry:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token 无效或已过期")

    username = entry["username"]
    sso_refresh = entry.get("sso_refresh_token")
    role = entry.get("role") or role_for_legacy_token(username)
    expire_hours = await get_token_expire_hours(db)

    if sso_refresh:
        try:
            new_token_data = await refresh_sso_token(sso_refresh)
        except ValueError as e:
            await revoke_refresh_token(db, body.refresh_token)
            await db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))

        new_sso_access = new_token_data.get("access_token", "")
        new_sso_refresh = new_token_data.get("refresh_token", sso_refresh)
        if new_sso_access:
            try:
                userinfo = await get_sso_userinfo(new_sso_access)
                role = role_from_sso_userinfo(userinfo)
                username = (
                    userinfo.get("name")
                    or userinfo.get("email")
                    or userinfo.get("sub")
                    or username
                )
            except ValueError:
                # Keep stored role/username if userinfo briefly fails
                pass

        new_local_access = create_access_token(
            username, expire_hours=expire_hours, role=role
        )
        new_local_refresh = secrets.token_urlsafe(32)

        await revoke_refresh_token(db, body.refresh_token)
        await store_refresh_token(
            db,
            new_local_refresh,
            username,
            sso_refresh_token=new_sso_refresh,
            role=role,
        )
        await db.commit()

        return {
            "access_token": new_local_access,
            "refresh_token": new_local_refresh,
            "token_type": "bearer",
            "expires_in": int(expire_hours * 3600),
            "role": role,
            "username": username,
        }

    # Local-only refresh: AUTH_USERNAME stays admin; otherwise use stored role
    role = role_for_legacy_token(username) if role_for_legacy_token(username) == ROLE_ADMIN else role
    new_local_access = create_access_token(username, expire_hours=expire_hours, role=role)
    new_local_refresh = secrets.token_urlsafe(32)
    await revoke_refresh_token(db, body.refresh_token)
    await store_refresh_token(
        db, new_local_refresh, username, sso_refresh_token=None, role=role
    )
    await db.commit()

    return {
        "access_token": new_local_access,
        "refresh_token": new_local_refresh,
        "token_type": "bearer",
        "expires_in": int(expire_hours * 3600),
        "role": role,
        "username": username,
    }
