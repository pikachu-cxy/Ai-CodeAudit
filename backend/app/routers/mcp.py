"""MCP server registry — real CRUD plus a real (guarded) connection probe.

Boundaries:
* HTTP/SSE endpoints are tested with an actual JSON-RPC ``initialize`` request.
  ``assert_public_url`` blocks loopback / private / metadata addresses first.
* stdio servers are NOT executed. The probe returns ``not_executed`` instead of
  pretending to be connected.
* Credential-like headers are refused on write; no secret is ever stored.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies.auth import require_admin
from app.models import McpServer, dt_iso
from app.services.platform_service import dumps, loads_list, loads_object, log_action
from app.services.poc_http import PocTargetError, assert_public_url

router = APIRouter(
    prefix="/api/mcp",
    tags=["mcp"],
    dependencies=[Depends(require_admin)],
)

TRANSPORTS = ("http", "sse", "stdio")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_SECRET_HEADER_MARKERS = (
    "authorization",
    "proxy-authorization",
    "api-key",
    "apikey",
    "x-api-key",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "credential",
    "password",
)
_HOP_BY_HOP = frozenset({
    "host", "content-length", "connection", "transfer-encoding",
    "keep-alive", "upgrade", "te", "trailer", "proxy-connection",
})
_INITIALIZE_PAYLOAD = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "ai-audit", "version": "2.0"},
    },
}


class McpServerIn(BaseModel):
    slug: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    transport: str = "http"
    endpoint: str = ""
    command: str = ""
    args: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: int = 5
    enabled: bool = False


class McpServerUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    transport: str | None = None
    endpoint: str | None = None
    command: str | None = None
    args: list[str] | None = None
    headers: dict[str, str] | None = None
    timeout_seconds: int | None = None
    enabled: bool | None = None


class McpServerOut(BaseModel):
    id: int
    slug: str
    name: str
    description: str
    transport: str
    endpoint: str
    command: str
    args: list[str]
    headers: dict[str, str]
    timeout_seconds: int
    enabled: bool
    last_test_at: str | None = None
    last_test_ok: bool | None = None
    last_test_message: str = ""
    last_test_latency_ms: int | None = None
    created_at: str | None = None
    updated_at: str | None = None


class McpTestOut(BaseModel):
    ok: bool
    status: str
    message: str
    latency_ms: int | None = None
    checked_at: str | None = None
    server_info: dict | None = None


def _validate_slug(value: str) -> str:
    slug = str(value or "").strip().lower()
    if not _SLUG_RE.match(slug):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "标识只能包含小写字母、数字、- 和 _，长度 2–64，且以字母或数字开头",
        )
    return slug


def _validate_headers(headers: dict[str, str]) -> None:
    if len(headers) > 16:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "自定义 Header 最多 16 项")
    for raw_key, raw_value in headers.items():
        key = str(raw_key or "").strip().lower()
        if not key:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Header 名称不能为空")
        if key in _HOP_BY_HOP:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"不允许设置逐跳 Header：{raw_key}"
            )
        if any(marker in key for marker in _SECRET_HEADER_MARKERS):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"当前版本不保存凭据类 Header（{raw_key}）。请勿在此处填写令牌或密钥。",
            )
        if len(str(raw_value or "")) > 256:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Header 值不能超过 256 个字符")


def _validate_fields(data: dict, *, full: dict | None = None) -> None:
    def bad(message: str) -> None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, message)

    merged = {**(full or {}), **data}
    if "name" in data and not str(data["name"] or "").strip():
        bad("名称不能为空")
    if "name" in data and len(str(data["name"])) > 128:
        bad("名称不能超过 128 个字符")
    if "transport" in data and data["transport"] not in TRANSPORTS:
        bad(f"传输方式必须是以下之一：{', '.join(TRANSPORTS)}")
    if "description" in data and len(str(data["description"] or "")) > 2000:
        bad("描述不能超过 2000 个字符")
    if "endpoint" in data and len(str(data["endpoint"] or "")) > 512:
        bad("Endpoint 不能超过 512 个字符")
    if "command" in data and len(str(data["command"] or "")) > 512:
        bad("命令不能超过 512 个字符")
    if "timeout_seconds" in data:
        try:
            seconds = int(data["timeout_seconds"])
        except (TypeError, ValueError):
            bad("超时时间必须是整数")
            return
        if not 1 <= seconds <= 30:
            bad("超时时间需在 1–30 秒之间")
    if "enabled" in data and not isinstance(data["enabled"], bool):
        bad("enabled 必须是布尔值")
    if "args" in data:
        args = data["args"]
        if not isinstance(args, list) or len(args) > 32:
            bad("启动参数最多 32 项")
        if any(len(str(item)) > 256 for item in args):
            bad("单个启动参数不能超过 256 个字符")
    if "headers" in data:
        if not isinstance(data["headers"], dict):
            bad("Headers 必须是对象")
        _validate_headers(data["headers"])

    transport = merged.get("transport", "http")
    if transport in ("http", "sse"):
        endpoint = str(merged.get("endpoint") or "").strip()
        if full is None or "endpoint" in data or "transport" in data:
            if not endpoint:
                bad(f"{transport} 传输必须填写 Endpoint")
            if not endpoint.lower().startswith(("http://", "https://")):
                bad("Endpoint 必须以 http:// 或 https:// 开头")
    elif transport == "stdio" and (full is None or "command" in data or "transport" in data):
        if not str(merged.get("command") or "").strip():
            bad("stdio 传输必须填写命令")


def _to_out(row: McpServer) -> McpServerOut:
    return McpServerOut(
        id=row.id,
        slug=row.slug,
        name=row.name,
        description=row.description or "",
        transport=row.transport,
        endpoint=row.endpoint or "",
        command=row.command or "",
        args=loads_list(row.args_json),
        headers=loads_object(row.headers_json),
        timeout_seconds=row.timeout_seconds,
        enabled=bool(row.enabled),
        last_test_at=dt_iso(row.last_test_at),
        last_test_ok=row.last_test_ok,
        last_test_message=row.last_test_message or "",
        last_test_latency_ms=row.last_test_latency_ms,
        created_at=dt_iso(row.created_at),
        updated_at=dt_iso(row.updated_at),
    )


async def _get_row(db: AsyncSession, server_id: int) -> McpServer:
    row = await db.get(McpServer, server_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP Server 不存在")
    return row


async def _probe_http(row: McpServer) -> McpTestOut:
    try:
        url = await asyncio.to_thread(assert_public_url, row.endpoint)
    except PocTargetError as exc:
        return McpTestOut(ok=False, status="blocked", message=f"SSRF 防护拦截：{exc}")

    headers = dict(loads_object(row.headers_json))
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json, text/event-stream"
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=float(row.timeout_seconds), follow_redirects=False
        ) as client:
            response = await client.post(url, json=_INITIALIZE_PAYLOAD, headers=headers)
        latency = int((time.perf_counter() - started) * 1000)
    except (httpx.HTTPError, OSError) as exc:
        latency = int((time.perf_counter() - started) * 1000)
        return McpTestOut(
            ok=False,
            status="unreachable",
            message=f"连接失败：{type(exc).__name__}: {str(exc)[:220]}",
            latency_ms=latency,
        )

    if response.status_code >= 400:
        return McpTestOut(
            ok=False,
            status="http_error",
            message=f"服务端返回 HTTP {response.status_code}（未建立 MCP 会话）",
            latency_ms=latency,
        )
    try:
        payload = response.json()
    except ValueError:
        return McpTestOut(
            ok=False,
            status="protocol_error",
            message="响应不是有效 JSON，无法确认 JSON-RPC initialize 握手",
            latency_ms=latency,
        )
    if not isinstance(payload, dict) or not (payload.get("result") or payload.get("error")):
        return McpTestOut(
            ok=False,
            status="protocol_error",
            message="响应缺少 JSON-RPC result/error，无法确认握手",
            latency_ms=latency,
        )
    if payload.get("error"):
        return McpTestOut(
            ok=False,
            status="protocol_error",
            message=f"JSON-RPC 返回错误：{str(payload['error'])[:220]}",
            latency_ms=latency,
        )
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    return McpTestOut(
        ok=True,
        status="connected",
        message="JSON-RPC initialize 握手成功（仅验证连通性，未枚举或调用工具）",
        latency_ms=latency,
        server_info={
            "protocolVersion": str(result.get("protocolVersion") or ""),
            "server_name": str(
                (result.get("serverInfo") or {}).get("name", "")
                if isinstance(result.get("serverInfo"), dict)
                else ""
            ),
        },
    )


@router.get("/capabilities")
async def capabilities() -> dict:
    """Real support/security facts for the UI; no invented connection state."""
    return {
        "transports": list(TRANSPORTS),
        "stdio_execution_enabled": False,
        "credential_storage_enabled": False,
        "ssrf_guard": "assert_public_url (loopback / private / metadata blocked)",
        "redirects_followed": False,
        "probe": "HTTP POST JSON-RPC initialize; no tool enumeration or invocation",
        "note": (
            "连接测试只做一次真实的 initialize 握手，不枚举工具、不执行工具、"
            "不启动 stdio 进程，也不保存任何凭据。内网地址会被 SSRF 防护拦截。"
        ),
    }


@router.get("/servers", response_model=list[McpServerOut])
async def list_servers(db: AsyncSession = Depends(get_db)) -> list[McpServerOut]:
    result = await db.execute(select(McpServer).order_by(McpServer.id.asc()))
    return [_to_out(row) for row in result.scalars().all()]


@router.post("/servers", response_model=McpServerOut, status_code=status.HTTP_201_CREATED)
async def create_server(
    body: McpServerIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> McpServerOut:
    slug = _validate_slug(body.slug)
    data = body.model_dump()
    _validate_fields(data)
    existing = await db.execute(select(McpServer.id).where(McpServer.slug == slug))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"标识 {slug} 已存在")

    row = McpServer(
        slug=slug,
        name=str(data["name"]).strip(),
        description=data["description"],
        transport=data["transport"],
        endpoint=str(data["endpoint"] or "").strip(),
        command=str(data["command"] or "").strip(),
        args_json=dumps(list(data["args"])),
        headers_json=dumps(dict(data["headers"])),
        timeout_seconds=int(data["timeout_seconds"]),
        enabled=bool(data["enabled"]),
    )
    db.add(row)
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="mcp.create",
        target_type="mcp_server",
        target_id=slug,
        detail={"transport": row.transport, "enabled": bool(row.enabled)},
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.put("/servers/{server_id}", response_model=McpServerOut)
async def update_server(
    server_id: int,
    body: McpServerUpdate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> McpServerOut:
    row = await _get_row(db, server_id)
    data = body.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "没有需要更新的字段")
    _validate_fields(
        data,
        full={
            "transport": row.transport,
            "endpoint": row.endpoint,
            "command": row.command,
        },
    )
    mapping = {
        "args": lambda value: dumps(list(value)),
        "headers": lambda value: dumps(dict(value)),
        "name": lambda value: str(value).strip(),
        "endpoint": lambda value: str(value or "").strip(),
        "command": lambda value: str(value or "").strip(),
        "timeout_seconds": int,
    }
    for key, value in data.items():
        column = {"args": "args_json", "headers": "headers_json"}.get(key, key)
        setattr(row, column, mapping[key](value) if key in mapping else value)
    # Changing the target invalidates the previous probe result.
    if any(key in data for key in ("endpoint", "command", "transport", "headers", "args")):
        row.last_test_at = None
        row.last_test_ok = None
        row.last_test_message = "配置已变更，需要重新测试"
        row.last_test_latency_ms = None
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="mcp.update",
        target_type="mcp_server",
        target_id=row.slug,
        detail={"fields": sorted(data.keys())},
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.delete("/servers/{server_id}")
async def delete_server(
    server_id: int,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> dict:
    row = await _get_row(db, server_id)
    slug, name = row.slug, row.name
    await db.delete(row)
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="mcp.delete",
        target_type="mcp_server",
        target_id=slug,
        detail={"name": name},
    )
    await db.commit()
    return {"ok": True, "id": server_id, "slug": slug}


@router.post("/servers/{server_id}/test", response_model=McpTestOut)
async def test_server(
    server_id: int,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> McpTestOut:
    row = await _get_row(db, server_id)
    if row.transport == "stdio":
        result = McpTestOut(
            ok=False,
            status="not_executed",
            message="stdio 传输需要启动本地进程，当前版本未开放命令执行，因此没有进行连接测试。",
        )
    elif not str(row.endpoint or "").strip():
        result = McpTestOut(ok=False, status="invalid", message="尚未配置 Endpoint")
    else:
        result = await _probe_http(row)

    result.checked_at = dt_iso(datetime.now(timezone.utc))
    row.last_test_at = datetime.now(timezone.utc)
    row.last_test_ok = result.ok
    row.last_test_message = result.message
    row.last_test_latency_ms = result.latency_ms
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="mcp.test",
        target_type="mcp_server",
        target_id=row.slug,
        detail={"ok": result.ok, "status": result.status},
    )
    await db.commit()
    return result
