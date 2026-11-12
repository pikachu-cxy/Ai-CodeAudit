"""Parse and execute HTTP PoC requests with public-only SSRF controls."""

from __future__ import annotations

import ipaddress
import re
import shlex
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlparse

ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
BLOCKED_HEADER_NAMES = frozenset({
    "host",
    "transfer-encoding",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
})
MAX_BODY_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SEC = 10.0
MAX_REDIRECTS = 3
CGNAT = ipaddress.ip_network("100.64.0.0/10")
METADATA_V4 = ipaddress.ip_address("169.254.169.254")
_PLACEHOLDER_RE = re.compile(r"\{[A-Z][A-Z0-9_]*\}")


class PocTargetError(ValueError):
    """Raised when the target URL is not a permitted public address."""


def normalize_http_request(
    method: str | None,
    url: str | None,
    headers: dict[str, str] | list | None,
    body: str | None,
) -> dict[str, Any]:
    verb = str(method or "GET").strip().upper() or "GET"
    if verb not in ALLOWED_METHODS:
        raise PocTargetError(f"不支持的 HTTP 方法: {verb}")
    hdrs = _normalize_headers(headers)
    raw_body = body if body is not None else ""
    if isinstance(raw_body, bytes):
        raw_body = raw_body.decode("utf-8", errors="replace")
    raw_body = str(raw_body)
    if len(raw_body.encode("utf-8")) > MAX_BODY_BYTES:
        raise PocTargetError(f"请求体超过 {MAX_BODY_BYTES} 字节上限")
    return {
        "method": verb,
        "url": str(url or "").strip(),
        "headers": hdrs,
        "body": raw_body,
    }


def http_request_from_poc(poc: dict | None, api_endpoint: str | None = None) -> dict[str, Any]:
    stored: dict[str, Any] = {}
    if isinstance(poc, dict):
        raw = poc.get("http_request")
        if isinstance(raw, dict) and str(raw.get("url") or "").strip():
            return normalize_http_request(
                raw.get("method"),
                raw.get("url"),
                raw.get("headers"),
                raw.get("body"),
            )
        parsed = parse_poc_content(str(poc.get("poc_content") or ""))
        if parsed and str(parsed.get("url") or "").strip():
            stored = parsed
    if not stored.get("url"):
        seeded = seed_from_api_endpoint(api_endpoint)
        if seeded:
            stored = {**seeded, **{k: v for k, v in stored.items() if v}}
    if not stored:
        stored = {"method": "GET", "url": "", "headers": {}, "body": ""}
    return normalize_http_request(
        stored.get("method"),
        stored.get("url"),
        stored.get("headers"),
        stored.get("body"),
    )


def seed_from_api_endpoint(api_endpoint: str | None) -> dict[str, Any] | None:
    text = str(api_endpoint or "").strip()
    if not text or text.lower() in ("unknown", "n/a", "-"):
        return None
    parts = text.split(None, 1)
    method = "GET"
    rest = text
    if parts and parts[0].upper() in ALLOWED_METHODS:
        method = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""
    rest = rest.strip()
    if rest.startswith(("http://", "https://")):
        url = rest
    elif rest.startswith("/"):
        url = rest
    elif rest:
        url = rest if "://" in rest else f"/{rest.lstrip('/')}"
    else:
        url = ""
    return {"method": method, "url": url, "headers": {}, "body": ""}


def parse_poc_content(text: str) -> dict[str, Any] | None:
    raw = (text or "").strip()
    if not raw:
        return None
    if raw.lower().lstrip().startswith("curl"):
        parsed = _parse_curl(raw)
        if parsed:
            return parsed
    http_parsed = _parse_raw_http(raw)
    if http_parsed:
        return http_parsed
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            return {"method": "GET", "url": line.split()[0], "headers": {}, "body": ""}
    return None


def assert_public_url(url: str, *, resolve_dns: bool = True) -> str:
    text = str(url or "").strip()
    if not text:
        raise PocTargetError("请填写完整的 http(s) URL")
    if _PLACEHOLDER_RE.search(text):
        raise PocTargetError("URL 仍含占位符，请替换为真实公网地址后再发送")
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise PocTargetError("仅允许 http / https 协议")
    if parsed.username or parsed.password:
        raise PocTargetError("不允许在 URL 中携带用户名或密码")
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise PocTargetError("URL 缺少主机名")
    _assert_host_not_blocked(host)
    if resolve_dns:
        _assert_resolved_ips_public(host)
    return text


def execute_http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT_SEC,
    resolve_dns: bool = True,
) -> dict[str, Any]:
    req = normalize_http_request(method, url, headers, body)
    target = req["url"]
    if not target.startswith(("http://", "https://")):
        raise PocTargetError("请填写完整的 http(s) URL（含协议）")
    assert_public_url(target, resolve_dns=resolve_dns)

    data = None
    if req["method"] not in ("GET", "HEAD") and req["body"]:
        data = req["body"].encode("utf-8")

    request = urllib.request.Request(
        target,
        data=data,
        method=req["method"],
        headers=req["headers"],
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _SafeRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    started = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) > MAX_RESPONSE_BYTES
            raw = raw[:MAX_RESPONSE_BYTES]
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
            return {
                "ok": True,
                "status_code": int(getattr(resp, "status", None) or resp.getcode() or 0),
                "elapsed_ms": elapsed_ms,
                "headers": resp_headers,
                "body": _decode_body(raw),
                "truncated": truncated,
                "final_url": str(resp.geturl() or target),
                "error": None,
            }
    except PocTargetError:
        raise
    except urllib.error.HTTPError as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        try:
            raw = exc.read(MAX_RESPONSE_BYTES + 1)
        except Exception:
            raw = b""
        truncated = len(raw) > MAX_RESPONSE_BYTES
        raw = raw[:MAX_RESPONSE_BYTES]
        hdrs = {str(k): str(v) for k, v in (exc.headers.items() if exc.headers else [])}
        return {
            "ok": True,
            "status_code": int(exc.code or 0),
            "elapsed_ms": elapsed_ms,
            "headers": hdrs,
            "body": _decode_body(raw),
            "truncated": truncated,
            "final_url": str(exc.url or target),
            "error": None,
        }
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": False,
            "status_code": None,
            "elapsed_ms": elapsed_ms,
            "headers": {},
            "body": "",
            "truncated": False,
            "final_url": target,
            "error": str(exc)[:500],
        }


def headers_to_text(headers: dict[str, str] | None) -> str:
    if not headers:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def text_to_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return _normalize_headers(headers)


def request_to_curl(req: dict[str, Any]) -> str:
    method = str(req.get("method") or "GET").upper()
    url = str(req.get("url") or "")
    headers = req.get("headers") if isinstance(req.get("headers"), dict) else {}
    body = str(req.get("body") or "")
    parts = ["curl", "-i", "-X", shlex.quote(method)]
    for name, value in headers.items():
        parts.extend(["-H", shlex.quote(f"{name}: {value}")])
    if body:
        parts.extend(["--data-raw", shlex.quote(body)])
    if url:
        parts.append(shlex.quote(url))
    return " ".join(parts)


def _normalize_headers(headers: dict[str, str] | list | None) -> dict[str, str]:
    out: dict[str, str] = {}
    items: list[tuple[str, str]] = []
    if isinstance(headers, dict):
        items = [(str(k), str(v)) for k, v in headers.items()]
    elif isinstance(headers, list):
        for item in headers:
            if isinstance(item, dict):
                name = item.get("name") or item.get("key")
                value = item.get("value")
                if name is not None:
                    items.append((str(name), str(value or "")))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                items.append((str(item[0]), str(item[1])))
    for name, value in items:
        key = name.strip()
        if not key:
            continue
        if key.lower() in BLOCKED_HEADER_NAMES:
            continue
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise PocTargetError("请求头包含非法换行")
        out[key] = value
    return out


def _assert_host_not_blocked(host: str) -> None:
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise PocTargetError("不允许访问 localhost")
    if host.endswith(".local") or host.endswith(".onion"):
        raise PocTargetError("不允许访问 .local / .onion 主机")
    if host.endswith(".internal") or host.endswith(".corp"):
        raise PocTargetError("不允许访问内部域名")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if _ip_is_blocked(ip):
        raise PocTargetError("不允许访问内网或保留地址")


def _assert_resolved_ips_public(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PocTargetError(f"无法解析主机名: {host}") from exc
    if not infos:
        raise PocTargetError(f"无法解析主机名: {host}")
    for info in infos:
        sockaddr = info[4]
        ip_text = str(sockaddr[0])
        if ip_text.lower().startswith("::ffff:"):
            ip_text = ip_text.split(":")[-1]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise PocTargetError(f"解析到非法地址: {ip_text}") from exc
        if _ip_is_blocked(ip):
            raise PocTargetError("目标解析到内网或保留地址，已拦截")


def ip_is_blocked(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return _ip_is_blocked(ip)


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_unspecified:
        return True
    if getattr(ip, "is_site_local", False):
        return True
    if ip.version == 4:
        if ip in CGNAT or ip == METADATA_V4:
            return True
        if ip in ipaddress.ip_network("0.0.0.0/8"):
            return True
    if ip.version == 6:
        if ip in ipaddress.ip_network("fc00::/7"):
            return True
        if ip in ipaddress.ip_network("2001:db8::/32"):
            return True
    return False


def _decode_body(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self._hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._hops += 1
        if self._hops > MAX_REDIRECTS:
            raise PocTargetError("重定向次数过多")
        joined = urljoin(req.full_url, newurl)
        assert_public_url(joined, resolve_dns=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _parse_raw_http(text: str) -> dict[str, Any] | None:
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines:
        return None
    first = lines[0].strip()
    match = re.match(
        r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?$",
        first,
        re.I,
    )
    if not match:
        return None
    method = match.group(1).upper()
    path = match.group(2)
    headers: dict[str, str] = {}
    idx = 1
    while idx < len(lines) and lines[idx].strip():
        if ":" in lines[idx]:
            name, value = lines[idx].split(":", 1)
            headers[name.strip()] = value.strip()
        idx += 1
    body = "\n".join(lines[idx + 1 :]) if idx < len(lines) else ""
    host = headers.get("Host") or headers.get("host") or ""
    if path.startswith(("http://", "https://")):
        url = path
    elif host:
        url = f"https://{host}{path if path.startswith('/') else '/' + path}"
    else:
        url = path
    headers = {k: v for k, v in headers.items() if k.lower() != "host"}
    return {"method": method, "url": url, "headers": headers, "body": body}


def _parse_curl(text: str) -> dict[str, Any] | None:
    compact = text.replace("\\\n", " ").replace("\\\r\n", " ")
    try:
        tokens = shlex.split(compact, posix=True)
    except ValueError:
        return None
    if not tokens or tokens[0] not in ("curl", "curl.exe"):
        return None
    method = "GET"
    url = ""
    headers: dict[str, str] = {}
    body = ""
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok in ("-X", "--request") and nxt:
            method = nxt.upper()
            i += 2
            continue
        if tok in ("-H", "--header") and nxt:
            if ":" in nxt:
                name, value = nxt.split(":", 1)
                headers[name.strip()] = value.strip()
            i += 2
            continue
        if tok in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii") and nxt:
            body = nxt if not body else f"{body}&{nxt}"
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if tok == "--json" and nxt:
            body = nxt
            headers.setdefault("Content-Type", "application/json")
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if tok in ("-u", "--user", "-A", "--user-agent", "-b", "--cookie", "-e", "--referer"):
            i += 2
            continue
        if tok.startswith("-"):
            if tok in ("-I", "--head"):
                method = "HEAD"
            i += 1
            continue
        if tok.startswith(("http://", "https://")):
            url = tok
        i += 1
    if not url:
        return None
    if method not in ALLOWED_METHODS:
        method = "POST" if body else "GET"
    headers = {k: v for k, v in headers.items() if k.lower() not in BLOCKED_HEADER_NAMES}
    return {"method": method, "url": url, "headers": headers, "body": body}
