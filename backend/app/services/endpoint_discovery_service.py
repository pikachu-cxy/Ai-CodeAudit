"""Discover HTTP API endpoints in a project for endpoint-driven LLM audit."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.services.file_service import CODE_EXTENSIONS, SKIP_DIRS
from app.services.path_filters import should_skip_walk_path

JAVA_MAPPING_RE = re.compile(
    r"@(?P<ann>Get|Post|Put|Delete|Patch|Request)Mapping\s*\((?P<args>[^)]*)\)",
    re.IGNORECASE,
)
JAVA_CLASS_MAPPING_RE = re.compile(
    r"@RequestMapping\s*\((?P<args>[^)]*)\)",
    re.IGNORECASE,
)
JAVA_METHOD_SIG_RE = re.compile(
    r"(?:public|protected|private)\s+[\w<>,\s\[\]]+\s+(?P<name>\w+)\s*\(",
)
JAVA_VALUE_RE = re.compile(r'(?:value|path)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
JAVA_METHOD_ENUM_RE = re.compile(r"RequestMethod\.(\w+)", re.IGNORECASE)

PY_ROUTE_RE = re.compile(
    r"@(?P<decorator>app|router|api)\.(?P<method>get|post|put|delete|patch|route)\s*\((?P<args>[^)]*)\)",
    re.IGNORECASE,
)
PY_FASTAPI_RE = re.compile(
    r"@(?P<name>\w+)\.(?P<method>get|post|put|delete|patch)\s*\((?P<args>[^)]*)\)",
    re.IGNORECASE,
)
PY_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\(", re.IGNORECASE)

SENSITIVE_KEYWORDS = (
    "pwd", "password", "passwd", "reset", "auth", "login", "logout", "token",
    "user", "admin", "role", "permission", "record", "id", "order", "pay",
    "transfer", "withdraw", "refund", "coupon", "approve", "delete", "update",
    "modify", "bind", "unbind", "export", "import", "upload", "download",
)

SERVICE_CALL_RE = re.compile(r"(?:this\.)?(\w+Service)\.(\w+)\s*\(", re.IGNORECASE)
JAVA_INJECT_RE = re.compile(r"@(?:Autowired|Resource)\s+(?:private\s+)?[\w<>,\s]+\s+(\w+)\s*;", re.IGNORECASE)

JS_TS_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
JS_FILE_SIGNALS = (
    "express",
    "router(",
    "@controller",
    "@get(",
    "@post(",
    "koa-router",
    "@koa/router",
    "router.get",
    "router.post",
    "app.get",
    "app.post",
    "app.use",
)
JS_EXPRESS_ROUTE_RE = re.compile(
    r"(?P<target>\w+)\.(?P<method>get|post|put|delete|patch|all)\s*\(\s*(?P<args>[^)]*)\)",
    re.IGNORECASE,
)
JS_ROUTE_CHAIN_RE = re.compile(
    r"\.route\s*\(\s*['\"`](?P<path>[^'\"`]+)['\"`]\s*\)\s*\.\s*(?P<method>get|post|put|delete|patch|all)\s*\(",
    re.IGNORECASE,
)
JS_STRING_PATH_RE = re.compile(r'["\'`]([^"\'`]+)["\'`]')
JS_ROUTER_VAR_RE = re.compile(
    r"(?:const|let|var)\s+(?P<var>\w+)\s*=\s*(?:express\.)?Router\s*\(",
    re.IGNORECASE,
)
JS_USE_MOUNT_RE = re.compile(
    r"(?:app|server)\.use\s*\(\s*['\"`](?P<prefix>[^'\"`]+)['\"`]\s*,\s*(?P<target>\w+)",
    re.IGNORECASE,
)
JS_USE_REQUIRE_RE = re.compile(
    r"(?:app|server)\.use\s*\(\s*['\"`](?P<prefix>[^'\"`]+)['\"`]\s*,\s*require\s*\(\s*['\"`](?P<req>[^'\"`]+)['\"`]\s*\)",
    re.IGNORECASE,
)
JS_REQUIRE_VAR_RE = re.compile(
    r"(?:const|let|var)\s+(?P<var>\w+)\s*=\s*require\s*\(\s*['\"`](?P<req>[^'\"`]+)['\"`]\s*\)",
    re.IGNORECASE,
)
JS_IMPORT_FROM_RE = re.compile(
    r"import\s+(?:\w+\s*,?\s*)*\{?\s*(?P<var>\w+)\s*\}?\s*from\s+['\"`](?P<req>[^'\"`]+)['\"`]",
    re.IGNORECASE,
)
JS_IMPORT_DEFAULT_RE = re.compile(
    r"import\s+(?P<var>\w+)\s+from\s+['\"`](?P<req>[^'\"`]+)['\"`]",
    re.IGNORECASE,
)
NEST_CONTROLLER_RE = re.compile(r"@Controller\s*\(\s*(?P<args>[^)]*)\)", re.IGNORECASE)
NEST_HTTP_DECORATOR_RE = re.compile(
    r"@(?P<method>Get|Post|Put|Delete|Patch|All|Head|Options)\s*(?:\(\s*(?P<args>[^)]*)\))?",
    re.IGNORECASE,
)
NEST_CLASS_RE = re.compile(r"(?:export\s+)?class\s+(?P<name>\w+)", re.IGNORECASE)
NEST_METHOD_RE = re.compile(r"(?:public\s+|private\s+|protected\s+|async\s+)*(?P<name>\w+)\s*\(", re.IGNORECASE)
JS_SERVICE_CALL_RE = re.compile(r"(\w+Service)\.(\w+)\s*\(", re.IGNORECASE)
JS_REQUIRE_RE = re.compile(r"require\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*\)", re.IGNORECASE)
JS_IMPORT_RE = re.compile(r"from\s+['\"`]([^'\"`]+)['\"`]", re.IGNORECASE)
NEST_INJECT_RE = re.compile(
    r"(?:private\s+(?:readonly\s+)?(?:@Inject\([^)]*\)\s*)?|constructor\s*\([^)]*)"
    r"(\w+Service)\b",
    re.IGNORECASE,
)

_ENTRY_FILE_NAMES = ("app.js", "app.ts", "index.js", "index.ts", "server.js", "server.ts", "main.js", "main.ts")
_EXPRESS_MOUNT_CACHE: dict[str, tuple[float, dict[str, str]]] = {}


@dataclass
class EndpointInfo:
    file: str
    line: int
    handler: str
    http_method: str
    path: str
    class_name: str = ""
    sensitivity: int = 0
    snippet: str = ""


@dataclass
class ControllerUnit:
    file: str
    class_name: str
    base_path: str
    endpoints: list[EndpointInfo] = field(default_factory=list)
    sensitivity: int = 0


DISCOVERY_CACHE_TTL_SECONDS = 90
_CONTROLLER_CACHE: dict[str, tuple[float, list[ControllerUnit]]] = {}
_PROJECT_HINTS_CACHE: dict[str, tuple[float, dict[str, str]]] = {}
_RELATED_SERVICE_CACHE: dict[str, tuple[float, list[str]]] = {}


def _cache_get(cache: dict, key: str):
    entry = cache.get(key)
    if not entry:
        return None
    expires_at, value = entry
    if expires_at < time.time():
        cache.pop(key, None)
        return None
    return value


def _cache_set(cache: dict, key: str, value):
    cache[key] = (time.time() + DISCOVERY_CACHE_TTL_SECONDS, value)
    return value


def _score_text(text: str) -> int:
    lower = text.lower()
    score = 0
    for kw in SENSITIVE_KEYWORDS:
        if kw in lower:
            score += 2
    if any(x in lower for x in ("controller", "ctrl", "handler", "api")):
        score += 1
    return score


def _extract_java_string_path(args: str) -> str:
    m = JAVA_VALUE_RE.search(args)
    if m:
        return m.group(1)
    quoted = re.search(r'["\']([^"\']+)["\']', args)
    return quoted.group(1) if quoted else ""


def _extract_java_http_method(args: str, ann: str) -> str:
    ann_lower = ann.lower()
    if ann_lower in ("get", "post", "put", "delete", "patch"):
        return ann_lower.upper()
    m = JAVA_METHOD_ENUM_RE.search(args)
    if m:
        return m.group(1).upper()
    return "ANY"


def _join_paths(base: str, sub: str) -> str:
    base = (base or "").strip().rstrip("/")
    sub = (sub or "").strip()
    if not sub:
        return base or "/"
    if not sub.startswith("/"):
        sub = "/" + sub
    if not base:
        return sub
    return base + sub


def _java_class_name(text: str) -> str:
    m = re.search(r"class\s+(\w+)", text)
    return m.group(1) if m else ""


def _discover_java_endpoints(project_path: Path, file_path: Path) -> ControllerUnit | None:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if "@Controller" not in text and "@RestController" not in text:
        if "Mapping" not in text:
            return None

    rel = str(file_path.relative_to(project_path))
    lines = text.splitlines()
    class_base = ""
    for line in lines[:80]:
        if "@RequestMapping" in line and "class" not in line:
            cm = JAVA_CLASS_MAPPING_RE.search(line)
            if cm:
                class_base = _extract_java_string_path(cm.group("args"))
                break

    class_name = _java_class_name(text)
    unit = ControllerUnit(file=rel, class_name=class_name, base_path=class_base)

    i = 0
    while i < len(lines):
        line = lines[i]
        mapping_match = JAVA_MAPPING_RE.search(line)
        if not mapping_match:
            i += 1
            continue

        ann = mapping_match.group("ann")
        args = mapping_match.group("args")
        http_method = _extract_java_http_method(args, ann)
        sub_path = _extract_java_string_path(args)

        handler = ""
        snippet_lines: list[str] = [line.strip()]
        for j in range(i + 1, min(i + 8, len(lines))):
            snippet_lines.append(lines[j].strip())
            sig = JAVA_METHOD_SIG_RE.search(lines[j])
            if sig:
                handler = sig.group("name")
                break

        if not handler:
            i += 1
            continue

        full_path = _join_paths(class_base, sub_path)
        blob = " ".join(snippet_lines)
        sens = _score_text(f"{handler} {full_path} {blob}")
        ep = EndpointInfo(
            file=rel,
            line=i + 1,
            handler=handler,
            http_method=http_method,
            path=full_path or f"/{handler}",
            class_name=class_name,
            sensitivity=sens,
            snippet="\n".join(snippet_lines[:6]),
        )
        unit.endpoints.append(ep)
        unit.sensitivity = max(unit.sensitivity, sens)
        i = j if handler else i + 1

    return unit if unit.endpoints else None


def _extract_py_path(args: str) -> str:
    quoted = re.findall(r'["\']([^"\']+)["\']', args)
    return quoted[0] if quoted else ""


def _discover_python_endpoints(project_path: Path, file_path: Path) -> ControllerUnit | None:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if not any(x in text for x in ("@app.", "@router.", "@api.", "APIRouter", "FastAPI", "Blueprint")):
        return None

    rel = str(file_path.relative_to(project_path))
    lines = text.splitlines()
    unit = ControllerUnit(file=rel, class_name=file_path.stem, base_path="")

    for i, line in enumerate(lines):
        m = PY_ROUTE_RE.search(line) or PY_FASTAPI_RE.search(line)
        if not m:
            continue
        method = m.group("method").upper()
        if method == "ROUTE":
            method = "ANY"
        path = _extract_py_path(m.group("args"))

        handler = ""
        snippet_lines = [line.strip()]
        for j in range(i + 1, min(i + 6, len(lines))):
            snippet_lines.append(lines[j].strip())
            dm = PY_DEF_RE.match(lines[j])
            if dm:
                handler = dm.group("name")
                break
        if not handler:
            continue

        blob = " ".join(snippet_lines)
        sens = _score_text(f"{handler} {path} {blob}")
        ep = EndpointInfo(
            file=rel,
            line=i + 1,
            handler=handler,
            http_method=method,
            path=path or f"/{handler}",
            class_name=file_path.stem,
            sensitivity=sens,
            snippet="\n".join(snippet_lines[:6]),
        )
        unit.endpoints.append(ep)
        unit.sensitivity = max(unit.sensitivity, sens)

    return unit if unit.endpoints else None


def _extract_js_string_path(args: str) -> str:
    m = JS_STRING_PATH_RE.search(args or "")
    return m.group(1) if m else ""


def _extract_js_handler(args: str) -> str:
    if not args:
        return "anonymous"
    parts = args.split(",", 1)
    if len(parts) < 2:
        return "anonymous"
    rest = parts[1].strip()
    if not rest:
        return "anonymous"
    if "=>" in rest or rest.startswith("function") or rest.startswith("async function"):
        return "anonymous"
    m = re.search(r"(\w+(?:\.\w+)+|\w+)\s*(?:,|\)|$)", rest)
    if m:
        name = m.group(1)
        if name not in ("req", "res", "next", "ctx"):
            return name
    return "anonymous"


def _js_ts_file_has_signals(text: str) -> bool:
    lower = text.lower()
    return any(sig in lower for sig in JS_FILE_SIGNALS)


def _normalize_rel_posix(project_path: Path, file_path: Path) -> str:
    return str(file_path.resolve().relative_to(project_path.resolve())).replace("\\", "/")


def _resolve_js_module_path(base_dir: Path, req_path: str) -> Path | None:
    raw = (req_path or "").strip()
    if not raw or raw.startswith("@") or raw.startswith("http"):
        return None
    candidate = (base_dir / raw).resolve()
    if candidate.is_file():
        return candidate
    for suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
        with_suffix = Path(str(candidate) + suffix)
        if with_suffix.is_file():
            return with_suffix.resolve()
    index_dir = candidate if candidate.is_dir() else Path(str(candidate))
    for name in ("index.js", "index.ts", "index.mjs"):
        index_file = index_dir / name
        if index_file.is_file():
            return index_file.resolve()
    return None


def _collect_express_mount_prefixes(project_path: Path) -> dict[str, str]:
    """Map route module relative paths to mount prefixes from entry files."""
    root = project_path.resolve()
    cache_key = str(root)
    cached = _cache_get(_EXPRESS_MOUNT_CACHE, cache_key)
    if cached is not None:
        return cached

    mounts: dict[str, str] = {}
    entry_dirs = [root]
    for sub in ("src", "app", "server"):
        d = root / sub
        if d.is_dir():
            entry_dirs.append(d)

    seen_entries: set[str] = set()
    for entry_dir in entry_dirs:
        for name in _ENTRY_FILE_NAMES:
            entry_path = entry_dir / name
            key = str(entry_path.resolve())
            if key in seen_entries or not entry_path.is_file():
                continue
            seen_entries.add(key)
            try:
                text = entry_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            var_to_req: dict[str, str] = {}
            for m in JS_REQUIRE_VAR_RE.finditer(text):
                var_to_req[m.group("var")] = m.group("req")
            for m in JS_IMPORT_DEFAULT_RE.finditer(text):
                var_to_req[m.group("var")] = m.group("req")
            for m in JS_IMPORT_FROM_RE.finditer(text):
                var_to_req[m.group("var")] = m.group("req")

            for m in JS_USE_REQUIRE_RE.finditer(text):
                prefix = m.group("prefix")
                resolved = _resolve_js_module_path(entry_dir, m.group("req"))
                if resolved and (root in resolved.parents or resolved == root):
                    rel = _normalize_rel_posix(root, resolved)
                    mounts[rel] = prefix

            for m in JS_USE_MOUNT_RE.finditer(text):
                prefix = m.group("prefix")
                target = m.group("target")
                req = var_to_req.get(target)
                if not req:
                    continue
                resolved = _resolve_js_module_path(entry_dir, req)
                if resolved and (root in resolved.parents or resolved == root):
                    rel = _normalize_rel_posix(root, resolved)
                    mounts[rel] = prefix

    return _cache_set(_EXPRESS_MOUNT_CACHE, cache_key, mounts)


def _same_file_router_prefixes(text: str) -> dict[str, str]:
    """Map router variable names to mount prefixes within the same file."""
    router_vars: set[str] = set()
    for m in JS_ROUTER_VAR_RE.finditer(text):
        router_vars.add(m.group("var"))
    if "router" in text:
        router_vars.add("router")

    prefixes: dict[str, str] = {}
    for m in JS_USE_MOUNT_RE.finditer(text):
        target = m.group("target")
        if target in router_vars or target.endswith("Router") or target.endswith("Routes"):
            prefixes[target] = m.group("prefix")
    return prefixes


def _discover_nestjs_endpoints(
    project_path: Path,
    file_path: Path,
    text: str,
    rel: str,
    external_base: str,
) -> ControllerUnit | None:
    if "@Controller" not in text and "@Get(" not in text and "@Post(" not in text:
        return None

    lines = text.splitlines()
    class_base = ""
    class_name = ""
    for line in lines[:120]:
        cm = NEST_CONTROLLER_RE.search(line)
        if cm:
            class_base = _extract_js_string_path(cm.group("args"))
            break
    cm_class = NEST_CLASS_RE.search(text)
    if cm_class:
        class_name = cm_class.group("name")

    unit = ControllerUnit(
        file=rel,
        class_name=class_name or file_path.stem,
        base_path=_join_paths(external_base, class_base),
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        dec = NEST_HTTP_DECORATOR_RE.search(line)
        if not dec:
            i += 1
            continue

        method = dec.group("method").upper()
        if method in ("HEAD", "OPTIONS"):
            method = "ANY"
        sub_path = _extract_js_string_path(dec.group("args") or "")

        handler = ""
        snippet_lines = [line.strip()]
        for j in range(i + 1, min(i + 8, len(lines))):
            snippet_lines.append(lines[j].strip())
            if lines[j].strip().startswith("@"):
                continue
            sig = NEST_METHOD_RE.search(lines[j])
            if sig and sig.group("name") not in ("constructor", "if", "for", "while", "switch"):
                handler = sig.group("name")
                break

        if not handler:
            i += 1
            continue

        full_path = _join_paths(unit.base_path, sub_path)
        blob = " ".join(snippet_lines)
        sens = _score_text(f"{handler} {full_path} {blob}")
        ep = EndpointInfo(
            file=rel,
            line=i + 1,
            handler=handler,
            http_method=method,
            path=full_path or f"/{handler}",
            class_name=unit.class_name,
            sensitivity=sens,
            snippet="\n".join(snippet_lines[:6]),
        )
        unit.endpoints.append(ep)
        unit.sensitivity = max(unit.sensitivity, sens)
        i = j if handler else i + 1

    return unit if unit.endpoints else None


def _discover_express_koa_endpoints(
    project_path: Path,
    file_path: Path,
    text: str,
    rel: str,
    external_base: str,
) -> ControllerUnit | None:
    router_prefixes = _same_file_router_prefixes(text)
    lines = text.splitlines()
    unit = ControllerUnit(file=rel, class_name=file_path.stem, base_path=external_base)

    def _target_base(target: str) -> str:
        prefix = router_prefixes.get(target)
        if prefix:
            return _join_paths(external_base, prefix)
        if target in ("app", "server"):
            return external_base
        return external_base

    def _add_endpoint(
        line_no: int,
        http_method: str,
        sub_path: str,
        handler: str,
        snippet_lines: list[str],
        target: str,
    ) -> None:
        base = _target_base(target)
        full_path = _join_paths(base, sub_path)
        blob = " ".join(snippet_lines)
        sens = _score_text(f"{handler} {full_path} {blob}")
        ep = EndpointInfo(
            file=rel,
            line=line_no,
            handler=handler,
            http_method=http_method.upper(),
            path=full_path or f"/{handler}",
            class_name=unit.class_name,
            sensitivity=sens,
            snippet="\n".join(snippet_lines[:6]),
        )
        unit.endpoints.append(ep)
        unit.sensitivity = max(unit.sensitivity, sens)

    for i, line in enumerate(lines):
        chain = JS_ROUTE_CHAIN_RE.search(line)
        if chain:
            sub_path = chain.group("path")
            method = chain.group("method").upper()
            handler = _extract_js_handler(line[chain.end() :])
            _add_endpoint(i + 1, method, sub_path, handler, [line.strip()], "router")
            continue

        m = JS_EXPRESS_ROUTE_RE.search(line)
        if not m:
            continue
        target = m.group("target")
        method = m.group("method").upper()
        args = m.group("args")
        sub_path = _extract_js_string_path(args)
        handler = _extract_js_handler(args)
        _add_endpoint(i + 1, method, sub_path, handler, [line.strip()], target)

    return unit if unit.endpoints else None


def _discover_js_ts_endpoints(
    project_path: Path,
    file_path: Path,
    *,
    mount_prefixes: dict[str, str] | None = None,
) -> ControllerUnit | None:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if not _js_ts_file_has_signals(text):
        return None

    rel = _normalize_rel_posix(project_path, file_path)
    prefixes = mount_prefixes if mount_prefixes is not None else _collect_express_mount_prefixes(project_path)
    external_base = prefixes.get(rel, "")

    nest_unit = _discover_nestjs_endpoints(project_path, file_path, text, rel, external_base)
    express_unit = _discover_express_koa_endpoints(project_path, file_path, text, rel, external_base)

    if nest_unit and express_unit:
        merged = ControllerUnit(
            file=rel,
            class_name=nest_unit.class_name or express_unit.class_name,
            base_path=nest_unit.base_path or express_unit.base_path,
            endpoints=nest_unit.endpoints + express_unit.endpoints,
            sensitivity=max(nest_unit.sensitivity, express_unit.sensitivity),
        )
        return merged if merged.endpoints else None
    return nest_unit or express_unit


def discover_controller_units(
    project_path: Path,
    cancel_check: Callable[[], None] | None = None,
) -> list[ControllerUnit]:
    """Scan project and return controller files grouped with their endpoints."""
    root = project_path.resolve()
    cache_key = str(root)
    cached = _cache_get(_CONTROLLER_CACHE, cache_key)
    if cached is not None:
        return cached

    units: list[ControllerUnit] = []
    mount_prefixes = _collect_express_mount_prefixes(root)

    checked = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        checked += 1
        if cancel_check and checked % 200 == 0:
            cancel_check()
        if should_skip_walk_path(path, SKIP_DIRS):
            continue
        suffix = path.suffix.lower()
        if suffix not in CODE_EXTENSIONS:
            continue

        unit: ControllerUnit | None = None
        if suffix == ".java":
            unit = _discover_java_endpoints(root, path)
        elif suffix == ".py":
            unit = _discover_python_endpoints(root, path)
        elif suffix in JS_TS_SUFFIXES:
            unit = _discover_js_ts_endpoints(root, path, mount_prefixes=mount_prefixes)

        if unit and unit.endpoints:
            units.append(unit)

    units.sort(key=lambda u: (-u.sensitivity, -len(u.endpoints), u.file))
    return _cache_set(_CONTROLLER_CACHE, cache_key, units)


def list_endpoints_summary(
    project_path: Path,
    *,
    filter_text: str = "",
    limit: int = 80,
    cancel_check: Callable[[], None] | None = None,
) -> list[dict]:
    """Flat endpoint list for Agent tools."""
    units = discover_controller_units(project_path, cancel_check=cancel_check)
    rows: list[dict] = []
    needle = (filter_text or "").strip().lower()

    for unit in units:
        if cancel_check and len(rows) % 50 == 0:
            cancel_check()
        for ep in unit.endpoints:
            hay = f"{ep.handler} {ep.path} {ep.file} {unit.class_name}".lower()
            if needle and needle not in hay:
                continue
            rows.append(
                {
                    "file": ep.file,
                    "line": ep.line,
                    "handler": ep.handler,
                    "http_method": ep.http_method,
                    "path": ep.path,
                    "class": unit.class_name,
                    "sensitivity": ep.sensitivity,
                }
            )

    rows.sort(key=lambda r: (-r["sensitivity"], r["file"], r["line"]))
    return rows[: max(1, limit)]


DOMAIN_SIGNALS: dict[str, tuple[str, ...]] = {
    "用户与账号": ("user", "login", "logout", "auth", "register", "pwd", "password", "account", "member"),
    "支付与交易": ("pay", "order", "transfer", "refund", "withdraw", "coupon", "wallet", "trade", "billing"),
    "权限与审批": ("admin", "role", "permission", "approve", "audit", "mgr", "manage"),
    "AI与对话": ("agent", "chat", "llm", "prompt", "message", "ai", "bot", "guide", "copilot", "completion"),
    "文件与数据": ("upload", "download", "export", "import", "file", "document", "report"),
}


def cluster_endpoints_by_domain(units: list[ControllerUnit]) -> list[dict]:
    """Group endpoints into coarse business domains for Origin context."""
    buckets: dict[str, list[dict]] = {name: [] for name in DOMAIN_SIGNALS}
    buckets["其它"] = []

    for unit in units:
        for ep in unit.endpoints:
            hay = f"{ep.path} {ep.handler} {unit.class_name} {unit.file}".lower()
            row = {
                "method": ep.http_method,
                "path": ep.path,
                "handler": ep.handler,
                "file": ep.file,
                "class": unit.class_name,
                "sensitivity": ep.sensitivity,
            }
            matched = False
            for domain, keywords in DOMAIN_SIGNALS.items():
                if any(kw in hay for kw in keywords):
                    buckets[domain].append(row)
                    matched = True
                    break
            if not matched:
                buckets["其它"].append(row)

    clusters: list[dict] = []
    for domain, rows in buckets.items():
        if not rows:
            continue
        rows.sort(key=lambda r: (-r["sensitivity"], r["path"]))
        clusters.append(
            {
                "domain": domain,
                "endpoint_count": len(rows),
                "high_sensitivity_count": sum(1 for r in rows if r["sensitivity"] >= 2),
                "sample_endpoints": rows[:10],
            }
        )
    clusters.sort(key=lambda c: (-c["high_sensitivity_count"], -c["endpoint_count"]))
    return clusters


def collect_project_hints(project_path: Path) -> dict[str, str]:
    """Lightweight project metadata to help LLM infer business context."""
    root = project_path.resolve()
    cache_key = str(root)
    cached = _cache_get(_PROJECT_HINTS_CACHE, cache_key)
    if cached is not None:
        return cached

    hints: dict[str, str] = {}
    candidates = (
        "README.md",
        "README",
        "README.zh-CN.md",
        "pom.xml",
        "package.json",
        "pyproject.toml",
        "build.gradle",
    )
    for name in candidates:
        path = project_path / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            hints[name] = text[:800]
    return _cache_set(_PROJECT_HINTS_CACHE, cache_key, hints)


def find_related_service_files(
    project_path: Path,
    controller_path: Path,
    *,
    max_files: int = 4,
    cancel_check: Callable[[], None] | None = None,
    max_scan_seconds: float = 8.0,
    max_files_scanned: int = 1200,
) -> list[Path]:
    """Heuristically find Service/DAO files referenced by a controller.

    Hard time/file budgets keep large repos from pegging CPU for minutes.
    """
    root = project_path.resolve()
    controller_resolved = controller_path.resolve()
    cache_key = f"{root}::{controller_resolved}"
    cached = _cache_get(_RELATED_SERVICE_CACHE, cache_key)
    if cached is not None:
        return [Path(p) for p in cached[:max_files]]

    try:
        text = controller_resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    symbols: set[str] = set()
    for m in SERVICE_CALL_RE.finditer(text):
        symbols.add(m.group(2))
    for m in JAVA_INJECT_RE.finditer(text):
        symbols.add(m.group(1))
    for m in JS_SERVICE_CALL_RE.finditer(text):
        symbols.add(m.group(2))
        symbols.add(m.group(1))
    for m in NEST_INJECT_RE.finditer(text):
        symbols.add(m.group(1))
    for m in JS_REQUIRE_RE.finditer(text):
        req = m.group(1)
        base = Path(req).stem
        if base:
            symbols.add(base)
    for m in JS_IMPORT_RE.finditer(text):
        req = m.group(1)
        base = Path(req).stem
        if base:
            symbols.add(base)

    if not symbols:
        return []

    hits: list[tuple[int, Path]] = []
    started = time.perf_counter()
    scanned = 0

    # Prefer same package / nearby tree before full-repo walk.
    search_roots = [controller_resolved.parent]
    for up in list(controller_resolved.parents)[:4]:
        if up == root or root in up.parents or up == root.parent:
            search_roots.append(up)
    if root not in search_roots:
        search_roots.append(root)

    seen_paths: set[str] = set()
    for search_root in search_roots:
        if max_scan_seconds and (time.perf_counter() - started) >= max_scan_seconds:
            break
        if scanned >= max_files_scanned:
            break
        try:
            iterator = search_root.rglob("*")
        except OSError:
            continue
        for path in iterator:
            if max_scan_seconds and (time.perf_counter() - started) >= max_scan_seconds:
                break
            if scanned >= max_files_scanned:
                break
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
            except OSError:
                continue
            key = str(resolved)
            if key in seen_paths or resolved == controller_resolved:
                continue
            seen_paths.add(key)
            if cancel_check and (scanned % 40 == 0):
                cancel_check()
            if should_skip_walk_path(path, SKIP_DIRS):
                continue
            if path.suffix.lower() not in {".java", ".py", ".kt", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                continue
            scanned += 1
            try:
                if cancel_check and (scanned % 10 == 0):
                    cancel_check()
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            score = 0
            for sym in symbols:
                if re.search(rf"\b{re.escape(sym)}\s*\(", content):
                    score += 3
                elif sym.lower() in path.name.lower():
                    score += 2
                elif sym in content:
                    score += 1
            if score > 0:
                hits.append((score, path))
                if len(hits) >= max_files * 4:
                    # Enough candidates; stop early to protect responsiveness.
                    break
        if len(hits) >= max_files:
            break

    hits.sort(key=lambda x: (-x[0], str(x[1])))
    seen: set[str] = set()
    out: list[Path] = []
    for _, p in hits:
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= max_files:
            break
    _cache_set(_RELATED_SERVICE_CACHE, cache_key, [str(p.resolve()) for p in out])
    return out[:max_files]


def find_cross_module_siblings(
    project_path: Path,
    controller_path: Path,
    handler_name: str,
    *,
    max_files: int = 2,
) -> list[Path]:
    """Find same-named handler methods in other modules (e.g. mch vs mgr)."""
    root = project_path.resolve()
    name = controller_path.name
    matches: list[Path] = []
    for path in root.rglob(name):
        if not path.is_file() or path.resolve() == controller_path.resolve():
            continue
        if should_skip_walk_path(path, SKIP_DIRS):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(rf"\b{re.escape(handler_name)}\s*\(", text):
            matches.append(path)
    return matches[:max_files]
