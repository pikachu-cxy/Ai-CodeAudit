"""Hard read-only execution policy for Deep Audit V1.

This module -- not the system prompt -- is the enforcement boundary:

* the Worker only ever receives a :class:`ReadOnlyRepository`, never a ``Path``;
* only the five existing read-only code tools are callable;
* every argument is type/range/character validated before execution;
* file reads are bounded by bytes, lines and output characters;
* secret-bearing paths are rejected outright and tool records are redacted;
* no shell, file-write, or network tool is exposed at all.

The repository is handed to the executor as a read-only *view*: the object has
no mutating methods, and all paths it resolves must remain inside the project
root. We deliberately do not spawn ``git``/shell commands to compute the
revision; evidence is bound to a digest of the scoped source manifest.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Any

from app.services.agent_tools import execute_agent_tool
from app.services.deep_audit_budget import BudgetPolicy
from app.services.file_service import SKIP_DIRS
from app.services.tool_log_redaction import redact_text

ALLOWED_TOOLS = frozenset(
    {"list_endpoints", "read_file", "read_files_batch", "search_code", "list_controllers"}
)

CODE_SUFFIXES = frozenset(
    {
        ".py", ".java", ".go", ".js", ".ts", ".tsx", ".jsx", ".php", ".rb",
        ".cs", ".kt", ".rs", ".vue", ".xml", ".yaml", ".yml", ".json",
        ".sql", ".properties", ".gradle", ".toml", ".ini", ".conf", ".md",
        ".txt", ".sh", ".bat", ".c", ".h", ".cpp", ".html", ".css",
    }
)

SENSITIVE_PATH_RE = re.compile(
    r"(^|[/\\])(\.git|\.env|\.ssh|\.aws|node_modules|vendor)([/\\]|$)"
    r"|(secret|credential|password|passwd|private[_-]?key|api[_-]?key|token)"
    r"|\.(pem|p12|pfx|jks|keystore|key)$",
    re.IGNORECASE,
)

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


class ToolPolicyError(ValueError):
    """Raised when an Agent asks for a tool/argument outside the read-only policy."""


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def relative_path(raw: str) -> str:
    if not isinstance(raw, str):
        raise ToolPolicyError("path 必须是字符串")
    value = raw.strip().replace("\\", "/").rstrip("/")
    if (
        not value or len(value) > 512 or _CONTROL_CHARS_RE.search(value)
        or any(char in value for char in ':*?"<>|')
        or any(not part or part in (".", "..") or part.endswith((".", " ")) for part in value.split("/"))
        or SENSITIVE_PATH_RE.search(value)
    ):
        raise ToolPolicyError("path 必须是安全的项目相对路径")
    return value


def path_in_scope(path: str, prefixes: tuple[str, ...]) -> bool:
    return not prefixes or any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def _normalise_rel(raw: str) -> str:
    value = relative_path(raw)
    if Path(value).suffix.lower() not in CODE_SUFFIXES:
        raise ToolPolicyError("只允许读取源码/配置文件类型")
    return value


def _bounded_int(value: Any, *, default: int, low: int, high: int, name: str) -> int:
    if value is None:
        return default
    if type(value) is not int:
        raise ToolPolicyError(f"{name} 必须是整数")
    if not low <= value <= high:
        raise ToolPolicyError(f"{name} 需在 {low}–{high} 之间")
    return value


def _validate_query(value: Any, policy: BudgetPolicy, *, name: str = "query") -> str:
    if not isinstance(value, str) or not 2 <= len(value.strip()) <= policy.max_search_chars:
        raise ToolPolicyError(f"{name} 必须是 2–{policy.max_search_chars} 字符的字符串")
    if _CONTROL_CHARS_RE.search(value) or ".." in value:
        raise ToolPolicyError(f"{name} 含非法字符")
    if name == "query" and not re.fullmatch(r"[\w.$]+(?:\(\))?|/[\w/.{}:$-]+", value.strip()):
        raise ToolPolicyError("query 必须是符号名或路由")
    return value.strip()


@dataclass(frozen=True)
class CodeSlice:
    path: str
    line_start: int
    line_end: int
    content: str
    content_hash: str


class ReadOnlyRepository:
    """Immutable view of a checked-out project. No mutating methods exist."""

    def __init__(
        self,
        project_path: Path | str,
        policy: BudgetPolicy,
        *,
        prefixes: tuple[str, ...] = (),
        check: Callable[[], None] = lambda: None,
    ):
        self.root = Path(project_path).resolve(strict=True)
        if not self.root.is_dir():
            raise ToolPolicyError("项目目录不存在")
        self._policy = policy
        self._hashes: dict[Path, bytes] = {}
        digest = hashlib.sha256()
        visited = 0
        for parent, dirs, files in os.walk(self.root):
            check()
            directory = Path(parent)
            allowed_dirs = []
            for name in sorted(dirs):
                path = directory / name
                rel = path.relative_to(self.root).as_posix()
                if (
                    name.casefold() in SKIP_DIRS or SENSITIVE_PATH_RE.search(name)
                    or path.is_symlink() or path.resolve().parent != directory
                ):
                    continue
                if path_in_scope(rel, prefixes) or any(prefix.startswith(rel + "/") for prefix in prefixes):
                    allowed_dirs.append(name)
            dirs[:] = allowed_dirs
            visited += len(dirs) + len(files)
            if visited > 50_000:
                raise ToolPolicyError("项目文件清单超过 50000 项，请缩小审计范围")
            for name in sorted(files):
                check()
                path = directory / name
                rel = path.relative_to(self.root).as_posix()
                if (
                    path.suffix.lower() not in CODE_SUFFIXES or SENSITIVE_PATH_RE.search(rel)
                    or not path_in_scope(rel, prefixes) or path.is_symlink()
                    or not path.is_file() or path.resolve() != path
                    or path.stat().st_size > policy.max_file_bytes
                ):
                    continue
                if len(self._hashes) >= 5000:
                    raise ToolPolicyError("可审计源码超过 5000 个文件，请缩小审计范围")
                file_hash = hashlib.sha256(self._read_bytes(path)).digest()
                self._hashes[path] = file_hash
                digest.update(rel.encode("utf-8") + b"\0" + file_hash)
        self.files = tuple(self._hashes)
        self.revision = "content:" + digest.hexdigest()

    def _read_bytes(self, path: Path) -> bytes:
        if path.resolve(strict=True) != path or path.is_symlink() or not path.is_file():
            raise ToolPolicyError("文件不在只读源码清单内")
        with path.open("rb") as stream:
            data = stream.read(self._policy.max_file_bytes + 1)
        if len(data) > self._policy.max_file_bytes:
            raise ToolPolicyError("文件超过字节上限")
        return data

    def read_source(self, path: Path) -> str:
        expected = self._hashes.get(path)
        if expected is None:
            raise ToolPolicyError("文件不在只读源码清单内")
        data = self._read_bytes(path)
        if hashlib.sha256(data).digest() != expected:
            raise ToolPolicyError("运行期间源码版本已变化")
        return data.decode("utf-8", errors="replace")

    def read_slice(self, entry: dict, *, char_limit: int) -> CodeSlice:
        rel = entry["path"]
        lines = self.read_source(self.root / rel).splitlines()
        start = entry["start_line"]
        window = lines[start - 1 : entry["end_line"]]
        selected: list[str] = []
        chars = 0
        for line in window:
            chars += len(line) + 1
            if chars > char_limit:
                break
            selected.append(line)
        if not selected:
            raise ToolPolicyError("请求行范围无可完整读取的代码")
        body = "\n".join(selected)
        return CodeSlice(rel, start, start + len(selected) - 1, body, content_hash(body))


def validate_tool_call(tool: str, arguments: dict | None, policy: BudgetPolicy) -> dict:
    """Normalise and strictly validate a tool call before it can execute."""
    name = tool
    if not isinstance(name, str) or name not in ALLOWED_TOOLS:
        raise ToolPolicyError("工具不在只读白名单内")
    allowed_args = {
        "list_endpoints": {"limit", "filter"},
        "list_controllers": {"limit", "filter"},
        "read_file": {"path", "start_line", "end_line"},
        "read_files_batch": {"files", "per_file_char_limit"},
        "search_code": {"query", "file_hint", "limit"},
    }
    args = {} if arguments is None else arguments
    if not isinstance(args, dict) or args.keys() - allowed_args[name]:
        raise ToolPolicyError("工具参数无效")
    clean: dict[str, Any] = {}

    if name in ("list_endpoints", "list_controllers"):
        clean["limit"] = _bounded_int(args.get("limit"), default=20, low=1, high=50, name="limit")
        if "filter" in args:
            clean["filter"] = _validate_query(args.get("filter"), policy, name="filter")
        return clean

    if name == "read_file":
        rel = _normalise_rel(args.get("path"))
        start = _bounded_int(args.get("start_line"), default=1, low=1, high=100_000, name="start_line")
        end = _bounded_int(
            args.get("end_line"), default=min(start + 120, start + policy.max_lines_per_read - 1),
            low=1, high=100_000, name="end_line",
        )
        if end < start:
            raise ToolPolicyError("end_line 不能小于 start_line")
        if end - start + 1 > policy.max_lines_per_read:
            end = start + policy.max_lines_per_read - 1
        clean.update({"path": rel, "start_line": start, "end_line": end})
        return clean

    if name == "read_files_batch":
        files = args.get("files")
        if not isinstance(files, list) or not files:
            raise ToolPolicyError("files 必须是非空数组")
        if len(files) > policy.max_batch_files:
            raise ToolPolicyError(f"单次最多读取 {policy.max_batch_files} 个文件")
        items: list[dict] = []
        for item in files:
            if not isinstance(item, dict) or item.keys() - allowed_args["read_file"]:
                raise ToolPolicyError("files 每项必须是对象")
            rel = _normalise_rel(item.get("path"))
            start = _bounded_int(item.get("start_line"), default=1, low=1, high=100_000, name="start_line")
            end = _bounded_int(
                item.get("end_line"), default=min(start + 120, start + policy.max_lines_per_read - 1),
                low=1, high=100_000, name="end_line",
            )
            if end < start:
                raise ToolPolicyError("end_line 不能小于 start_line")
            if end - start + 1 > policy.max_lines_per_read:
                end = start + policy.max_lines_per_read - 1
            items.append({"path": rel, "start_line": start, "end_line": end})
        clean["files"] = items
        clean["per_file_char_limit"] = _bounded_int(
            args.get("per_file_char_limit"), default=policy.max_output_chars,
            low=500, high=policy.max_output_chars, name="per_file_char_limit",
        )
        return clean

    # search_code
    clean["query"] = _validate_query(args.get("query"), policy)
    if "file_hint" in args:
        clean["file_hint"] = _normalise_rel(args["file_hint"])
    clean["limit"] = _bounded_int(args.get("limit"), default=15, low=1, high=30, name="limit")
    return clean


def execute_read_only_tool(
    repo: ReadOnlyRepository,
    tool: str,
    arguments: dict | None,
    policy: BudgetPolicy,
    check: Callable[[], None],
) -> tuple[str, list[CodeSlice]]:
    clean = validate_tool_call(tool, arguments, policy)
    check()
    if tool in {"read_file", "read_files_batch"}:
        entries = [clean] if tool == "read_file" else clean["files"]
        char_limit = min(clean.get("per_file_char_limit", policy.max_output_chars),
                         policy.max_output_chars // len(entries))
        slices = []
        rows = []
        for entry in entries:
            check()
            try:
                item = repo.read_slice(entry, char_limit=char_limit)
            except (OSError, ToolPolicyError):
                rows.append({"path": entry["path"], "error": "源码不可读或超出范围"})
                continue
            slices.append(item)
            rows.append({
                "path": item.path, "start_line": item.line_start, "end_line": item.line_end,
                "content": redact_text(item.content),
            })
        payload = {"ok": bool(slices)}
        payload.update(rows[0] if tool == "read_file" else {"files": rows})
        return json.dumps(payload, ensure_ascii=False), slices

    if clean.get("file_hint") and repo.root / clean["file_hint"] not in repo.files:
        raise ToolPolicyError("file_hint 不在只读源码清单内")
    raw = execute_agent_tool(
        repo.root, tool, clean, source_files=repo.files, read_source=repo.read_source,
        cancel_check=check,
    )
    check()
    payload = json.loads(raw)
    if not payload.get("ok"):
        return json.dumps({"ok": False, "error": "只读查询失败"}, ensure_ascii=False), []
    key = {"search_code": "hits", "list_endpoints": "endpoints", "list_controllers": "controllers"}[tool]
    payload.pop("suggested_next_tool", None)
    for hit in payload.get("hits", []):
        hit.pop("matched_text", None)
    for name in ("related_batch_candidates", key):
        rows = payload.get(name, [])
        while rows and len(json.dumps(payload, ensure_ascii=False)) > policy.max_output_chars:
            rows.pop()
    if "count" in payload:
        payload["count"] = len(payload.get(key, []))
    return redact_text(json.dumps(payload, ensure_ascii=False)), []
