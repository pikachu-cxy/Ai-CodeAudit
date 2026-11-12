"""Shared utilities for scanner plugins."""

import json
import logging
import re
import shutil
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_npm_executable() -> str | None:
    """
    Resolve npm for subprocess without shell.

    On Windows, ``npm`` from PATH is often a shell shim; CreateProcess cannot
    run it (WinError 2). Prefer ``npm.cmd`` / ``npm.exe``. On Linux/macOS,
    plain ``npm`` is correct.
    """
    if sys.platform == "win32":
        for name in ("npm.cmd", "npm.exe", "npm"):
            found = shutil.which(name)
            if found:
                return found
        return None
    return shutil.which("npm")

SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


def normalize_severity(raw: str | None, default: str = "UNKNOWN") -> str:
    if not raw:
        return default
    upper = str(raw).upper()
    return SEVERITY_MAP.get(upper, upper if upper in {
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"
    } else default)


def read_code_snippet(file_path: Path, line_start: int, context: int = 5) -> str | None:
    if not line_start or not file_path.is_file():
        return None
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    start = max(0, line_start - context - 1)
    end = min(len(lines), line_start + context)
    snippet_lines = []
    for i in range(start, end):
        prefix = ">>>" if i == line_start - 1 else "   "
        snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")
    return "\n".join(snippet_lines)


def resolve_file_path(project_path: Path, rel_or_abs: str) -> Path:
    p = Path(rel_or_abs)
    if p.is_absolute():
        return p
    return project_path / rel_or_abs


_REPOS_PREFIX_RE = re.compile(
    r"(?:^|.*/)(?:(?:backend/)?data/)?repos/[^/]+/(?P<tail>.+)$",
    re.IGNORECASE,
)
_UPLOAD_PREFIX_RE = re.compile(
    r"(?:^|.*/)(?:(?:backend/)?data/)?uploads/[^/]+/[^/]+/(?P<tail>.+)$",
    re.IGNORECASE,
)


def to_repo_relative_path(file_path: str | Path | None, project_path: Path | str | None = None) -> str:
    """Store/display paths as in-repo relatives, never host machine directories."""
    raw = str(file_path or "").strip()
    if not raw:
        return ""
    root = Path(project_path).resolve() if project_path else None
    if root:
        try:
            candidate = Path(raw)
            resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
            return str(resolved.relative_to(root)).replace("\\", "/")
        except (OSError, ValueError):
            pass
    text = raw.replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    text = text.lstrip("/")
    for rx in (_REPOS_PREFIX_RE, _UPLOAD_PREFIX_RE):
        match = rx.search(text)
        if match:
            return match.group("tail").lstrip("/")
    return text


def parse_json_output(stdout: str, tool: str) -> dict | list:
    text = (stdout or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse {tool} JSON output: {exc}") from exc


def finding(
    *,
    tool: str,
    rule_id: str,
    message: str,
    severity: str,
    file_path: str,
    line_start: int = 0,
    line_end: int = 0,
    code_snippet: str | None = None,
    check_id: str | None = None,
    metadata: dict | None = None,
    project_path: Path | str | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "check_id": check_id or rule_id,
        "severity": normalize_severity(severity),
        "message": message,
        "file_path": to_repo_relative_path(file_path, project_path),
        "line_start": line_start,
        "line_end": line_end or line_start,
        "code_snippet": code_snippet,
        "metadata_json": json.dumps(metadata or {}, ensure_ascii=False),
        "tool": tool,
    }
