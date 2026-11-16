"""Shared, dependency-free redaction for tool execution records.

Both the legacy chat tool dispatcher and Deep Audit's guarded executor log tool
arguments. This module keeps credential-shaped values out of ScanEvent rows and
API responses without importing either caller (avoids a circular import).
"""
from __future__ import annotations

import re
from typing import Any

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|authorization|bearer)\b"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.+/=]{8,})[\"']?"
)
LONG_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
SENSITIVE_KEY_RE = re.compile(r"(?i)(key|token|secret|password|passwd|auth|credential)")


def redact_text(text: str) -> str:
    """Strip credential assignments and long opaque blobs from a log string."""
    value = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text or "")
    return LONG_BLOB_RE.sub("<redacted>", value)


def redact_arguments(
    arguments: dict | None, *, max_chars: int = 120, include_strings: bool = False
) -> dict[str, Any]:
    """Return a log-safe preview; never emit full values or secret keys."""
    out: dict[str, Any] = {}
    for key, value in (arguments.items() if isinstance(arguments, dict) else ()):
        name = str(key)
        if name not in {"query", "path", "file_hint", "filter", "files", "start_line", "end_line", "limit", "per_file_char_limit"}:
            continue
        if SENSITIVE_KEY_RE.search(name):
            out[name] = "<redacted>"
            continue
        if isinstance(value, str):
            out[name] = redact_text(value)[:max_chars] if include_strings else "<omitted>"
        elif isinstance(value, list):
            out[name] = f"{len(value)} items"
        elif isinstance(value, dict):
            out[name] = f"{len(value)} keys"
        elif isinstance(value, (int, float, bool)) or value is None:
            out[name] = value
        else:
            out[name] = type(value).__name__
    return out
