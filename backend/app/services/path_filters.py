"""Shared helpers to skip test / non-production source paths during scans."""

from __future__ import annotations

import re
import sys
from pathlib import Path, PurePosixPath

# Directory segment names treated as test trees (case-insensitive).
TEST_DIR_NAMES = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "testdata",
        "testing",
        "spec",
        "specs",
        "mock",
        "mocks",
        "fixture",
        "fixtures",
    }
)

# Fallback skip dirs when callers do not pass their own base set.
BASE_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        "venv",
        ".venv",
        "dist",
        "build",
        "vendor",
        "target",
        ".idea",
        ".vscode",
        "coverage",
        ".next",
        ".gradle",
        ".m2",
        "out",
        "bin",
        "obj",
        ".tox",
        ".cache",
        "uploads",
        "repos",
        ".tools",
        "test-results",
        "logs",
    }
)

# Semgrep --exclude patterns (directory names / globs).
TEST_EXCLUDE_PATTERNS = [
    "test",
    "tests",
    "__tests__",
    "testdata",
    "testing",
    "spec",
    "specs",
    "**/src/test/**",
    "**/*Test.java",
    "**/*Tests.java",
    "**/*_test.go",
    "**/*_test.py",
    "**/*.test.js",
    "**/*.test.ts",
    "**/*.test.jsx",
    "**/*.test.tsx",
    "**/*.spec.js",
    "**/*.spec.ts",
    "**/*.spec.jsx",
    "**/*.spec.tsx",
]

# Bandit --exclude is a comma-separated list of path substrings / dirs.
BANDIT_TEST_EXCLUDES = [
    "*/test/*",
    "*/tests/*",
    "*/__tests__/*",
    "*/testdata/*",
    "*/testing/*",
    "*_test.py",
    "test_*.py",
]

_TEST_FILE_RE = re.compile(
    r"("
    r"Test\.java$|Tests\.java$|"
    r"_test\.go$|_test\.py$|^test_[^/\\]+\.py$|"
    r"\.(test|spec)\.(js|jsx|ts|tsx)$"
    r")",
    re.IGNORECASE,
)


def exclude_test_paths_enabled() -> bool:
    from app.config import settings

    return bool(getattr(settings, "exclude_test_paths", True))


def walk_skip_dir_names(base: set[str] | frozenset[str] | None = None) -> set[str]:
    """Directory names to skip while walking a project tree."""
    out = {str(x) for x in (base if base is not None else BASE_SKIP_DIRS)}
    if exclude_test_paths_enabled():
        out |= set(TEST_DIR_NAMES)
    return out


def _path_parts(file_path: str | Path) -> list[str]:
    text = str(file_path or "").replace("\\", "/").strip()
    if not text:
        return []
    # Drop drive letter for Windows absolute paths.
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    return [p for p in PurePosixPath(text).parts if p not in ("/", ".")]


def is_test_path(file_path: str | Path | None) -> bool:
    """Return True if path looks like test / fixture / mock source."""
    if not file_path:
        return False
    parts = _path_parts(file_path)
    if not parts:
        return False
    lowered = [p.lower() for p in parts]

    # Java / Maven / Gradle: src/test/...
    for i in range(len(lowered) - 1):
        if lowered[i] == "src" and lowered[i + 1] == "test":
            return True

    if any(p in TEST_DIR_NAMES for p in lowered):
        return True

    filename = parts[-1]
    return bool(_TEST_FILE_RE.search(filename))


def filter_out_test_findings(items: list[dict]) -> tuple[list[dict], int]:
    """Drop findings whose file_path is under a test tree. Returns (kept, skipped)."""
    if not exclude_test_paths_enabled():
        return items, 0
    kept: list[dict] = []
    skipped = 0
    for item in items:
        if is_test_path(item.get("file_path")):
            skipped += 1
            continue
        kept.append(item)
    return kept, skipped


def merge_semgrep_excludes(base: list[str]) -> list[str]:
    patterns = list(base)
    if exclude_test_paths_enabled():
        for p in TEST_EXCLUDE_PATTERNS:
            if p not in patterns:
                patterns.append(p)
    # Windows semgrep-core 1.166 can fail target discovery on `**/*Test.java`
    # style globs. Directory names still exclude test trees; file-level test
    # findings are filtered after parse.
    if sys.platform == "win32":
        patterns = [p for p in patterns if "*" not in p]
    return patterns


def bandit_exclude_args() -> list[str]:
    if not exclude_test_paths_enabled():
        return []
    return ["--exclude", ",".join(BANDIT_TEST_EXCLUDES)]


def should_skip_walk_part(part: str, base: set[str] | frozenset[str] | None = None) -> bool:
    skip = walk_skip_dir_names(base)
    return part.lower() in {s.lower() for s in skip}


def should_skip_walk_path(
    path: Path | str,
    base: set[str] | frozenset[str] | None = None,
    *,
    relative_to: Path | str | None = None,
) -> bool:
    """Return True if path should be skipped while walking a project tree.

    When ``relative_to`` is set, only path segments *under the project root*
    are checked. This avoids false skips when the project itself lives under
    a platform data dir named ``repos`` / ``uploads``.
    """
    check_path: Path | str = path
    if relative_to is not None:
        try:
            check_path = Path(path).resolve().relative_to(Path(relative_to).resolve())
        except ValueError:
            return True
    parts = _path_parts(check_path)
    skip = {s.lower() for s in walk_skip_dir_names(base)}
    return any(p.lower() in skip for p in parts) or (
        exclude_test_paths_enabled() and is_test_path(check_path)
    )
