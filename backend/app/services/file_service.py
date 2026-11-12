"""Safe project file reads and code location helpers."""

from collections.abc import Callable
import re
import time
from pathlib import Path

from app.services.path_filters import should_skip_walk_path
from app.services.scanners.common import to_repo_relative_path

CODE_EXTENSIONS = {
    ".py", ".java", ".go", ".js", ".ts", ".tsx", ".jsx",
    ".php", ".rb", ".cs", ".kt", ".rs", ".vue", ".xml", ".yaml", ".yml",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build",
    "vendor", "target", ".idea", ".vscode", "coverage", ".next",
}

LOCATION_RE = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[\\/\w.\-]+?\.[A-Za-z0-9]+):(?P<line>\d+)(?:-(?P<line_end>\d+))?",
    re.IGNORECASE,
)


def resolve_project_file(project_path: Path, file_path: str) -> Path:
    """Resolve and validate a file path stays inside the scan project root."""
    root = project_path.resolve()
    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("路径越界，禁止访问项目目录外的文件")
    if not resolved.is_file():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    return resolved


def read_file_with_context(
    project_path: Path,
    file_path: str,
    highlight_start: int,
    highlight_end: int,
    context_lines: int = 40,
) -> dict:
    resolved = resolve_project_file(project_path, file_path)
    rel = to_repo_relative_path(resolved, project_path) or str(resolved.relative_to(project_path.resolve())).replace("\\", "/")
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"无法读取文件: {exc}") from exc

    lines = text.splitlines()
    total = len(lines) if lines else 1
    hi_start = max(1, highlight_start or 1)
    hi_end = max(hi_start, highlight_end or hi_start)

    win_start = max(1, hi_start - context_lines)
    win_end = min(total, hi_end + context_lines)
    slice_lines = lines[win_start - 1 : win_end]

    return {
        "file_path": rel,
        "relative_path": rel,
        "content": "\n".join(slice_lines),
        "line_start": win_start,
        "line_end": win_end,
        "total_lines": total,
        "highlight_start": hi_start,
        "highlight_end": hi_end,
    }


def _resolve_path_in_project(project_path: Path, raw_path: str) -> Path | None:
    root = project_path.resolve()
    candidate = Path(raw_path.replace("\\", "/"))
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()

    if resolved.is_file() and (resolved == root or root in resolved.parents):
        return resolved

    name = candidate.name
    if not name:
        return None
    matches = [p for p in root.rglob(name) if p.is_file() and not should_skip_walk_path(p, SKIP_DIRS)]
    return matches[0] if matches else None


def parse_location_ref(
    text: str,
    project_path: Path,
    default_file: str | None = None,
) -> dict | None:
    """Parse file:line references embedded in free text."""
    if not text:
        return None

    match = LOCATION_RE.search(text.replace("\\", "/"))
    if match:
        resolved = _resolve_path_in_project(project_path, match.group("path"))
        if resolved:
            line_start = int(match.group("line"))
            line_end = int(match.group("line_end") or line_start)
            return {
                "file_path": to_repo_relative_path(resolved, project_path),
                "line_start": line_start,
                "line_end": line_end,
                "confidence": 0.99,
                "strategy": "path_line",
                "language_matched": True,
            }

    line_only = re.search(r"(?:^|\s)(?:L|line\s*)(?P<line>\d+)(?:\s|$)", text, re.IGNORECASE)
    if line_only and default_file:
        try:
            resolved = resolve_project_file(project_path, default_file)
            line = int(line_only.group("line"))
            return {
                "file_path": to_repo_relative_path(resolved, project_path),
                "line_start": line,
                "line_end": line,
                "confidence": 0.9,
                "strategy": "line_only",
                "language_matched": True,
            }
        except (FileNotFoundError, ValueError):
            pass

    return None


def _iter_source_files(
    project_path: Path,
    prefer_file: Path | None = None,
    allowed_suffixes: set[str] | None = None,
):
    if prefer_file and prefer_file.is_file():
        if (not allowed_suffixes) or (prefer_file.suffix.lower() in allowed_suffixes):
            yield prefer_file
    for path in project_path.rglob("*"):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in CODE_EXTENSIONS:
            continue
        if allowed_suffixes and suffix not in allowed_suffixes:
            continue
        if should_skip_walk_path(path, SKIP_DIRS):
            continue
        if prefer_file and path.resolve() == prefer_file.resolve():
            continue
        yield path


def _iter_nearby_source_files(
    prefer_file: Path | None = None,
    allowed_suffixes: set[str] | None = None,
):
    if not prefer_file:
        return
    parent = prefer_file.parent
    if not parent.is_dir():
        return
    for path in parent.rglob("*"):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in CODE_EXTENSIONS:
            continue
        if allowed_suffixes and suffix not in allowed_suffixes:
            continue
        if should_skip_walk_path(path, SKIP_DIRS):
            continue
        if path.resolve() == prefer_file.resolve():
            continue
        yield path


def locate_text_in_project(
    project_path: Path,
    query: str,
    file_hint: str | None = None,
    limit: int = 8,
    max_scan_seconds: float | None = None,
    max_files_scanned: int | None = None,
    cancel_check: Callable[[], None] | None = None,
    max_file_bytes: int | None = None,
) -> list[dict]:
    """Search project source for a symbol / snippet and return file+line hits."""
    query = (query or "").strip()
    if not query or len(query) < 2:
        return []

    loc = parse_location_ref(query, project_path, file_hint)
    if loc:
        return [loc]

    prefer: Path | None = None
    if file_hint:
        try:
            prefer = resolve_project_file(project_path, file_hint)
        except (FileNotFoundError, ValueError):
            prefer = None

    # Method/symbol style: UserService.updateRole(
    symbol = query
    for sep in ("->", "→", "|"):
        if sep in symbol:
            symbol = symbol.split(sep)[-1].strip()
    symbol = symbol.strip("`\"'")
    if "(" in symbol:
        symbol = symbol.split("(")[0].strip()
    if "." in symbol:
        symbol = symbol.split(".")[-1].strip()

    patterns = []
    if symbol and symbol not in {"unknown", "请求参数"}:
        patterns.append(symbol)
    if query not in patterns and len(query) <= 120:
        patterns.append(query)

    route_match = re.search(r"(/[\w/.{}:*$-]+)", query)
    if route_match:
        route_path = route_match.group(1).rstrip(".,;)")
        if route_path not in patterns:
            patterns.append(route_path)
        # Spring / JAX-RS style mapping fragments
        tail = route_path.rsplit("/", 1)[-1]
        if tail and len(tail) >= 2 and tail not in patterns:
            patterns.append(tail)

    results: list[dict] = []
    seen: set[tuple[str, int]] = set()
    started = time.perf_counter()
    scanned_files = 0
    line_checks = 0

    preferred_suffix = prefer.suffix.lower() if prefer else None
    passes: list[set[str] | None] = []
    if preferred_suffix and preferred_suffix in CODE_EXTENSIONS:
        passes.append({preferred_suffix})
    passes.append(None)  # fallback: cross-language search

    for allowed_suffixes in passes:
        iterators = []
        if prefer:
            iterators.append(_iter_nearby_source_files(prefer, allowed_suffixes=allowed_suffixes))
        iterators.append(_iter_source_files(project_path, prefer, allowed_suffixes=allowed_suffixes))
        for iterator in iterators:
            for path in iterator:
                scanned_files += 1
                if max_files_scanned is not None and scanned_files >= max_files_scanned:
                    return results
                if max_scan_seconds is not None and (time.perf_counter() - started) >= max_scan_seconds:
                    return results
                if cancel_check and (scanned_files % 10 == 0):
                    cancel_check()
                try:
                    if max_file_bytes is not None and path.stat().st_size > max_file_bytes:
                        continue
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue

                for idx, line in enumerate(lines, start=1):
                    line_checks += 1
                    # Also allow cancellation while scanning inside a large file.
                    if cancel_check and (line_checks % 1000 == 0):
                        cancel_check()
                    stripped = line.strip()
                    if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                        continue
                    hit = False
                    for pat in patterns:
                        if pat and pat in line:
                            hit = True
                            break
                    if not hit:
                        continue
                    key = (str(path.resolve()), idx)
                    if key in seen:
                        continue
                    seen.add(key)
                    same_file = bool(prefer and path.resolve() == prefer.resolve())
                    same_lang = bool(preferred_suffix and path.suffix.lower() == preferred_suffix)
                    confidence = 0.45
                    if same_file:
                        confidence += 0.35
                    if same_lang:
                        confidence += 0.2
                    if symbol and symbol in stripped:
                        confidence += 0.1
                    if route_match and route_path in stripped:
                        confidence += 0.25
                    if "Mapping" in stripped and route_match and route_path in stripped:
                        confidence += 0.15
                    confidence = min(0.99, confidence)
                    results.append({
                        "file_path": to_repo_relative_path(path.resolve(), project_path),
                        "line_start": idx,
                        "line_end": idx,
                        "matched_text": stripped[:200],
                        "confidence": round(confidence, 2),
                        "strategy": "symbol_search",
                        "language_matched": same_lang,
                    })
                    if len(results) >= limit:
                        return results

        # If same-language pass already found candidates, don't dilute with other languages.
        if results and allowed_suffixes is not None:
            return results

    return results
