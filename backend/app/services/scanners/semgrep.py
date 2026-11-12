import asyncio
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from app.config import settings
from app.services.path_filters import merge_semgrep_excludes, should_skip_walk_part
from app.services.project_languages import LANGUAGE_TO_PACK, packs_for_languages
from app.services.scanners.base import BaseScanner, ScannerRunResult
from app.services.scanners.common import finding, parse_json_output, read_code_snippet, resolve_file_path

logger = logging.getLogger(__name__)

# Optional project scan_languages override for the current async task.
# None / empty = existing auto / global semgrep_config behavior.
_forced_languages_ctx: ContextVar[tuple[str, ...] | None] = ContextVar(
    "semgrep_forced_languages", default=None
)


def set_forced_scan_languages(langs: list[str] | None):
    """Set forced languages for Semgrep planning in the current task. Returns reset token."""
    cleaned = tuple(str(x).strip().lower() for x in (langs or []) if str(x).strip())
    return _forced_languages_ctx.set(cleaned or None)


def reset_forced_scan_languages(token) -> None:
    _forced_languages_ctx.reset(token)


def get_forced_scan_languages() -> tuple[str, ...] | None:
    return _forced_languages_ctx.get()


SECURITY_BASE_CONFIGS = ["p/security-audit", "p/owasp-top-ten"]
SMALL_PROJECT_MAX_FILES = 20
DOMINANT_LANG_RATIO = 0.65
# Above this source-file count, drop overlapping rule packs / narrow includes.
LARGE_PROJECT_SOURCE_FILES = 800

EXT_TO_CONFIG = {
    ".py": "p/python",
    ".js": "p/javascript",
    ".jsx": "p/javascript",
    ".ts": "p/typescript",
    ".tsx": "p/typescript",
    ".go": "p/golang",
    ".java": "p/java",
    ".php": "p/php",
    ".rb": "p/ruby",
    ".cs": "p/csharp",
    ".kt": "p/kotlin",
    ".rs": "p/rust",
}

CONFIG_TO_INCLUDE_GLOBS: dict[str, list[str]] = {
    "p/python": ["*.py"],
    "p/javascript": ["*.js", "*.jsx", "*.mjs", "*.cjs"],
    "p/typescript": ["*.ts", "*.tsx"],
    "p/golang": ["*.go"],
    "p/java": ["*.java", "*.kt", "*.kts"],
    "p/kotlin": ["*.kt", "*.kts", "*.java"],
    "p/php": ["*.php"],
    "p/ruby": ["*.rb"],
    "p/csharp": ["*.cs"],
    "p/rust": ["*.rs"],
}

# Top-level dirs that rarely need Semgrep (CI / Maven wrapper / docs).
SKIP_SCAN_TARGET_DIRS = frozenset({
    ".github", ".gitlab", ".circleci", ".mvn", ".idea", ".vscode",
    "docs", "doc", "charts", "helm", "deploy", "deployment",
    "installer", "scripts", "tools",
})

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build",
    "vendor", "target", ".idea", ".vscode", "coverage", ".next",
    ".gradle", ".m2", "out", "bin", "obj", ".tox", ".cache",
    "uploads", "repos", ".tools", "test-results", "logs",
}

DEFAULT_EXCLUDES = [
    "node_modules",
    "**/node_modules/**",
    "target",
    "**/target/**",
    "build",
    "dist",
    ".git",
    "vendor",
    "__pycache__",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    ".gradle",
    ".m2",
    "*.min.js",
    "*.map",
]

# Prefer scanning source-like files so dependency trees are not enumerated.
SOURCE_INCLUDE_GLOBS = [
    "*.java", "*.kt", "*.kts",
    "*.py",
    "*.go",
    "*.js", "*.jsx", "*.mjs", "*.cjs",
    "*.ts", "*.tsx",
    "*.php",
    "*.rb",
    "*.cs",
    "*.rs",
    "*.vue",
]

# Avoid recounting huge trees on every scanner step (timeout_seconds + scan + progress).
_PLAN_CACHE: dict[str, tuple[float, "SemgrepPlan"]] = {}
_PLAN_CACHE_TTL_SEC = 120.0


@dataclass
class SemgrepPlan:
    configs: list[str]
    config_reason: str
    file_count: int
    source_file_count: int
    rule_timeout: int
    wall_timeout: int
    include_globs: list[str]
    source_counts: dict[str, int]


def _iter_files(project_path: Path, *, max_files: int | None = 80000):
    """Walk source tree without descending into SKIP_DIRS (rglob still enters them)."""
    root = project_path.resolve()
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    name = entry.name
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if should_skip_walk_part(name, SKIP_DIRS):
                                continue
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                            count += 1
                            if max_files is not None and count >= max_files:
                                return
                    except OSError:
                        continue
        except OSError:
            continue


def count_project_files(project_path: Path) -> int:
    try:
        return sum(1 for _ in _iter_files(project_path))
    except Exception:
        return 0


def count_source_files(project_path: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for path in _iter_files(project_path):
        cfg = EXT_TO_CONFIG.get(path.suffix.lower())
        if cfg:
            counts[cfg] += 1
    return counts


def pick_semgrep_config(project_path: Path, source_counts: Counter[str]) -> tuple[str, str]:
    """Pick primary language pack when auto mode is enabled."""
    configured = settings.semgrep_config
    if configured != "auto":
        return configured, f"使用配置: {configured}"

    if not source_counts:
        return "p/security-audit", "未识别源码语言，使用 p/security-audit"

    total = sum(source_counts.values())
    dominant, dom_count = source_counts.most_common(1)[0]
    ratio = dom_count / total

    if ratio >= DOMINANT_LANG_RATIO:
        pct = int(ratio * 100)
        return dominant, f"主语言 {dominant}（{dom_count}/{total} 源码文件，{pct}%）"

    if len(source_counts) == 1:
        only = next(iter(source_counts))
        return only, f"单语言项目使用 {only}"

    langs = ", ".join(f"{k}:{v}" for k, v in source_counts.most_common(3))
    return "p/security-audit", f"多语言项目（{langs}），使用安全规则包（不使用 auto）"


def resolve_semgrep_configs(project_path: Path, source_counts: Counter[str]) -> tuple[list[str], str]:
    """Always include security rule packs; add language pack when auto.

    When ``forced_languages`` context is set (project scan_languages), skip auto/
    global config and attach SECURITY_BASE_CONFIGS + packs for each forced language
    that has matching source files.
    """
    configs: list[str] = []
    reasons: list[str] = []
    forced = _forced_languages_ctx.get()

    if forced:
        configs.extend(SECURITY_BASE_CONFIGS)
        reasons.append("安全规则: " + ", ".join(SECURITY_BASE_CONFIGS))
        reasons.append(f"用户指定扫描语言: {', '.join(forced)}")
        for pack in packs_for_languages(list(forced)):
            if int(source_counts.get(pack, 0) or 0) <= 0:
                logger.info("Skipping Semgrep pack %s: no matching source files", pack)
                reasons.append(f"跳过 {pack}（仓库无对应源码）")
                continue
            if pack not in configs:
                configs.append(pack)
                reasons.append(f"强制语言包: {pack}")
    else:
        configured = (settings.semgrep_config or "auto").strip() or "auto"
        if configured == "auto":
            configs.extend(SECURITY_BASE_CONFIGS)
            reasons.append("安全规则: " + ", ".join(SECURITY_BASE_CONFIGS))
            lang, lang_reason = pick_semgrep_config(project_path, source_counts)
            if lang not in configs and lang != "auto":
                configs.append(lang)
                reasons.append(lang_reason)
            else:
                reasons.append(lang_reason)
        else:
            if configured not in SECURITY_BASE_CONFIGS:
                configs.extend(SECURITY_BASE_CONFIGS)
                reasons.append("附加安全规则: " + ", ".join(SECURITY_BASE_CONFIGS))
            if configured not in configs and configured != "auto":
                configs.append(configured)
            reasons.append(f"用户配置: {configured}")

    # Deduplicate while preserving order; never keep "auto" (needs Semgrep metrics).
    seen: set[str] = set()
    unique: list[str] = []
    for cfg in configs:
        if cfg == "auto" or cfg in seen:
            continue
        seen.add(cfg)
        unique.append(cfg)
    if not unique:
        unique = list(SECURITY_BASE_CONFIGS)
        reasons.append("已将 auto 替换为安全规则包（metrics 关闭时 auto 不可用）")

    source_total = sum(source_counts.values())
    # Large monorepos: security-audit overlaps heavily with owasp-top-ten; keep one.
    if (
        source_total >= LARGE_PROJECT_SOURCE_FILES
        and "p/security-audit" in unique
        and "p/owasp-top-ten" in unique
    ):
        unique = [c for c in unique if c != "p/owasp-top-ten"]
        reasons.append("大型项目已精简 p/owasp-top-ten（保留 p/security-audit）")

    return unique, "；".join(reasons)


def semgrep_wall_timeout(file_count: int, config_count: int) -> int:
    if file_count <= SMALL_PROJECT_MAX_FILES:
        base = 180
    elif file_count <= 500:
        base = 600
    elif file_count <= 1500:
        base = 1200
    else:
        base = 1800
    return min(base + (config_count - 1) * 120, settings.semgrep_timeout)


def semgrep_rule_timeout(file_count: int, config_count: int) -> int:
    if file_count <= SMALL_PROJECT_MAX_FILES:
        base = 45
    elif file_count > 500:
        base = 180
    else:
        base = 90
    return min(base, settings.semgrep_timeout)


def _dominant_lang_config(source_counts: Counter[str]) -> str | None:
    if not source_counts:
        return None
    total = sum(source_counts.values())
    if total <= 0:
        return None
    dominant, count = source_counts.most_common(1)[0]
    if count / total >= DOMINANT_LANG_RATIO:
        return dominant
    return None


def _include_globs_for_plan(configs: list[str], source_counts: Counter[str]) -> list[str]:
    """
    For large dominant-language repos, only include that language's globs so
    Semgrep does not spend wall time on secondary frontend trees.

    When languages are forced by the project, merge globs for those packs instead
    of narrowing to a single dominant language.
    """
    forced = _forced_languages_ctx.get()
    if forced:
        globs: list[str] = []
        seen: set[str] = set()
        for cfg in configs:
            for g in CONFIG_TO_INCLUDE_GLOBS.get(cfg, []):
                if g not in seen:
                    seen.add(g)
                    globs.append(g)
        if not globs:
            for pack in packs_for_languages(list(forced)):
                for g in CONFIG_TO_INCLUDE_GLOBS.get(pack, []):
                    if g not in seen:
                        seen.add(g)
                        globs.append(g)
        return globs or list(SOURCE_INCLUDE_GLOBS)

    source_total = sum(source_counts.values())
    dominant = _dominant_lang_config(source_counts)
    if source_total >= LARGE_PROJECT_SOURCE_FILES and dominant:
        globs = list(CONFIG_TO_INCLUDE_GLOBS.get(dominant, []))
        if globs:
            return globs

    # Prefer includes from selected language packs; fall back to all source globs.
    globs = []
    seen = set()
    for cfg in configs:
        for g in CONFIG_TO_INCLUDE_GLOBS.get(cfg, []):
            if g not in seen:
                seen.add(g)
                globs.append(g)
    return globs or list(SOURCE_INCLUDE_GLOBS)


def plan_semgrep_scan(project_path: Path) -> SemgrepPlan:
    forced = _forced_languages_ctx.get()
    forced_key = ",".join(forced) if forced else ""
    key = f"{project_path.resolve()}|{forced_key}"
    cached = _PLAN_CACHE.get(key)
    now = time.monotonic()
    if cached and (now - cached[0]) < _PLAN_CACHE_TTL_SEC:
        return cached[1]

    # Single walk: file totals + language counts (previously walked twice).
    file_count = 0
    source_counts: Counter[str] = Counter()
    for path in _iter_files(project_path):
        file_count += 1
        cfg = EXT_TO_CONFIG.get(path.suffix.lower())
        if cfg:
            source_counts[cfg] += 1

    source_file_count = sum(source_counts.values())
    configs, reason = resolve_semgrep_configs(project_path, source_counts)
    include_globs = _include_globs_for_plan(configs, source_counts)
    if (
        not forced
        and source_file_count >= LARGE_PROJECT_SOURCE_FILES
        and _dominant_lang_config(source_counts)
        and include_globs != list(SOURCE_INCLUDE_GLOBS)
    ):
        reason = f"{reason}；大型主语言项目仅扫描: {', '.join(include_globs)}"
    rule_timeout = semgrep_rule_timeout(source_file_count or file_count, len(configs))
    wall_timeout = semgrep_wall_timeout(source_file_count or file_count, len(configs))
    plan = SemgrepPlan(
        configs=configs,
        config_reason=reason,
        file_count=file_count,
        source_file_count=source_file_count,
        rule_timeout=rule_timeout,
        wall_timeout=wall_timeout,
        include_globs=include_globs,
        source_counts=dict(source_counts),
    )
    _PLAN_CACHE[key] = (now, plan)
    return plan


def _include_suffixes(include_globs: list[str]) -> set[str]:
    out: set[str] = set()
    for g in include_globs:
        # "*.java" -> ".java"
        if g.startswith("*.") and len(g) > 2:
            out.add("." + g.split(".", 1)[1].lower())
    return out


def _dir_has_included_files(root: Path, include_globs: list[str], *, max_checks: int = 12000) -> bool:
    suffixes = _include_suffixes(include_globs)
    # If no suffixes can be inferred, keep previous behavior.
    if not suffixes:
        return True
    checked = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    checked += 1
                    if checked > max_checks:
                        # Avoid expensive prewalk; assume relevant and let semgrep handle.
                        return True
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if should_skip_walk_part(entry.name, SKIP_DIRS):
                                continue
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            if Path(entry.name).suffix.lower() in suffixes:
                                return True
                    except OSError:
                        continue
        except OSError:
            continue
    return False


# Split dirs larger than this so semgrep-core target discovery stays bounded.
# Keep coarse: too many tiny shards → dozens of Semgrep cold starts on Windows.
_MAX_FILES_PER_TARGET = 600
_MAX_EXPAND_DEPTH = 2
# Hard cap on Semgrep process invocations per scan (targets are packed into batches).
_MAX_SHARD_BATCHES = 6

_ACTIVE_SEMGREP_PIDS: set[int] = set()
_ACTIVE_SEMGREP_LOCK = threading.Lock()


def _count_included_files(root: Path, include_globs: list[str], *, limit: int = 5000) -> int:
    suffixes = _include_suffixes(include_globs)
    if not suffixes:
        return 0
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if should_skip_walk_part(entry.name, SKIP_DIRS):
                                continue
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            if Path(entry.name).suffix.lower() in suffixes:
                                count += 1
                                if count >= limit:
                                    return count
                    except OSError:
                        continue
        except OSError:
            continue
    return count


def _expand_scan_target(dir_path: Path, include_globs: list[str], *, depth: int = 0) -> list[str]:
    """Expand oversized dirs into children; keep leaf dirs otherwise."""
    if depth >= _MAX_EXPAND_DEPTH:
        return [str(dir_path)]
    n = _count_included_files(dir_path, include_globs, limit=_MAX_FILES_PER_TARGET + 1)
    if n <= _MAX_FILES_PER_TARGET:
        return [str(dir_path)]

    children: list[str] = []
    try:
        with os.scandir(dir_path) as it:
            for entry in it:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    name = entry.name
                    if should_skip_walk_part(name, SKIP_DIRS):
                        continue
                    if name.lower() in {x.lower() for x in SKIP_SCAN_TARGET_DIRS}:
                        continue
                    child = Path(entry.path)
                    if not _dir_has_included_files(child, include_globs):
                        continue
                    children.extend(_expand_scan_target(child, include_globs, depth=depth + 1))
                except OSError:
                    continue
    except OSError:
        return [str(dir_path)]
    return children or [str(dir_path)]


def _target_arg(path: str | Path) -> str:
    """Forward-slash paths: semgrep-core on Windows mishandles some backslash roots."""
    return Path(path).resolve().as_posix()


def _semgrep_scan_targets(project_path: Path, include_globs: list[str]) -> list[str]:
    """
    Prefer top-level children that are not dependency/build dirs.

    Passing the monorepo root forces semgrep-core to enumerate huge trees
    (e.g. uploaded node_modules) before --exclude applies, which often fails
    on Windows with "Failed to obtain target files from semgrep-core".
    Oversized modules (e.g. backend/crm) are split further.
    """
    root = project_path.resolve()
    targets: list[str] = []
    try:
        with os.scandir(root) as it:
            for entry in it:
                name = entry.name
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if should_skip_walk_part(name, SKIP_DIRS):
                            continue
                        if name.lower() in {x.lower() for x in SKIP_SCAN_TARGET_DIRS}:
                            continue
                        dir_path = Path(entry.path)
                        if not _dir_has_included_files(dir_path, include_globs):
                            continue
                        targets.extend(_expand_scan_target(dir_path, include_globs))
                    elif entry.is_file(follow_symlinks=False):
                        if Path(name).suffix.lower() in _include_suffixes(include_globs):
                            targets.append(str(Path(entry.path)))
                except OSError:
                    continue
    except OSError:
        return [_target_arg(root)]
    raw = targets or [str(root)]
    return [_target_arg(t) for t in raw]


def pack_scan_targets(
    targets: list[str],
    *,
    max_batches: int = _MAX_SHARD_BATCHES,
) -> list[list[str]]:
    """
    Pack leaf targets into at most max_batches Semgrep invocations.

    Prefer contiguous chunks (same module tree stays together) over round-robin.
    """
    if not targets:
        return []
    if len(targets) <= max_batches:
        return [[t] for t in targets]
    batch_count = max(1, min(max_batches, len(targets)))
    # Even chunk sizes; last batch absorbs remainder.
    base = len(targets) // batch_count
    rem = len(targets) % batch_count
    batches: list[list[str]] = []
    idx = 0
    for i in range(batch_count):
        size = base + (1 if i < rem else 0)
        if size <= 0:
            continue
        batches.append(targets[idx : idx + size])
        idx += size
    return batches


def build_semgrep_base_command(plan: SemgrepPlan, project_path: Path) -> list[str]:
    """Build semgrep argv without scan roots (roots are appended per shard)."""
    jobs = "1" if sys.platform == "win32" else "2"
    cmd = [
        "semgrep", "scan",
        "--json", "--quiet",
        "--disable-version-check",
        "--timeout", str(plan.rule_timeout),
        "--jobs", jobs,
        # Always skip git ls-files. Semgrep 1.159+ raises
        # "Failed to obtain target files from semgrep-core" when VCS discovery
        # RPC fails (common on Windows GitLab clones). Our --exclude list
        # already covers node_modules / build trees.
        "--no-git-ignore",
    ]
    for cfg in plan.configs:
        if cfg == "auto":
            continue
        cmd.extend(["--config", cfg])
    if not any(c != "auto" for c in plan.configs):
        for cfg in SECURITY_BASE_CONFIGS:
            cmd.extend(["--config", cfg])
    cmd.extend(["--metrics", "off"])
    for pattern in merge_semgrep_excludes(DEFAULT_EXCLUDES):
        cmd.extend(["--exclude", pattern])
    for pattern in plan.include_globs or SOURCE_INCLUDE_GLOBS:
        cmd.extend(["--include", pattern])
    return cmd


def build_semgrep_command(plan: SemgrepPlan, project_path: Path) -> list[str]:
    """Full command (base + all targets). Prefer sharded runs via scan()."""
    cmd = build_semgrep_base_command(plan, project_path)
    cmd.extend(_semgrep_scan_targets(project_path, plan.include_globs or SOURCE_INCLUDE_GLOBS))
    return cmd


def _findings_from_semgrep_json(data: dict, project_path: Path) -> list[dict]:
    findings: list[dict] = []
    for item in data.get("results", []) or []:
        extra = item.get("extra", {}) or {}
        metadata = dict(extra.get("metadata", {}) or {})
        dataflow_trace = extra.get("dataflow_trace")
        if dataflow_trace:
            metadata["dataflow_trace"] = dataflow_trace
        metavars = extra.get("metavars")
        if metavars:
            simplified = {}
            for name, val in metavars.items():
                if isinstance(val, dict):
                    simplified[name] = {
                        "start": val.get("start"),
                        "end": val.get("end"),
                        "abstract_content": val.get("abstract_content"),
                    }
            metadata["metavars"] = simplified
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}
        rel_path = item.get("path", "")
        abs_path = resolve_file_path(project_path, rel_path)
        line_start = start.get("line", 0)

        findings.append(finding(
            tool="semgrep",
            rule_id=item.get("check_id") or metadata.get("rule_id", "unknown"),
            check_id=item.get("check_id"),
            severity=extra.get("severity") or metadata.get("severity", "MEDIUM"),
            message=extra.get("message", "Security issue detected"),
            file_path=str(abs_path),
            line_start=line_start,
            line_end=end.get("line", line_start),
            code_snippet=read_code_snippet(abs_path, line_start),
            metadata=metadata,
            project_path=project_path,
        ))
    return findings


def _is_target_discovery_error(payload: str) -> bool:
    text = (payload or "").lower()
    return "failed to obtain target files from semgrep-core" in text


def _run_semgrep_shards(
    plan: SemgrepPlan,
    project_path: Path,
    targets: list[str],
    wall_timeout: int,
) -> tuple[list[dict], dict]:
    """
    Run Semgrep in a small number of batches and merge findings.

    Tiny per-directory shards cause dozens of cold starts on Windows; pack
    targets into at most _MAX_SHARD_BATCHES process invocations.
    """
    base = build_semgrep_base_command(plan, project_path)
    batches = pack_scan_targets(
        targets,
        # Windows: one invocation with all roots. Splitting into per-dir shards
        # with cwd=repo-root reproduces "Failed to obtain target files from
        # semgrep-core" on 1.166; the same roots in a single argv succeed.
        max_batches=1 if sys.platform == "win32" else _MAX_SHARD_BATCHES,
    )
    findings: list[dict] = []
    shard_reports: list[dict] = []
    version: str | None = None
    started = time.monotonic()
    n = max(1, len(batches))
    # Budget wall time across batches; each gets a fair share with a floor/cap.
    per_shard_cap = max(240, min(900, wall_timeout // n + 180))

    for idx, batch in enumerate(batches):
        elapsed = time.monotonic() - started
        remaining = wall_timeout - elapsed
        if remaining < 45:
            shard_reports.append({
                "targets": batch,
                "skipped": True,
                "reason": "wall_timeout_budget_exhausted",
            })
            break

        shard_timeout = int(min(remaining, per_shard_cap))
        cmd = [*base, *batch]
        try:
            returncode, stdout, stderr = _run_semgrep_subprocess(
                cmd, shard_timeout, cwd=project_path,
            )
            combined = f"{stdout}\n{stderr}"
            if _is_target_discovery_error(combined) and len(batch) > 1:
                # One bad root can fail the whole RPC; retry this batch per-root.
                logger.warning(
                    "Semgrep target discovery failed for batch of %s roots; retrying per-root",
                    len(batch),
                )
                for one in batch:
                    one_timeout = max(60, min(shard_timeout, 300))
                    rc2, out2, err2 = _run_semgrep_subprocess(
                        [*base, one], one_timeout, cwd=project_path,
                    )
                    returncode, stdout, stderr = rc2, out2, err2
                    if rc2 in (0, 1) and not _is_target_discovery_error(f"{out2}\n{err2}"):
                        try:
                            data = parse_json_output(out2 or "{}", "semgrep")
                        except Exception as exc:
                            shard_reports.append({
                                "targets": [one],
                                "exit_code": rc2,
                                "error": f"parse_failed: {exc}",
                            })
                            continue
                        if not isinstance(data, dict):
                            data = {}
                        if data.get("version"):
                            version = str(data.get("version"))
                        batch_findings = _findings_from_semgrep_json(data, project_path)
                        findings.extend(batch_findings)
                        shard_reports.append({
                            "targets": [one],
                            "exit_code": rc2,
                            "findings": len(batch_findings),
                            "scanned": len(((data.get("paths") or {}).get("scanned")) or []),
                            "retried": True,
                        })
                    else:
                        shard_reports.append({
                            "targets": [one],
                            "exit_code": rc2,
                            "error": (err2 or out2 or "semgrep failed")[:500],
                            "discovery_error": _is_target_discovery_error(err2 or out2 or ""),
                            "retried": True,
                        })
                continue
        except subprocess.TimeoutExpired:
            shard_reports.append({
                "targets": batch,
                "error": f"timeout>{shard_timeout}s",
                "exit_code": None,
            })
            continue

        raw = (stdout or stderr or "").strip()
        if returncode not in (0, 1):
            shard_reports.append({
                "targets": batch,
                "exit_code": returncode,
                "error": (stderr or stdout or "semgrep failed")[:500],
                "discovery_error": _is_target_discovery_error(stderr or stdout or ""),
            })
            continue

        try:
            data = parse_json_output(stdout or "{}", "semgrep")
        except Exception as exc:
            shard_reports.append({
                "targets": batch,
                "exit_code": returncode,
                "error": f"parse_failed: {exc}",
            })
            continue

        if not isinstance(data, dict):
            data = {}
        if data.get("version"):
            version = str(data.get("version"))
        batch_findings = _findings_from_semgrep_json(data, project_path)
        findings.extend(batch_findings)
        shard_reports.append({
            "targets": batch,
            "exit_code": returncode,
            "findings": len(batch_findings),
            "scanned": len(((data.get("paths") or {}).get("scanned")) or []),
        })
        logger.info(
            "Semgrep batch %s/%s (%s roots) -> %s findings",
            idx + 1,
            n,
            len(batch),
            len(batch_findings),
        )

    detail = {
        "command": " ".join(base) + " <shard-batch>",
        "configs": plan.configs,
        "include_globs": plan.include_globs,
        "config_reason": plan.config_reason,
        "file_count": plan.file_count,
        "source_file_count": plan.source_file_count,
        "source_counts": dict(plan.source_counts),
        "target_count": len(targets),
        "shard_count": len(batches),
        "shards": shard_reports,
        "version": version,
    }
    detail["rule_inventory"] = _attach_rule_inventory(plan.configs, plan.source_counts)
    return findings, detail


def _attach_rule_inventory(
    configs: list[str],
    source_counts: dict[str, int] | None = None,
) -> dict:
    """Resolve registry rule packs into a persisted inventory summary."""
    from app.services.semgrep_rule_inventory import (
        CONFIG_TO_LANGUAGES,
        build_rule_inventory_summary,
        languages_from_source_counts,
    )

    fact_langs = languages_from_source_counts(source_counts)
    forced = _forced_languages_ctx.get()
    if forced:
        forced_tags: set[str] = set()
        for lang in forced:
            forced_tags.add(lang)
            pack = LANGUAGE_TO_PACK.get(lang)
            if pack:
                forced_tags |= set(CONFIG_TO_LANGUAGES.get(pack, ()))
        # Forced ∩ detected; empty intersection falls back to forced tags.
        project_languages = (fact_langs & forced_tags) if fact_langs else set(forced_tags)
        if not project_languages:
            project_languages = forced_tags
    else:
        project_languages = fact_langs
    try:
        return build_rule_inventory_summary(
            configs,
            project_languages=project_languages or None,
        )
    except Exception as exc:
        logger.warning("Semgrep rule inventory failed: %s", exc)
        return {
            "source": "error",
            "configs": list(configs),
            "total_rules": 0,
            "by_subtype": {},
            "by_owasp": {},
            "sample_rules_by_subtype": {},
            "sample_rules_by_owasp": {},
            "inventory_error": str(exc)[:500],
            "resolved_at": None,
            "project_languages": sorted(project_languages),
            "filtered": bool(project_languages),
            "unfiltered_total_rules": 0,
        }


def kill_active_semgrep_processes() -> int:
    """Force-kill Semgrep process trees tracked by this scanner (timeout/cancel)."""
    with _ACTIVE_SEMGREP_LOCK:
        pids = list(_ACTIVE_SEMGREP_PIDS)
        _ACTIVE_SEMGREP_PIDS.clear()
    killed = 0
    for pid in pids:
        _kill_process_tree(pid)
        killed += 1
    if killed:
        logger.warning("Force-killed %s active Semgrep process tree(s)", killed)
    return killed


def _kill_process_tree(pid: int) -> None:
    if pid <= 0:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=10,
            )
        else:
            import signal

            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except ProcessLookupError:
                os.kill(pid, signal.SIGKILL)
    except Exception:
        logger.warning("Failed to kill semgrep process tree pid=%s", pid, exc_info=True)


def _run_semgrep_subprocess(
    cmd: list[str],
    wall_timeout: int,
    *,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    env = os.environ.copy()
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(cwd) if cwd else None,
        env=env,
        creationflags=creationflags,
    )
    with _ACTIVE_SEMGREP_LOCK:
        _ACTIVE_SEMGREP_PIDS.add(proc.pid)
    try:
        try:
            stdout, stderr = proc.communicate(timeout=wall_timeout)
            return proc.returncode, stdout or "", stderr or ""
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            raise
    finally:
        with _ACTIVE_SEMGREP_LOCK:
            _ACTIVE_SEMGREP_PIDS.discard(proc.pid)


class SemgrepScanner(BaseScanner):
    id = "semgrep"
    name = "Semgrep"
    description = "多语言静态分析，覆盖 OWASP Top 10 等安全规则"
    category = "sast"
    install_hint = "pip install semgrep  或 https://semgrep.dev/docs/getting-started/"

    async def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    async def availability_reason(self) -> str | None:
        if await self.is_available():
            return None
        return "未检测到 semgrep 可执行文件"

    async def timeout_seconds(self, project_path: Path) -> int:
        plan = await asyncio.to_thread(plan_semgrep_scan, project_path)
        return min(settings.semgrep_timeout, plan.wall_timeout) + 30

    async def scan(self, project_path: Path) -> ScannerRunResult:
        plan = await asyncio.to_thread(plan_semgrep_scan, project_path)
        include_globs = plan.include_globs or SOURCE_INCLUDE_GLOBS
        targets = await asyncio.to_thread(_semgrep_scan_targets, project_path, include_globs)
        started = time.monotonic()

        def _run():
            return _run_semgrep_shards(plan, project_path, targets, plan.wall_timeout)

        try:
            findings, detail = await asyncio.to_thread(_run)
        except subprocess.TimeoutExpired:
            kill_active_semgrep_processes()
            elapsed = int(time.monotonic() - started)
            timeout_detail = {
                "configs": plan.configs,
                "include_globs": plan.include_globs,
                "config_reason": plan.config_reason,
                "wall_timeout": plan.wall_timeout,
                "rule_timeout": plan.rule_timeout,
                "file_count": plan.file_count,
                "source_file_count": plan.source_file_count,
                "source_counts": dict(plan.source_counts),
                "target_count": len(targets),
                "shard_count": len(pack_scan_targets(targets)),
                "elapsed_seconds": elapsed,
            }
            timeout_detail["rule_inventory"] = _attach_rule_inventory(plan.configs, plan.source_counts)
            return ScannerRunResult(
                scanner_id=self.id,
                detail=timeout_detail,
                error=f"Semgrep 进程超时（>{plan.wall_timeout}秒），已强制终止",
            )
        except asyncio.CancelledError:
            kill_active_semgrep_processes()
            raise

        elapsed = round(time.monotonic() - started, 1)
        detail = {
            **detail,
            "elapsed_seconds": elapsed,
            "wall_timeout": plan.wall_timeout,
            "rule_timeout": plan.rule_timeout,
            "result_count": len(findings),
        }
        shard_reports = detail.get("shards") or []
        failed = [s for s in shard_reports if s.get("error") or s.get("skipped")]
        ok = [s for s in shard_reports if not s.get("error") and not s.get("skipped")]

        if not findings and not ok:
            err_bits = [
                str(s.get("error") or s.get("reason") or "failed")[:300]
                for s in failed[:3]
            ]
            return ScannerRunResult(
                scanner_id=self.id,
                detail=detail,
                error=("; ".join(err_bits) or "semgrep failed")[:2000],
            )

        if failed:
            detail["partial_errors"] = len(failed)
            logger.warning(
                "Semgrep completed with %s/%s shard failures (%s findings kept)",
                len(failed),
                len(shard_reports),
                len(findings),
            )

        return ScannerRunResult(
            scanner_id=self.id,
            version=detail.get("version"),
            findings=findings,
            detail=detail,
        )
