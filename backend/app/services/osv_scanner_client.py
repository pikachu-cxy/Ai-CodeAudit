"""Thin wrapper around Google osv-scanner CLI for Maven/Java results."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
from app.services.path_filters import BASE_SKIP_DIRS, should_skip_walk_path
from app.services.scanners.common import parse_json_output

logger = logging.getLogger(__name__)

_SKIP = set(BASE_SKIP_DIRS) | {"node_modules", ".git"}
_MAX_LOCKFILES = 40


@dataclass
class OsvPackageVuln:
    ecosystem: str
    package: str
    version: str
    vuln_ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    source_path: str = ""


def _candidate_paths() -> list[Path]:
    """Extra locations when PATH is stale (common after WinGet install without relaunch)."""
    candidates: list[Path] = []
    configured = (getattr(settings, "osv_scanner_path", None) or "").strip()
    if configured:
        candidates.append(Path(configured))
    env_path = (os.environ.get("OSV_SCANNER_PATH") or "").strip()
    if env_path:
        candidates.append(Path(env_path))

    local_app = os.environ.get("LOCALAPPDATA") or ""
    if local_app:
        winget_pkgs = Path(local_app) / "Microsoft" / "WinGet" / "Packages"
        if winget_pkgs.is_dir():
            for pkg_dir in winget_pkgs.glob("Google.OSVScanner*"):
                exe = pkg_dir / "osv-scanner.exe"
                if exe.is_file():
                    candidates.append(exe)
        links = Path(local_app) / "Microsoft" / "WinGet" / "Links" / "osv-scanner.exe"
        candidates.append(links)

    home = Path.home()
    candidates.extend(
        [
            home / "go" / "bin" / "osv-scanner.exe",
            home / "go" / "bin" / "osv-scanner",
            home / "scoop" / "shims" / "osv-scanner.exe",
            Path("C:/ProgramData/chocolatey/bin/osv-scanner.exe"),
        ]
    )
    return candidates


def resolve_osv_scanner() -> str | None:
    """Resolve osv-scanner binary for subprocess (Windows-friendly)."""
    if sys.platform == "win32":
        for name in ("osv-scanner.exe", "osv-scanner"):
            found = shutil.which(name)
            if found:
                return found
    else:
        found = shutil.which("osv-scanner")
        if found:
            return found

    for path in _candidate_paths():
        try:
            if path.is_file():
                return str(path.resolve())
        except OSError:
            continue
    return None


def osv_scanner_available() -> bool:
    return resolve_osv_scanner() is not None


def discover_maven_manifests(project_path: Path, *, limit: int = _MAX_LOCKFILES) -> list[Path]:
    """Find pom.xml files under project (relative skip dirs; works under data/repos)."""
    root = project_path.resolve()
    found: list[Path] = []
    if (root / "pom.xml").is_file():
        found.append(root / "pom.xml")
    for path in root.rglob("pom.xml"):
        if should_skip_walk_path(path, _SKIP, relative_to=root):
            continue
        resolved = path.resolve()
        if resolved not in {p.resolve() for p in found}:
            found.append(resolved)
        if len(found) >= limit:
            break
    return found[:limit]


def build_osv_scan_commands(exe: str, project_path: Path, lockfiles: list[Path]) -> list[list[str]]:
    """Build osv-scanner v2 commands; prefer lockfile feed for Maven on Windows.

    osv-scanner 2.x: ``scan source -f json ...``
    Recursive directory scan is unreliable for pom.xml discovery on some Windows
    setups, so Maven uses repeated ``--lockfile`` (pom.xml is accepted).
    ``--no-resolve`` avoids private parent POM / deps.dev resolution failures.
    """
    cmds: list[list[str]] = []
    if lockfiles:
        cmd = [
            exe,
            "scan",
            "source",
            "--format",
            "json",
            "--verbosity",
            "error",
            "--no-resolve",
        ]
        for lf in lockfiles:
            cmd.extend(["--lockfile", str(lf)])
        cmds.append(cmd)

    # Fallback / supplement: recursive source scan from project cwd (relative ".").
    cmds.append(
        [
            exe,
            "scan",
            "source",
            "--format",
            "json",
            "--verbosity",
            "error",
            "--no-resolve",
            "-r",
            ".",
        ]
    )
    # Legacy v1-style (still works on some installs).
    cmds.append([exe, "--format", "json", "-r", str(project_path.resolve())])
    return cmds


def _normalize_ecosystem(raw: str) -> str:
    text = (raw or "").strip().lower()
    if text in {"maven", "java"}:
        return "Maven"
    return raw or ""


def _is_maven(ecosystem: str) -> bool:
    return _normalize_ecosystem(ecosystem) == "Maven"


def _extract_json_payload(text: str) -> Any:
    raw = (text or "").strip()
    if not raw:
        return {}
    try:
        return parse_json_output(raw, "osv-scanner")
    except RuntimeError:
        start = raw.find("{")
        if start < 0:
            raise
        return parse_json_output(raw[start:], "osv-scanner")


def parse_osv_scanner_json(data: dict | list | Any) -> list[OsvPackageVuln]:
    """Parse osv-scanner --format json output into Maven package vulns."""
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []

    out: list[OsvPackageVuln] = []
    for block in results:
        if not isinstance(block, dict):
            continue
        source = block.get("source") if isinstance(block.get("source"), dict) else {}
        source_path = str(source.get("path") or "")
        packages = block.get("packages")
        if not isinstance(packages, list):
            continue
        for pkg_block in packages:
            if not isinstance(pkg_block, dict):
                continue
            pkg = pkg_block.get("package") if isinstance(pkg_block.get("package"), dict) else {}
            ecosystem = str(pkg.get("ecosystem") or "")
            if not _is_maven(ecosystem):
                continue
            name = str(pkg.get("name") or "").strip()
            version = str(pkg.get("version") or "").strip()
            if not name:
                continue
            vulns = pkg_block.get("vulnerabilities") or pkg_block.get("vulns") or []
            ids: list[str] = []
            aliases: list[str] = []
            summary = ""
            if isinstance(vulns, list):
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    vid = str(vuln.get("id") or "").strip()
                    if vid:
                        ids.append(vid)
                    for alias in vuln.get("aliases") or []:
                        if alias:
                            aliases.append(str(alias))
                    if not summary:
                        summary = str(vuln.get("summary") or vuln.get("details") or "")[:300]
            # osv-scanner 2.x may put ids under groups when vulns list is compact.
            for group in pkg_block.get("groups") or []:
                if not isinstance(group, dict):
                    continue
                for vid in group.get("ids") or []:
                    if vid and str(vid) not in ids:
                        ids.append(str(vid))
                for alias in group.get("aliases") or []:
                    if alias and str(alias) not in aliases:
                        aliases.append(str(alias))
            if not ids and not aliases:
                continue
            out.append(
                OsvPackageVuln(
                    ecosystem="Maven",
                    package=name,
                    version=version,
                    vuln_ids=ids,
                    aliases=aliases,
                    summary=summary,
                    source_path=source_path,
                )
            )
    return out


def _merge_vulns(items: list[OsvPackageVuln]) -> list[OsvPackageVuln]:
    by_key: dict[tuple[str, str], OsvPackageVuln] = {}
    for item in items:
        key = (item.package.lower(), item.version)
        existing = by_key.get(key)
        if not existing:
            by_key[key] = item
            continue
        existing.vuln_ids = list(dict.fromkeys([*existing.vuln_ids, *item.vuln_ids]))
        existing.aliases = list(dict.fromkeys([*existing.aliases, *item.aliases]))
        if not existing.summary and item.summary:
            existing.summary = item.summary
        if not existing.source_path and item.source_path:
            existing.source_path = item.source_path
    return list(by_key.values())


async def run_osv_scanner(project_path: Path) -> tuple[list[OsvPackageVuln], dict]:
    """Run osv-scanner (v2 lockfile feed preferred); return Maven vulns + detail."""
    exe = resolve_osv_scanner()
    root = project_path.resolve()
    detail: dict[str, Any] = {"engine": "osv-scanner", "available": bool(exe)}
    if not exe:
        detail["skipped"] = "osv-scanner not found"
        return [], detail

    lockfiles = discover_maven_manifests(root)
    detail["lockfiles"] = [str(p) for p in lockfiles]
    detail["lockfile_count"] = len(lockfiles)

    timeout = max(60, int(getattr(settings, "scanner_timeout", 120) or 120))
    attempts: list[dict[str, Any]] = []
    collected: list[OsvPackageVuln] = []

    for cmd in build_osv_scan_commands(exe, root, lockfiles):
        mode = "lockfile" if "--lockfile" in cmd else ("recursive_cwd" if cmd[-1] == "." else "legacy")
        attempt: dict[str, Any] = {"mode": mode, "cmd_tail": cmd[1:8]}

        def _run(command: list[str] = cmd, cwd: str | None = str(root) if mode != "legacy" else None):
            return subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )

        try:
            proc = await asyncio.to_thread(_run)
        except FileNotFoundError as exc:
            attempt["error"] = f"cannot start osv-scanner: {exc}"
            attempts.append(attempt)
            break
        except subprocess.TimeoutExpired:
            attempt["error"] = "timed out"
            attempts.append(attempt)
            continue

        attempt["returncode"] = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        # 0 = clean, 1 = vulns found; 128 often "no package sources" on bad discovery.
        if proc.returncode not in (0, 1):
            attempt["error"] = (stderr or stdout or "osv-scanner failed")[:800]
            attempts.append(attempt)
            continue

        try:
            data = _extract_json_payload(stdout)
        except RuntimeError as exc:
            attempt["error"] = str(exc)[:500]
            # Sometimes JSON is on stderr mixed with warnings.
            try:
                data = _extract_json_payload(stderr)
            except RuntimeError:
                attempts.append(attempt)
                continue

        vulns = parse_osv_scanner_json(data)
        attempt["maven_package_vulns"] = len(vulns)
        attempts.append(attempt)
        if vulns:
            collected.extend(vulns)
            # Lockfile mode is enough when it yields results.
            if mode == "lockfile":
                break

    detail["attempts"] = attempts
    merged = _merge_vulns(collected)
    detail["maven_package_vulns"] = len(merged)
    if not merged and attempts:
        last_err = next((a.get("error") for a in reversed(attempts) if a.get("error")), None)
        if last_err:
            detail["error"] = last_err
    return merged, detail
