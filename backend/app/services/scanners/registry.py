import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.config import settings
from app.services.scanners.bandit import BanditScanner
from app.services.scanners.base import BaseScanner, ScannerInfo, ScannerRunResult
from app.services.scanners.codeql import CodeqlScanner
from app.services.scanners.dep_exploit import DepExploitScanner
from app.services.scanners.gitleaks import GitleaksScanner
from app.services.scanners.npm_audit import NpmAuditScanner
from app.services.scanners.pip_audit import PipAuditScanner
from app.services.scanners.semgrep import SemgrepScanner, kill_active_semgrep_processes

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, int, str | None], Awaitable[None]]

ALL_SCANNERS: list[BaseScanner] = [
    SemgrepScanner(),
    CodeqlScanner(),
    BanditScanner(),
    GitleaksScanner(),
    NpmAuditScanner(),
    PipAuditScanner(),
    DepExploitScanner(),
]

_SCANNER_MAP = {s.id: s for s in ALL_SCANNERS}


def get_scanner(scanner_id: str) -> BaseScanner | None:
    return _SCANNER_MAP.get(scanner_id)


async def list_scanners() -> list[ScannerInfo]:
    enabled = set(settings.enabled_scanners)
    result = []
    for scanner in ALL_SCANNERS:
        info = scanner.info(enabled=scanner.id in enabled)
        info.available = await scanner.is_available()
        info.availability_reason = await scanner.availability_reason()
        result.append(info)
    return result


async def _abort_scanner_task(scanner_id: str, task: asyncio.Task) -> None:
    """Cancel the asyncio task and force-kill any Semgrep subprocess trees."""
    if scanner_id == "semgrep":
        await asyncio.to_thread(kill_active_semgrep_processes)
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=8)
    except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
        pass


async def run_scanners(
    project_path: Path,
    on_progress: ProgressCallback | None = None,
    scan_id: int | None = None,
) -> tuple[list[dict], list[ScannerRunResult]]:
    """Run all enabled scanners and merge findings."""
    from app.services.scan_runtime import is_scan_cancel_requested

    enabled_ids = [sid for sid in settings.enabled_scanners if sid in _SCANNER_MAP]
    if not enabled_ids:
        enabled_ids = ["semgrep"]

    all_findings: list[dict] = []
    run_results: list[ScannerRunResult] = []
    total = len(enabled_ids)
    for idx, scanner_id in enumerate(enabled_ids):
        if scan_id and is_scan_cancel_requested(scan_id):
            logger.info("Scan %s cancelled before scanner %s", scan_id, scanner_id)
            break

        scanner = _SCANNER_MAP[scanner_id]
        if on_progress:
            await on_progress(scanner.name, idx, total, "starting")

        available = await scanner.is_available()
        if not available:
            run_results.append(ScannerRunResult(
                scanner_id=scanner_id,
                skipped=True,
                skip_reason=f"未安装，请参考: {scanner.install_hint}",
            ))
            logger.warning("Scanner %s not available, skipping", scanner_id)
            continue

        scanner_timeout = await scanner.timeout_seconds(project_path)

        try:
            started = time.monotonic()
            task = asyncio.create_task(scanner.scan(project_path))
            while True:
                if scan_id and is_scan_cancel_requested(scan_id):
                    await _abort_scanner_task(scanner_id, task)
                    logger.info("Scan %s cancelled during scanner %s", scan_id, scanner_id)
                    return all_findings, run_results
                elapsed = int(time.monotonic() - started)
                remaining = scanner_timeout - elapsed
                if remaining <= 0:
                    await _abort_scanner_task(scanner_id, task)
                    raise asyncio.TimeoutError()
                # Heartbeat with asyncio.wait — do NOT use wait_for here, it would
                # cancel the scanner task every 15s.
                wait_slice = min(15, max(1, remaining))
                done, _pending = await asyncio.wait({task}, timeout=wait_slice)
                if task in done:
                    if task.cancelled():
                        raise asyncio.CancelledError()
                    exc = task.exception()
                    if exc is not None:
                        raise exc
                    result = task.result()
                    break
                if on_progress:
                    await on_progress(
                        scanner.name,
                        idx,
                        total,
                        f"running:{elapsed}s",
                    )
            run_results.append(result)
            if result.error:
                logger.error("Scanner %s error: %s", scanner_id, result.error)
            else:
                all_findings.extend(result.findings)
        except asyncio.TimeoutError:
            logger.error("Scanner %s timed out after %ss", scanner_id, scanner_timeout)
            if scanner_id == "semgrep":
                await asyncio.to_thread(kill_active_semgrep_processes)
            run_results.append(ScannerRunResult(
                scanner_id=scanner_id,
                error=f"扫描超时（>{scanner_timeout}秒），已跳过",
            ))
        except Exception as exc:
            logger.exception("Scanner %s failed", scanner_id)
            if scanner_id == "semgrep":
                await asyncio.to_thread(kill_active_semgrep_processes)
            run_results.append(ScannerRunResult(scanner_id=scanner_id, error=str(exc)))

    return all_findings, run_results
