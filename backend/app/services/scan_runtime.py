"""In-process cancel/pause signals and active pipeline tracking for scans."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

logger = logging.getLogger(__name__)

_cancel_requested: set[int] = set()
_active_pipelines: dict[int, asyncio.Task] = {}


class ScanCancelled(Exception):
    """Raised when user requests pause during scan pipeline."""


def request_scan_cancel(scan_id: int) -> None:
    _cancel_requested.add(scan_id)


def clear_scan_cancel(scan_id: int) -> None:
    _cancel_requested.discard(scan_id)


def is_scan_cancel_requested(scan_id: int) -> bool:
    return scan_id in _cancel_requested


def check_scan_cancel(scan_id: int) -> None:
    if is_scan_cancel_requested(scan_id):
        raise ScanCancelled("用户已暂停扫描")


def is_scan_pipeline_active(scan_id: int) -> bool:
    task = _active_pipelines.get(scan_id)
    return task is not None and not task.done()


def has_any_active_pipeline() -> bool:
    return any(task is not None and not task.done() for task in _active_pipelines.values())


def schedule_scan_pipeline(scan_id: int, coro: Coroutine[Any, Any, None]) -> asyncio.Task:
    """Track pipeline tasks so restarts can reclaim zombie SCANNING rows."""
    old = _active_pipelines.get(scan_id)
    if old and not old.done():
        old.cancel()

    async def _after_response() -> None:
        # Yield so the HTTP response can flush before heavy scan work begins.
        await asyncio.sleep(0.05)
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scan pipeline failed for scan_id=%s", scan_id)
            raise

    task = asyncio.create_task(_after_response(), name=f"scan-pipeline-{scan_id}")
    _active_pipelines[scan_id] = task
    logger.info("Scheduled scan pipeline for scan_id=%s", scan_id)

    def _clear(done: asyncio.Task) -> None:
        current = _active_pipelines.get(scan_id)
        if current is done:
            _active_pipelines.pop(scan_id, None)

    task.add_done_callback(_clear)
    return task


def cancel_scan_pipeline(scan_id: int) -> bool:
    """Request cooperative cancel; cancel the asyncio task if one is running."""
    request_scan_cancel(scan_id)
    task = _active_pipelines.get(scan_id)
    if task and not task.done():
        task.cancel()
        logger.info("Cancelled active pipeline task for scan_id=%s", scan_id)
        return True
    return False


def launch_sast_pipeline(scan_id: int) -> asyncio.Task:
    """Start SAST pipeline on the asyncio event loop (reliable for webhooks/CI)."""
    from app.services.scan_service import run_scan_pipeline

    return schedule_scan_pipeline(scan_id, run_scan_pipeline(scan_id))


def launch_sast_deep_pipeline(
    scan_id: int,
    finding_ids: list[int] | None = None,
    max_findings: int = 12,
    force: bool = False,
) -> asyncio.Task:
    """Start SAST deep audit on the asyncio event loop (same reliability as SAST scan)."""
    from app.services.scan_service import run_sast_deep_pipeline

    return schedule_scan_pipeline(
        scan_id,
        run_sast_deep_pipeline(scan_id, finding_ids, max_findings, force),
    )


def launch_llm_audit_pipeline(
    scan_id: int,
    categories: list | None = None,
) -> asyncio.Task:
    """Start LLM endpoint audit on the asyncio event loop."""
    from app.services.scan_service import run_llm_audit_pipeline

    return schedule_scan_pipeline(scan_id, run_llm_audit_pipeline(scan_id, categories))


async def run_tracked_scan_pipeline(scan_id: int, pipeline) -> None:
    """Run pipeline after the HTTP response (Starlette BackgroundTasks)."""
    old = _active_pipelines.get(scan_id)
    if old and not old.done():
        old.cancel()

    task = asyncio.current_task()
    if task is not None:
        _active_pipelines[scan_id] = task
    try:
        await pipeline(scan_id)
    finally:
        if task is not None and _active_pipelines.get(scan_id) is task:
            _active_pipelines.pop(scan_id, None)
