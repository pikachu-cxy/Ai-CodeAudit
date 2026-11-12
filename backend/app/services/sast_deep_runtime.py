"""In-process progress + cancel for SAST deep / flow-recon audits."""

from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Any

_lock = threading.Lock()
_cancel_requested: set[int] = set()
_progress: dict[int, dict[str, Any]] = {}


class SastDeepCancelled(Exception):
    """Raised when user pauses SAST deep audit."""


def request_sast_deep_cancel(scan_id: int) -> None:
    _cancel_requested.add(scan_id)


def clear_sast_deep_cancel(scan_id: int) -> None:
    _cancel_requested.discard(scan_id)


def is_sast_deep_cancel_requested(scan_id: int) -> bool:
    return scan_id in _cancel_requested


def check_sast_deep_cancel(scan_id: int) -> None:
    if is_sast_deep_cancel_requested(scan_id):
        raise SastDeepCancelled("用户已暂停 SAST 深度研判")


def init_sast_deep_progress(scan_id: int, tasks: list[dict[str, Any]], *, message: str = "") -> dict:
    """tasks: [{id, label, kind, status}] status in pending|running|done|error|skipped"""
    payload = {
        "scan_id": scan_id,
        "status": "running",
        "phase": "prepare",
        "message": message or "准备深度研判…",
        "total": len(tasks),
        "done": 0,
        "percent": 0,
        "current_task_id": None,
        "tasks": deepcopy(tasks),
        "started_at": time.time(),
        "updated_at": time.time(),
        "error": None,
    }
    with _lock:
        _progress[scan_id] = payload
    return deepcopy(payload)


def update_sast_deep_progress(
    scan_id: int,
    *,
    phase: str | None = None,
    message: str | None = None,
    current_task_id: str | None = None,
    task_id: str | None = None,
    task_status: str | None = None,
    task_detail: str | None = None,
    status: str | None = None,
    error: str | None = None,
    percent: int | None = None,
) -> dict | None:
    with _lock:
        state = _progress.get(scan_id)
        if not state:
            return None
        if phase is not None:
            state["phase"] = phase
        if message is not None:
            state["message"] = message
        if current_task_id is not None:
            state["current_task_id"] = current_task_id
        if status is not None:
            state["status"] = status
        if error is not None:
            state["error"] = error
        if task_id is not None:
            for t in state["tasks"]:
                if t.get("id") == task_id:
                    if task_status is not None:
                        t["status"] = task_status
                    if task_detail is not None:
                        t["detail"] = task_detail
                    break
        done = sum(1 for t in state["tasks"] if t.get("status") in ("done", "error", "skipped"))
        total = max(1, len(state["tasks"]))
        state["done"] = done
        if percent is not None:
            state["percent"] = max(0, min(99, int(percent)))
        elif state.get("status") == "running":
            state["percent"] = min(99, int(done * 100 / total))
        if state.get("status") in ("done", "failed", "cancelled"):
            state["percent"] = 100 if state["status"] == "done" else state.get("percent", 0)
        state["updated_at"] = time.time()
        return deepcopy(state)


def finish_sast_deep_progress(scan_id: int, *, status: str, message: str, error: str | None = None) -> dict | None:
    with _lock:
        state = _progress.get(scan_id)
        if not state:
            state = {
                "scan_id": scan_id,
                "tasks": [],
                "total": 0,
                "done": 0,
                "started_at": time.time(),
            }
            _progress[scan_id] = state
        state["status"] = status
        state["message"] = message
        state["phase"] = status
        state["error"] = error
        state["current_task_id"] = None
        state["percent"] = 100 if status == "done" else state.get("percent", 0)
        if status == "done":
            for t in state["tasks"]:
                if t.get("status") == "running":
                    t["status"] = "done"
            state["done"] = sum(1 for t in state["tasks"] if t.get("status") in ("done", "error", "skipped"))
            state["percent"] = 100
        state["updated_at"] = time.time()
        return deepcopy(state)


def get_sast_deep_progress(scan_id: int) -> dict | None:
    with _lock:
        state = _progress.get(scan_id)
        return deepcopy(state) if state else None
