"""Immutable source asset snapshots and a separate Run coverage projection."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import PurePosixPath

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models import AssetGraphSnapshot, AuditFact, Finding, ReviewStatus
from app.services import blackboard_service as bb
from app.services.endpoint_discovery_service import list_endpoints_summary

VERSION = "endpoints-v1"
LIMIT = 240


def graph_id(*identity) -> str:
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def edge(source, target, kind, verified=True):
    return {"id": graph_id(source, target, kind), "source": source, "target": target,
            "type": kind, "verified": verified}


async def read_snapshot(db, scan_id, asset_graph_id=None):
    query = select(AssetGraphSnapshot).where(AssetGraphSnapshot.scan_id == scan_id)
    if asset_graph_id is not None:
        query = query.where(AssetGraphSnapshot.id == asset_graph_id)
    return await db.scalar(query.order_by(AssetGraphSnapshot.id.desc()).limit(1))


async def ensure_snapshot(db, scan, repo, prefixes, ledger):
    scope = []
    for prefix in sorted(set(prefixes)):
        if not any(prefix.startswith(parent + "/") for parent in scope):
            scope.append(prefix)
    scan_id = scan.id
    name = scan.name
    key = graph_id(scan_id, repo.revision, scope, VERSION)
    query = select(AssetGraphSnapshot).where(AssetGraphSnapshot.snapshot_key == key)
    existing = await db.scalar(query)
    await db.commit()
    if existing:
        return existing

    rows = await asyncio.wait_for(asyncio.to_thread(
        list_endpoints_summary, repo.root, limit=LIMIT + 1, source_files=repo.files,
        read_source=repo.read_source, cancel_check=ledger.check_time, include_handler_line=True,
    ), timeout=ledger.remaining_seconds())
    files = {path.relative_to(repo.root).as_posix() for path in repo.files}
    nodes, edges = {}, {}

    def node(kind, identity, label, **data):
        key_id = graph_id(key, kind, identity)
        nodes[key_id] = {"id": key_id, "type": kind, "label": label, "data": data}
        return key_id

    def connect(source, target, kind, verified=True):
        row = edge(source, target, kind, verified)
        edges[row["id"]] = row

    root = node("project", scan_id, name)
    endpoint_rows = rows[:LIMIT]
    modules = sorted({PurePosixPath(item).parent.as_posix() for item in files})
    primary_modules = sorted({PurePosixPath(item["file"]).parent.as_posix() for item in endpoint_rows})
    displayed_modules = list(dict.fromkeys(primary_modules + modules))[:LIMIT]
    by_module = {}
    for directory in displayed_modules:
        mid = node("module", directory, directory if directory != "." else "根目录", path=directory)
        by_module[directory] = mid
        connect(root, mid, "contains", False)
    for row in endpoint_rows:
        path, route, symbol, line = row["file"], row["path"], row["handler"], row["line"]
        if path not in files or not isinstance(line, int) or line < 1:
            continue
        directory = PurePosixPath(path).parent.as_posix()
        mid = by_module.get(directory)
        if not mid:
            continue
        method = row["http_method"]
        endpoint = node("endpoint", (method, route, path, symbol, line),
                        f"{method} {route}", **row, module_id=mid)
        connect(mid, endpoint, "declares")
        handler_line = row.get("handler_line")
        if symbol and handler_line:
            handler = node("handler", (path, symbol, handler_line), symbol, file=path,
                           line=handler_line, module_id=mid)
            connect(endpoint, handler, "handled_by")

    snapshot = AssetGraphSnapshot(scan_id=scan_id, snapshot_key=key, repository_revision=repo.revision,
                                  scope_json=json.dumps(scope), extractor_version=VERSION,
                                  graph={"nodes": list(nodes.values()), "edges": list(edges.values()),
                                         "truncated": len(rows) > LIMIT or len(modules) > LIMIT})
    db.add(snapshot)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        winner = await db.scalar(query)
        if winner is None:
            raise
        return winner
    return snapshot


def endpoint_context(snapshot):
    return [n["data"] for n in snapshot.graph["nodes"] if n["type"] == "endpoint"]


def bind_tasks(snapshot, tasks):
    for task in tasks:
        scope = task["scope"]
        target = scope.get("target")
        matches = []
        for n in snapshot.graph["nodes"]:
            d = n["data"]
            if n["type"] == "endpoint" and target == f'{d["file"]}:{d["path"]}':
                matches.append(n["id"])
            elif n["type"] == "module" and d["path"] != "." and target == d["path"]:
                matches.append(n["id"])
        if not matches:
            matches = [n["id"] for n in snapshot.graph["nodes"]
                       if n["type"] == "endpoint" and n["data"]["file"] == target]
        scope["asset_ids"] = matches if len(matches) == 1 else []


async def project_snapshot(db, snapshot, run=None, root_asset_id=None, *, active=False):
    overlay = {}
    if run is not None:
        tasks = await bb.list_tasks(db, run.id)
        facts = (await db.execute(select(AuditFact.task_id, Finding.review_status)
                                 .join(Finding, AuditFact.finding_id == Finding.id)
                                 .where(AuditFact.run_id == run.id))).all()
        candidates = {task_id for task_id, _ in facts}
        confirmed = {task_id for task_id, review in facts if review == ReviewStatus.CONFIRMED}
        for task in tasks:
            axes = bb._loads(task.budget_usage, {})
            name = ("confirmed" if task.id in confirmed else "candidate" if task.id in candidates
                    else "reused" if task.status == "skipped"
                    else "audited_no_candidates" if task.status == "completed" and axes.get("coverage") == "covered"
                    else "deterministic" if task.status == "completed" and axes.get("coverage") == "deterministic_verified"
                    else "incomplete")
            for aid in bb._loads(task.scope_json, {}).get("asset_ids", []):
                state = "interrupted" if task.status == "running" and not active else task.status
                overlay.setdefault(aid, []).append({"id": task.id, "status": state, "coverage": name,
                                                    "label": task.task_type, "agent_id": task.agent_id})

    graph = snapshot.graph
    nodes, edges = graph["nodes"], graph["edges"]
    if root_asset_id:
        selected = {root_asset_id}
        selected.update(e["source"] for e in edges if e["target"] == root_asset_id)
        selected.update(e["target"] for e in edges if e["source"] == root_asset_id)
        nodes = [n for n in nodes if n["id"] in selected]
        edges = [e for e in edges if e["source"] in selected and e["target"] in selected]
    return {"asset_graph_id": snapshot.id, "scan_id": snapshot.scan_id,
            "repository_revision": snapshot.repository_revision, "scope": json.loads(snapshot.scope_json),
            "extractor_version": snapshot.extractor_version, "truncated": graph["truncated"],
            "run_id": run.id if run else None, "nodes": nodes, "edges": edges, "overlay": overlay}
