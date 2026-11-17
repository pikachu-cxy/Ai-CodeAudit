"""Read-only graph projection of existing planner, tasks, blackboard and Findings."""
from sqlalchemy import select, or_

from app.models import AuditEvidence, AuditFact, AuditRun, Finding, dt_iso
from app.services import blackboard_service as bb
from app.services.asset_graph_service import edge

MAX_FACTS = 500


async def project_run(db, run, *, active):
    config = bb._loads(run.config_snapshot, {})
    planner = (config.get("lineup") or {}).get("planner") or {}
    plan = config.get("planner_result") or {}
    tasks = await bb.list_tasks(db, run.id)
    by_task = {task.id: bb._loads(task.scope_json, {}) for task in tasks}
    references = {ref for scope in by_task.values() for ref in scope.get("fact_refs", [])
                  if isinstance(ref, int)}
    conditions = [AuditFact.run_id == run.id]
    if references:
        conditions.append(AuditFact.id.in_(sorted(references)[:MAX_FACTS]))
    facts = (await db.scalars(select(AuditFact).join(AuditRun)
             .where(AuditRun.scan_id == run.scan_id, AuditRun.repository_revision == run.repository_revision,
                    or_(*conditions)).order_by(AuditFact.id.desc()).limit(MAX_FACTS + 1))).all()
    truncated = len(facts) > MAX_FACTS
    facts = list(reversed(facts[:MAX_FACTS]))
    facts_by_id = {f.id: f for f in facts}
    fact_ids = set(facts_by_id)
    published = {fact.finding_id for fact in facts if fact.finding_id}
    evidence = (await db.scalars(select(AuditEvidence)
                .where(AuditEvidence.fact_id.in_(fact_ids), AuditEvidence.repository_revision == run.repository_revision)
                .order_by(AuditEvidence.id).limit(MAX_FACTS * 2 + 1))).all() if fact_ids else []
    truncated |= len(evidence) > MAX_FACTS * 2
    evidence = evidence[:MAX_FACTS * 2]
    evidence_ids = {e.id for e in evidence}
    findings = (await db.scalars(select(Finding).where(Finding.id.in_(published),
                  Finding.scan_id == run.scan_id))).all() if published else []

    nodes, edges, active_ids = [], [], []
    def node(kind, key, label, **data):
        nodes.append({"id": key, "type": kind, "label": label, "data": data})
    def connect(source, target, kind):
        edges.append(edge(source, target, kind))

    node("planner", "planner", planner.get("name") or planner.get("slug") or "内置 Planner",
         status=run.status, source=plan.get("mode"), fallback_reason=plan.get("fallback_reason"))
    for task in tasks:
        state = task.status
        if state == "running":
            if active:
                active_ids.append(task.id)
            else:
                state = "interrupted"
        usage = bb._loads(task.budget_usage, {})
        key = f"task:{task.id}"
        node("task", key, task.goal.split("\n")[0], task_id=task.id, agent_id=task.agent_id,
             task_type=task.task_type, status=state, coverage=usage.get("coverage", "unknown"),
             asset_ids=by_task[task.id].get("asset_ids", []), target=by_task[task.id].get("target"),
             summary=task.result_summary, started_at=dt_iso(task.started_at), finished_at=dt_iso(task.finished_at),
             budget_usage=usage)
        connect("planner", key, "planned")
        for ref in by_task[task.id].get("fact_refs", []):
            if ref in fact_ids:
                fact = facts_by_id[ref]
                if fact.task_id != task.id or fact.run_id != run.id:
                    connect(key, f"fact:{ref}", "references")

    for fact in facts:
        key = f"fact:{fact.id}"
        node("fact", key, fact.summary, fact_type=fact.fact_type, source=fact.source,
             origin_run_id=fact.run_id, origin_task_id=fact.task_id, confidence=fact.confidence)
        if fact.run_id == run.id and fact.task_id in by_task:
            connect(f"task:{fact.task_id}", key, "observed")
        for ref in bb._loads(fact.metadata_json, {}).get("evidence_refs", []):
            if ref in evidence_ids:
                connect(key, f"evidence:{ref}", "references")
        if fact.finding_id and any(f.id == fact.finding_id for f in findings):
            connect(key, f"finding:{fact.finding_id}", "candidate")
    for item in evidence:
        data = bb.serialize_evidence(item)
        node("evidence", f"evidence:{item.id}", f"{item.file_path}:{item.line_start}", **data)
        connect(f"fact:{item.fact_id}", f"evidence:{item.id}", "supports")
    for finding in findings:
        node("finding", f"finding:{finding.id}", finding.rule_id, finding_id=finding.id,
             review_status=finding.review_status.value, severity=finding.severity.value,
             file=finding.file_path, line=finding.line_start)
    return {"run_id": run.id, "scan_id": run.scan_id, "asset_graph_id": config.get("asset_graph_id"),
            "repository_revision": run.repository_revision, "nodes": nodes, "edges": edges,
            "task_concurrency_limit": config.get("task_concurrency_limit", 1), "active_tasks": active_ids,
            "truncated": truncated}
