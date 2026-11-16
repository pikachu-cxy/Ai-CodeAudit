"""Validate a run's role selection and freeze its effective configuration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AgentDefinition
from app.services.deep_audit_budget import BudgetPolicy
from app.services.llm_provider import resolve_model


@dataclass(frozen=True)
class RoleConfig:
    slug: str
    model_task: str | None
    model_override: str
    system_prompt: str
    specialties: list[str]
    policy: dict[str, Any]


def freeze_role(row: AgentDefinition, policy: BudgetPolicy) -> RoleConfig:
    task = None if row.model_task == "default" else row.model_task
    return RoleConfig(
        slug=row.slug,
        model_task=task,
        model_override=resolve_model(task, explicit=row.model_override),
        system_prompt=row.system_prompt or "",
        specialties=list(row.specialties or []),
        policy=policy.constrained_by(row).to_dict(),
    )


def builtin_worker(policy: BudgetPolicy) -> RoleConfig:
    return RoleConfig("deep-audit-worker", None, resolve_model(None), "", [], policy.to_dict())


async def resolve_lineup(
    db: AsyncSession, planner_slug: str | None, worker_slugs: list[str] | None, legacy_slug: str | None,
) -> tuple[AgentDefinition | None, list[AgentDefinition]]:
    if legacy_slug and (planner_slug is not None or worker_slugs is not None):
        raise ValueError("agent_slug 不能与 Planner / Worker 阵容同时使用")
    workers = [legacy_slug.strip()] if legacy_slug else (worker_slugs if worker_slugs is not None else [])
    if worker_slugs is not None and not 1 <= len(worker_slugs) <= 3:
        raise ValueError("阵容须选择 1–3 个 Worker")
    if len(set(workers)) != len(workers):
        raise ValueError("Worker 不能重复选择")

    async def resolve(slug: str, role: str) -> AgentDefinition:
        row = await db.scalar(select(AgentDefinition).where(AgentDefinition.slug == slug))
        if row is None or row.slug != slug or not row.enabled:
            raise ValueError(f"AgentDefinition 不存在或未启用: {slug}")
        if row.role != role:
            raise ValueError(f"Agent {slug} 必须具有 {role} 角色")
        return row

    planner = await resolve(planner_slug, "planner") if planner_slug is not None else None
    return planner, [await resolve(slug, "worker") for slug in workers]


def assign_workers(specs: list[dict], workers: list[RoleConfig], default_slug: str) -> list[dict]:
    if not workers:
        return [{**spec, "agent_id": default_slug} for spec in specs]
    assigned = {worker.slug: 0 for worker in workers}
    result = []
    for spec in specs:
        specialists = [worker for worker in workers if spec["task_type"] in worker.specialties]
        generalists = [worker for worker in workers if not worker.specialties]
        worker = min(specialists or generalists or workers, key=lambda item: assigned[item.slug])
        if spec["status"] != "skipped":
            assigned[worker.slug] += 1
        result.append({**spec, "agent_id": worker.slug})
    return result


def public_config(config: dict) -> dict:
    """Runtime prompts stay private even when users can read run details."""
    lineup = config.get("lineup")
    if lineup is None:
        return config

    def public_role(role: dict) -> dict:
        return {key: value for key, value in role.items() if key != "system_prompt"}

    return {
        **config,
        "lineup": {
            "planner": public_role(lineup["planner"]) if lineup["planner"] else None,
            "workers": [public_role(role) for role in lineup["workers"]],
        },
    }
