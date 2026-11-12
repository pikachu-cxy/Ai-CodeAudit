"""Agent definition registry — configuration only.

IMPORTANT: no Planner/Worker scheduler, blackboard or executor consumes these
rows. Saving an Agent here changes configuration data only; it does not create a
runnable Agent and never touches the existing scan pipeline.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies.auth import require_admin
from app.models import AgentDefinition, dt_iso
from app.services.llm_provider import is_llm_configured, resolve_model
from app.services.platform_service import log_action

router = APIRouter(
    prefix="/api/agents",
    tags=["agents"],
    dependencies=[Depends(require_admin)],
)

AGENT_ROLES = ("planner", "worker", "reviewer", "reporter")
MODEL_TASKS = ("default", "fp", "deep", "agent")
BUDGET_RANGES = {
    "max_tool_rounds": (1, 50),
    "max_files": (1, 200),
    "max_tokens": (256, 200_000),
}
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


class AgentIn(BaseModel):
    slug: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    role: str = "worker"
    description: str = ""
    enabled: bool = True
    model_task: str = "agent"
    model_override: str = ""
    system_prompt: str = ""
    max_tool_rounds: int = 10
    max_files: int = 16
    max_tokens: int = 8192


class AgentUpdate(BaseModel):
    name: str | None = None
    role: str | None = None
    description: str | None = None
    enabled: bool | None = None
    model_task: str | None = None
    model_override: str | None = None
    system_prompt: str | None = None
    max_tool_rounds: int | None = None
    max_files: int | None = None
    max_tokens: int | None = None


class AgentOut(BaseModel):
    id: int
    slug: str
    name: str
    role: str
    description: str
    enabled: bool
    model_task: str
    model_override: str
    system_prompt: str
    max_tool_rounds: int
    max_files: int
    max_tokens: int
    effective_model: str
    execution_wired: bool = False
    created_at: str | None = None
    updated_at: str | None = None


def _validate_slug(value: str) -> str:
    slug = str(value or "").strip().lower()
    if not _SLUG_RE.match(slug):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "标识只能包含小写字母、数字、- 和 _，长度 2–64，且以字母或数字开头",
        )
    return slug


def _validate_fields(data: dict) -> None:
    def bad(message: str) -> None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, message)

    if "name" in data and not str(data["name"] or "").strip():
        bad("名称不能为空")
    if "name" in data and len(str(data["name"])) > 128:
        bad("名称不能超过 128 个字符")
    if "role" in data and data["role"] not in AGENT_ROLES:
        bad(f"角色必须是以下之一：{', '.join(AGENT_ROLES)}")
    if "model_task" in data and data["model_task"] not in MODEL_TASKS:
        bad(f"模型绑定必须是以下之一：{', '.join(MODEL_TASKS)}")
    if "description" in data and len(str(data["description"] or "")) > 2000:
        bad("描述不能超过 2000 个字符")
    if "system_prompt" in data and len(str(data["system_prompt"] or "")) > 12000:
        bad("系统提示词不能超过 12000 个字符")
    if "model_override" in data and len(str(data["model_override"] or "")) > 128:
        bad("模型名称不能超过 128 个字符")
    if "enabled" in data and not isinstance(data["enabled"], bool):
        bad("enabled 必须是布尔值")
    for key, (low, high) in BUDGET_RANGES.items():
        if key in data:
            try:
                number = int(data[key])
            except (TypeError, ValueError):
                bad(f"{key} 必须是整数")
                return
            if not low <= number <= high:
                bad(f"{key} 需在 {low}–{high} 之间")


def _to_out(row: AgentDefinition) -> AgentOut:
    task = None if row.model_task == "default" else row.model_task
    return AgentOut(
        id=row.id,
        slug=row.slug,
        name=row.name,
        role=row.role,
        description=row.description or "",
        enabled=bool(row.enabled),
        model_task=row.model_task,
        model_override=row.model_override or "",
        system_prompt=row.system_prompt or "",
        max_tool_rounds=row.max_tool_rounds,
        max_files=row.max_files,
        max_tokens=row.max_tokens,
        effective_model=resolve_model(task, explicit=row.model_override or None),
        execution_wired=False,
        created_at=dt_iso(row.created_at),
        updated_at=dt_iso(row.updated_at),
    )


async def _get_row(db: AsyncSession, agent_id: int) -> AgentDefinition:
    row = await db.get(AgentDefinition, agent_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent 配置不存在")
    return row


@router.get("/capabilities")
async def capabilities() -> dict:
    """Real runtime facts — never a fabricated model catalogue."""
    return {
        "runtime_status": "configuration_only",
        "execution_wired": False,
        "scheduler": None,
        "blackboard": None,
        "llm_configured": is_llm_configured(),
        "roles": list(AGENT_ROLES),
        "model_tasks": list(MODEL_TASKS),
        "resolved_models": {
            "default": resolve_model(None),
            "fp": resolve_model("fp"),
            "deep": resolve_model("deep"),
            "agent": resolve_model("agent"),
        },
        "budget_ranges": {key: list(value) for key, value in BUDGET_RANGES.items()},
        "agent_tool_round_limit": settings.llm_agent_max_tool_rounds,
        "note": (
            "这些记录只是配置定义：当前没有 Planner/Worker 调度器或代码事实黑板，"
            "保存、启用都不会触发任何审计任务。effective_model 来自现有 LLM 设置解析，"
            "不做任何模型调用。"
        ),
    }


@router.get("", response_model=list[AgentOut])
async def list_agents(db: AsyncSession = Depends(get_db)) -> list[AgentOut]:
    result = await db.execute(
        select(AgentDefinition).order_by(AgentDefinition.id.asc())
    )
    return [_to_out(row) for row in result.scalars().all()]


@router.post("", response_model=AgentOut, status_code=status.HTTP_201_CREATED)
async def create_agent(
    body: AgentIn,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> AgentOut:
    slug = _validate_slug(body.slug)
    data = body.model_dump()
    _validate_fields(data)
    existing = await db.execute(
        select(AgentDefinition.id).where(AgentDefinition.slug == slug)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"标识 {slug} 已存在")

    data["slug"] = slug
    data["name"] = str(data["name"]).strip()
    row = AgentDefinition(**data)
    db.add(row)
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="agent.create",
        target_type="agent",
        target_id=slug,
        detail={"name": row.name, "role": row.role, "enabled": bool(row.enabled)},
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.put("/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: int,
    body: AgentUpdate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> AgentOut:
    row = await _get_row(db, agent_id)
    data = body.model_dump(exclude_unset=True)
    _validate_fields(data)
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "没有需要更新的字段")
    if "name" in data:
        data["name"] = str(data["name"]).strip()
    for key, value in data.items():
        setattr(row, key, value)
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="agent.update",
        target_type="agent",
        target_id=row.slug,
        detail={"fields": sorted(data.keys())},
    )
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: int,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
) -> dict:
    row = await _get_row(db, agent_id)
    slug, name = row.slug, row.name
    await db.delete(row)
    await db.flush()
    await log_action(
        db,
        actor=user.get("username", "unknown"),
        action="agent.delete",
        target_type="agent",
        target_id=slug,
        detail={"name": name},
    )
    await db.commit()
    return {"ok": True, "id": agent_id, "slug": slug}
