"""Unified execution budget for Deep Audit V1.

The legacy LLM audit chain only limits *iterations*. Deep Audit additionally
limits tool calls, tokens and wall-clock time. Every LLM call and every tool
call must pass through :class:`BudgetLedger` before it is executed; the ledger
is persisted on ``AuditRun.budget_usage`` so a restart can recover it.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.auth_service import get_system_setting, set_system_setting


BUDGET_SETTING_KEY = "deep_audit_v1_budget"


class DeepAuditBudgetSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_llm_rounds: int = Field(ge=1)
    max_tool_calls: int = Field(ge=1)
    max_total_tokens: int = Field(ge=256)



class BudgetExceeded(RuntimeError):
    """Raised when a run hits one of its hard execution limits."""

    def __init__(self, dimension: str, limit: float, used: float):
        self.dimension = dimension
        self.limit = limit
        self.used = used
        super().__init__(f"深度审计预算耗尽（{dimension}: {used:.0f}/{limit:.0f}）")


class RoleBudgetExceeded(BudgetExceeded):
    """A selected Agent has exhausted its own allocation."""


@dataclass(frozen=True)
class BudgetPolicy:
    """Hard ceilings. AgentDefinition values may lower them, never raise them."""

    max_llm_rounds: int = 12
    max_tool_calls: int = 36
    max_total_tokens: int = 60_000
    max_seconds: float = 600.0
    max_tool_seconds: float = 15.0
    max_file_bytes: int = 512 * 1024
    max_lines_per_read: int = 200
    max_output_chars: int = 6_000
    max_batch_files: int = 6
    max_search_chars: int = 80
    max_tasks: int = 6

    @classmethod
    def from_settings(cls) -> "BudgetPolicy":
        return cls(
            max_llm_rounds=max(1, int(settings.deep_audit_max_llm_rounds)),
            max_tool_calls=max(1, int(settings.deep_audit_max_tool_calls)),
            max_total_tokens=max(256, int(settings.deep_audit_max_total_tokens)),
            max_seconds=max(10.0, float(settings.deep_audit_max_seconds)),
            max_tool_seconds=max(1.0, float(settings.deep_audit_max_tool_seconds)),
            max_file_bytes=max(4096, int(settings.agent_tool_max_file_bytes)),
            max_lines_per_read=max(10, int(settings.agent_tool_max_lines)),
            max_output_chars=max(500, int(settings.agent_tool_max_output_chars)),
            max_batch_files=max(1, int(settings.deep_audit_max_batch_files)),
            max_search_chars=max(8, int(settings.deep_audit_max_search_chars)),
            max_tasks=max(1, int(settings.deep_audit_max_tasks)),
        )

    @classmethod
    async def for_new_run(cls, db: AsyncSession) -> "BudgetPolicy":
        policy = cls.from_settings()
        saved = await get_system_setting(db, BUDGET_SETTING_KEY)
        if saved is None:
            return policy
        try:
            overrides = DeepAuditBudgetSettings.model_validate_json(saved)
        except ValidationError:
            return policy
        return replace(policy, **overrides.model_dump())

    def configurable_limits(self) -> DeepAuditBudgetSettings:
        return DeepAuditBudgetSettings(
            max_llm_rounds=self.max_llm_rounds,
            max_tool_calls=self.max_tool_calls,
            max_total_tokens=self.max_total_tokens,
        )

    def constrained_by(self, agent: Any | None) -> "BudgetPolicy":
        """Apply AgentDefinition ceilings as an upper bound (never a relaxation)."""
        if agent is None:
            return self

        def _positive(name: str, default: int) -> int:
            try:
                value = int(getattr(agent, name, default) or default)
            except (TypeError, ValueError):
                return default
            return max(1, value)

        rounds = min(self.max_llm_rounds, _positive("max_tool_rounds", self.max_llm_rounds))
        files = min(self.max_batch_files, _positive("max_files", self.max_batch_files))
        tokens = min(self.max_total_tokens, _positive("max_tokens", self.max_total_tokens))
        return BudgetPolicy(
            max_llm_rounds=rounds,
            max_tool_calls=min(self.max_tool_calls, rounds * 3),
            max_total_tokens=tokens,
            max_seconds=self.max_seconds,
            max_tool_seconds=self.max_tool_seconds,
            max_file_bytes=self.max_file_bytes,
            max_lines_per_read=self.max_lines_per_read,
            max_output_chars=self.max_output_chars,
            max_batch_files=files,
            max_search_chars=self.max_search_chars,
            max_tasks=self.max_tasks,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_llm_rounds": self.max_llm_rounds,
            "max_tool_calls": self.max_tool_calls,
            "max_total_tokens": self.max_total_tokens,
            "max_seconds": self.max_seconds,
            "max_tool_seconds": self.max_tool_seconds,
            "max_file_bytes": self.max_file_bytes,
            "max_lines_per_read": self.max_lines_per_read,
            "max_output_chars": self.max_output_chars,
            "max_batch_files": self.max_batch_files,
            "max_search_chars": self.max_search_chars,
            "max_tasks": self.max_tasks,
        }


async def save_deep_audit_budget(db: AsyncSession, budget: DeepAuditBudgetSettings) -> None:
    await set_system_setting(db, BUDGET_SETTING_KEY, budget.model_dump_json())
    await db.commit()


def estimate_tokens(text: str) -> int:
    """Conservative fallback when a provider does not return ``usage``."""
    return max(1, len((text or "").encode("utf-8")) + 1)


@dataclass
class BudgetLedger:
    """Mutable, serialisable accounting for one AuditRun."""

    policy: BudgetPolicy = field(default_factory=BudgetPolicy.from_settings)
    llm_rounds: int = 0
    tool_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_tokens: int = 0
    llm_ms: int = 0
    tool_ms: int = 0
    exhausted_dimension: str | None = None
    role_usage: dict[str, dict[str, int]] = field(default_factory=dict)
    _role: tuple[str, BudgetPolicy, dict[str, int]] | None = field(default=None, init=False, repr=False)
    _previous_seconds: float = 0.0
    _started: float = field(default_factory=time.monotonic, repr=False)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens + self.estimated_tokens

    @property
    def elapsed_seconds(self) -> float:
        return self._previous_seconds + time.monotonic() - self._started

    @classmethod
    def restore(cls, policy: BudgetPolicy, snapshot: dict | None) -> "BudgetLedger":
        data = snapshot or {}
        ledger = cls(policy=policy)
        for key in (
            "llm_rounds", "tool_calls", "prompt_tokens", "completion_tokens",
            "estimated_tokens", "llm_ms", "tool_ms",
        ):
            try:
                setattr(ledger, key, max(0, int(data.get(key) or 0)))
            except (TypeError, ValueError):
                pass
        ledger.role_usage = {key: dict(usage) for key, usage in data.get("role_usage", {}).items()}
        ledger.exhausted_dimension = data.get("exhausted_dimension") or None
        ledger._previous_seconds = max(0.0, float(data.get("elapsed_seconds") or 0))
        return ledger

    def _counters(self) -> dict[str, int]:
        return {"llm_rounds": self.llm_rounds, "tool_calls": self.tool_calls, "total_tokens": self.total_tokens}

    @contextmanager
    def for_role(self, slug: str, policy: BudgetPolicy) -> Iterator[None]:
        self._role = (slug, policy, self._counters())
        try:
            yield
        finally:
            self.role_usage = self._role_snapshot()
            self._role = None

    def _role_snapshot(self) -> dict[str, dict[str, int]]:
        if self._role is None:
            return self.role_usage
        slug, _, start = self._role
        previous = self.role_usage.get(slug, {})
        return {**self.role_usage, slug: {
            key: previous.get(key, 0) + value - start[key]
            for key, value in self._counters().items()
        }}

    def _role_remaining(self, dimension: str) -> tuple[int, int]:
        slug, policy, _ = self._role
        limit = getattr(policy, "max_" + dimension)
        return limit, self._role_snapshot()[slug][dimension]

    def _check_role_limit(self, dimension: str, required: int = 1) -> None:
        if self._role is not None:
            limit, used = self._role_remaining(dimension)
            if used + required > limit:
                raise RoleBudgetExceeded(dimension, limit, used + max(0, required - 1))

    def check_consumed_tokens(self) -> None:
        if self.total_tokens > self.policy.max_total_tokens:
            self._fail("total_tokens", self.policy.max_total_tokens, self.total_tokens)
        self._check_role_limit("total_tokens", required=0)

    def _fail(self, dimension: str, limit: float, used: float) -> None:
        self.exhausted_dimension = dimension
        raise BudgetExceeded(dimension, limit, used)

    def check_time(self) -> None:
        if self.elapsed_seconds >= self.policy.max_seconds:
            self._fail("seconds", self.policy.max_seconds, self.elapsed_seconds)

    def remaining_seconds(self) -> float:
        self.check_time()
        return self.policy.max_seconds - self.elapsed_seconds

    def completion_limit(self, prompt_text: str) -> int:
        self.check_llm()
        estimated_prompt = estimate_tokens(prompt_text)
        available = self.policy.max_total_tokens - self.total_tokens - estimated_prompt
        if available < 1:
            self._fail("total_tokens", self.policy.max_total_tokens, self.total_tokens + estimated_prompt)
        if self._role is not None:
            self._check_role_limit("total_tokens", estimated_prompt + 1)
            limit, used = self._role_remaining("total_tokens")
            available = min(available, limit - used - estimated_prompt)
        return min(4096, available)

    def check_llm(self) -> None:
        self.check_time()
        if self.llm_rounds >= self.policy.max_llm_rounds:
            self._fail("llm_rounds", self.policy.max_llm_rounds, self.llm_rounds)
        if self.total_tokens >= self.policy.max_total_tokens:
            self._fail("total_tokens", self.policy.max_total_tokens, self.total_tokens)

        self._check_role_limit("llm_rounds")
        self._check_role_limit("total_tokens")

    def check_tool(self) -> None:
        self.check_time()
        if self.tool_calls >= self.policy.max_tool_calls:
            self._fail("tool_calls", self.policy.max_tool_calls, self.tool_calls)

        self._check_role_limit("tool_calls")

    def consume_llm(
        self,
        *,
        prompt_text: str,
        completion_text: str,
        usage: dict | None,
        elapsed_ms: int,
    ) -> None:
        self.llm_ms += max(0, int(elapsed_ms))
        prompt_tokens = int((usage or {}).get("prompt_tokens") or 0)
        completion_tokens = int((usage or {}).get("completion_tokens") or 0)
        if prompt_tokens or completion_tokens:
            self.prompt_tokens += prompt_tokens
            self.completion_tokens += completion_tokens
        else:
            # Older providers omit usage. Keep the token ceiling effective by
            # charging a deterministic estimate instead of silently charging 0.
            self.estimated_tokens += estimate_tokens(prompt_text) + estimate_tokens(completion_text)

    def consume_tool(self, elapsed_ms: int) -> None:
        self.tool_ms += max(0, int(elapsed_ms))

    def snapshot(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "llm_rounds": self.llm_rounds,
            "tool_calls": self.tool_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "estimated_tokens": self.estimated_tokens,
            "total_tokens": self.total_tokens,
            "llm_ms": self.llm_ms,
            "tool_ms": self.tool_ms,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "exhausted_dimension": self.exhausted_dimension,
            "role_usage": self._role_snapshot(),
        }
