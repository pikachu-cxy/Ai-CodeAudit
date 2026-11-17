"""Unified execution budget for Deep Audit V1.

The legacy LLM audit chain only limits *iterations*. Deep Audit additionally
limits tool calls, tokens and wall-clock time. Every LLM call and every tool
call must pass through :class:`BudgetLedger` before it is executed; the ledger
is persisted on ``AuditRun.budget_usage`` so a restart can recover it.
"""
from __future__ import annotations

import asyncio
import json
import time
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
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _reservations: dict[object, tuple[str, int]] = field(default_factory=dict, init=False, repr=False)
    _settled: asyncio.Event = field(default_factory=asyncio.Event, init=False, repr=False)
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
        # Count a reservation as spent if the process stopped before settlement.
        for key, tokens in data.get("reserved_tokens", {}).items():
            amount = max(0, int(tokens))
            ledger.estimated_tokens += amount
            if key:
                role = ledger.role_usage.setdefault(key, {})
                role["total_tokens"] = role.get("total_tokens", 0) + amount
        ledger.exhausted_dimension = data.get("exhausted_dimension") or None
        ledger._previous_seconds = max(0.0, float(data.get("elapsed_seconds") or 0))
        return ledger

    def handle(self, key: str = "", policy: BudgetPolicy | None = None) -> "BudgetHandle":
        return BudgetHandle(self, key, policy or self.policy)

    def reserved(self, key: str | None = None) -> int:
        return sum(amount for role, amount in self._reservations.values() if key is None or role == key)

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
        return min(4096, available)

    def check_llm(self) -> None:
        self.check_time()
        if self.llm_rounds >= self.policy.max_llm_rounds:
            self._fail("llm_rounds", self.policy.max_llm_rounds, self.llm_rounds)
        if self.total_tokens >= self.policy.max_total_tokens:
            self._fail("total_tokens", self.policy.max_total_tokens, self.total_tokens)


    def check_tool(self) -> None:
        self.check_time()
        if self.tool_calls >= self.policy.max_tool_calls:
            self._fail("tool_calls", self.policy.max_tool_calls, self.tool_calls)


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
            "role_usage": {key: dict(value) for key, value in self.role_usage.items()},
            "reserved_tokens": {key: self.reserved(key) for key in {role for role, _ in self._reservations.values()}},
        }


_MODEL_SLOTS = asyncio.Semaphore(max(1, settings.deep_audit_model_concurrency))


@dataclass
class BudgetHandle:
    """Explicit role and task accounting on the run's asyncio event loop."""

    run: BudgetLedger
    key: str
    policy: BudgetPolicy
    usage: dict[str, int] = field(default_factory=lambda: {"llm_rounds": 0, "tool_calls": 0, "total_tokens": 0})

    def _used(self, dimension: str) -> int:
        return self.run.role_usage.get(self.key, {}).get(dimension, 0)

    def _charge(self, dimension: str, amount: int) -> None:
        self.usage[dimension] += amount
        if self.key:
            counts = self.run.role_usage.setdefault(self.key, {})
            counts[dimension] = counts.get(dimension, 0) + amount

    def _check_role(self, dimension: str, amount: int = 1) -> None:
        limit = getattr(self.policy, "max_" + dimension)
        used = self._used(dimension)
        if self.key and used + amount > limit:
            raise RoleBudgetExceeded(dimension, limit, used)

    def take_tool(self) -> None:
        self.run.check_tool()
        self._check_role("tool_calls")
        self.run.tool_calls += 1
        self._charge("tool_calls", 1)

    async def checkpoint(self, db, audit_run) -> None:
        from app.services.blackboard_service import update_run

        async with self.run.write_lock:
            await update_run(db, audit_run, budget_usage=self.run.snapshot())

    async def reserve_llm(self, prompt: str, check) -> tuple[object, int]:
        estimate = estimate_tokens(prompt)
        while True:
            check()
            self.run.check_llm()
            self._check_role("llm_rounds")
            self._check_role("total_tokens", estimate + 1)
            available = self.run.policy.max_total_tokens - self.run.total_tokens - estimate
            if available < 1:
                self.run._fail("total_tokens", self.run.policy.max_total_tokens, self.run.total_tokens + estimate)
            available -= self.run.reserved()
            if self.key:
                available = min(available, self.policy.max_total_tokens - self._used("total_tokens")
                                - self.run.reserved(self.key) - estimate)
            if available > 0:
                # No await between checks and changes. All reservations use the same event loop.
                slot, limit = object(), min(4096, available)
                self.run._reservations[slot] = (self.key, estimate + limit)
                self.run.llm_rounds += 1
                self._charge("llm_rounds", 1)
                return slot, limit
            self.run._settled.clear()
            try:
                await asyncio.wait_for(self.run._settled.wait(), timeout=self.run.remaining_seconds())
            except TimeoutError:
                self.run.check_time()
                raise

    def settle_llm(self, slot, prompt: str, text: str, usage: dict | None, elapsed_ms: int) -> None:
        self.run._reservations.pop(slot)
        before = self.run.total_tokens
        self.run.consume_llm(prompt_text=prompt, completion_text=text, usage=usage, elapsed_ms=elapsed_ms)
        self._charge("total_tokens", self.run.total_tokens - before)
        self.run._settled.set()

    async def call_model(self, provider, messages, *, check, persist=None, timeout: float, **kwargs) -> str:
        prompt = json.dumps(messages, ensure_ascii=False)
        await asyncio.wait_for(_MODEL_SLOTS.acquire(), timeout=self.run.remaining_seconds())
        try:
            slot, limit = await self.reserve_llm(prompt, check)
            text, usage = "", None
            started = time.perf_counter()
            try:
                if persist:
                    await persist()
                check()
                wait = min(timeout, self.run.remaining_seconds())
                text, usage = await asyncio.wait_for(
                    provider(messages, max_tokens=limit, timeout=wait, max_retries=0, **kwargs),
                    timeout=wait,
                )
                return text
            finally:
                self.settle_llm(slot, prompt, text, usage, int((time.perf_counter() - started) * 1000))
                if persist:
                    await persist()
                if self.run.total_tokens > self.run.policy.max_total_tokens:
                    self.run._fail("total_tokens", self.run.policy.max_total_tokens, self.run.total_tokens)
                self._check_role("total_tokens", 0)
        finally:
            _MODEL_SLOTS.release()
