"""One general-purpose Deep Audit Worker.

Reuses the existing read-only code tools in ``agent_tools.py`` through the hard
policy in ``deep_audit_guards.py``. The Worker never receives a ``Path``: it
receives a :class:`ReadOnlyRepository` and can only call whitelisted tools.

Two investigation modes:

* LLM mode -- ``chat_completion_with_usage`` + the existing tool/action JSON
  protocol (``parse_agent_response``). Token usage is charged to the budget.
* Deterministic mode -- used when no LLM credential is configured (or when the
  LLM call fails). It still performs REAL read-only tool calls and derives
  candidates from explicit, reviewable static patterns. It is not a mock.

Every tool observation is committed immediately as a shared ``code_fact`` with
verifiable evidence, so stopping the Worker never loses completed work.
"""
from __future__ import annotations

import ast
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditFact, AuditRun, AuditTask, ScanEvent
from app.services import blackboard_service as bb
from app.services.agent_tools import audit_tool_specs, parse_agent_response
from app.services.deep_audit_budget import BudgetExceeded, BudgetHandle, BudgetPolicy
from app.services.deep_audit_guards import (
    ALLOWED_TOOLS, ReadOnlyRepository, RepositoryChanged, ToolPolicyError, execute_read_only_tool,
)
from app.services.llm_provider import (
    chat_completion_with_usage, effective_llm_timeout,
)
from app.services.tool_log_redaction import redact_text

logger = logging.getLogger(__name__)

DEEP_AUDIT_PHASE = "deep_audit"

WORKER_SYSTEM_PROMPT = """你是 Deep Audit V1 的通用代码审计 Worker。你只负责一个 Planner 任务。

纪律（硬性）：
1. 项目代码只能通过下面的只读工具访问；你没有任何 Shell、写文件或网络工具。
2. 结论必须来自你亲自读到的代码：必须给出 file 和 line_start，并与工具返回的证据一致。
3. 证据不足时用 action=candidates 提交假设；绝不要把假设写成 findings。
4. 先读共享事实黑板，避免重复调查；优先追踪 Controller -> Service -> DAO 的跨文件调用链。
5. 调查充分后主动 action=finish，不要耗尽轮次。

所有输出必须是单个 JSON 对象，不要 markdown。
"""

RISK_PATTERNS: dict[str, list[tuple[re.Pattern, str, str]]] = {
    "authz": [
        (
            re.compile(r"(?i)(user_id|owner_id|account_id)\s*=\s*(request|req)\.(args|json|form|query|params|GET|POST)"),
            "资源标识直接取自请求参数，未见对象归属校验", "HIGH",
        ),
    ],
    "injection": [
        (
            re.compile(r"(?i)\b(query|sql|statement)\s*=\s*f[\"']"),
            "SQL 语句由 f-string 内插外部值构造，疑似注入", "HIGH",
        ),
        (
            re.compile(r"(?i)\b(query|sql|statement)\s*=\s*(?:\"[^\"]*\"|'[^']*')\s*\+"),
            "SQL 语句由字符串拼接构造，疑似注入", "HIGH",
        ),
        (
            re.compile(r"(?i)(execute|cursor\.execute)\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*\+)"),
            "拼接/格式化的 SQL 直接进入执行汇聚点", "HIGH",
        ),
        (
            re.compile(r"(?i)(os\.system|eval\(|exec\().*(request|user_input|payload)"),
            "外部输入进入命令或代码执行汇聚点", "CRITICAL",
        ),
    ],
    "business_logic": [
        (
            re.compile(r"(?i)(amount|price|balance)\s*=\s*(request|req)\.(json|args|form|data|get_json)"),
            "金额/数量直接采信客户端传值", "HIGH",
        ),
    ],
}

# Local heuristics only. A check in another function cannot discharge a hit.
AUTHZ_CONTROL = re.compile(
    r"(?i)(check_owner|assert_owner|require_permission|is_owner|current_user\.id\s*!=)"
)


@dataclass
class WorkerOutcome:
    facts_written: int = 0
    hypotheses: int = 0
    candidates: int = 0
    findings_linked: int = 0
    tool_calls: int = 0
    llm_rounds: int = 0
    notes: list[str] = field(default_factory=list)
    coverage: str = "uncovered"
    evidence_count: int = 0
    visible_through: int = 0

    def summary(self) -> str:
        counts = (
            f"工具 {self.tool_calls} 次 / LLM {self.llm_rounds} 轮；"
            f"新增事实 {self.facts_written}，假设 {self.hypotheses}，"
            f"候选 {self.candidates}，关联 Finding {self.findings_linked}"
        )
        return " ".join([counts, *self.notes])


async def log_event(
    db: AsyncSession, scan_id: int, event_type: str, payload: dict, *, level: str = "info"
) -> None:
    """Append a redacted, size-bounded execution record to ScanEvent."""
    body = {"type": event_type, **payload}
    text = json.dumps(body, ensure_ascii=False)
    db.add(
        ScanEvent(
            scan_id=scan_id,
            level=level,
            phase=DEEP_AUDIT_PHASE,
            tool=str(event_type)[:64],
            message=redact_text(text)[:4000],
        )
    )
    await db.commit()


def _prompt_text(shared: str, task: dict) -> str:
    return (
        f"{WORKER_SYSTEM_PROMPT}\n\n"
        f"{audit_tool_specs()}\n\n"
        f"=== 共享事实黑板（跨任务、跨 Worker 可读） ===\n{shared}\n\n"
        f"=== 当前任务 ===\n{json.dumps(task, ensure_ascii=False)}"
    )


async def _execute_tool(
    db: AsyncSession,
    *,
    run: AuditRun,
    task: AuditTask,
    repo: ReadOnlyRepository,
    policy: BudgetPolicy,
    ledger: BudgetHandle,
    tool: str,
    arguments: dict,
    agent_slug: str,
    cancel_check,
    outcome: WorkerOutcome,
) -> tuple[str, list[Any], bool]:
    """One guarded tool call -> tool result + code fact + evidence, committed."""
    cancel_check()
    ledger.take_tool()
    await ledger.checkpoint(db, run)
    cancel_check()
    started = time.perf_counter()
    deadline = min(policy.max_tool_seconds, ledger.run.remaining_seconds())

    def check():
        cancel_check()
        ledger.run.check_time()
        if time.perf_counter() - started >= deadline:
            raise TimeoutError("只读工具超时")

    try:
        result, slices = await asyncio.wait_for(
            asyncio.to_thread(execute_read_only_tool, repo, tool, arguments, policy, check),
            timeout=deadline,
        )
    except TimeoutError:
        ledger.run.check_time()
        result, slices = '{"ok": false, "error": "只读工具超时"}', []
    except RepositoryChanged:
        raise
    except ToolPolicyError:
        result, slices = '{"ok": false, "error": "工具或参数不符合只读策略"}', []
    finally:
        ledger.run.consume_tool(int((time.perf_counter() - started) * 1000))
    cancel_check()
    ledger.run.check_time()
    outcome.tool_calls += 1
    ok = bool(json.loads(result).get("ok"))
    tool_name = tool if tool in ALLOWED_TOOLS else "unknown"
    async with ledger.run.write_lock:
        cancel_check()
        await log_event(
            db, run.scan_id, "tool_call",
            {"run_id": run.id, "agent": agent_slug, "task_id": task.id, "tool": tool_name,
             "ok": ok, "result_chars": len(result), "duration_ms": int((time.perf_counter() - started) * 1000)},
        )
        if not ok:
            return result, slices, False

        dedupe_key = (
            f"read:{[(item.path, item.line_start, item.line_end, item.content_hash) for item in slices]}"
            if slices else f"{tool}:{json.dumps(arguments, sort_keys=True, ensure_ascii=False)}"
        )
        fact, created = await bb.add_fact(
            db, run.id, fact_type="code_fact",
            summary=f"只读工具 {tool} 完成代码调查，读取 {len(slices)} 段代码",
            source=f"tool:{tool}", confidence=0.9, task_id=task.id, dedupe_key=dedupe_key,
            revision=run.repository_revision,
            metadata={"tool": tool, "target": slices[0].path if slices else None},
            commit=False,
        )
        if slices:
            await bb.add_evidence(
                db, fact.id, slices, revision=run.repository_revision,
                evidence_type="code_slice", summary_prefix="只读工具读取", commit=False,
            )
            outcome.evidence_count += len(slices)
        bb.track_task_fact(task, fact)
        await db.commit()
    if created:
        outcome.facts_written += 1
    return result, slices, created


async def _evidence_for_location(
    db: AsyncSession, run: AuditRun, task: AuditTask, cutoff: int, file_path: str, line_start: int
) -> list[Any]:
    """Evidence across ALL runs of this scan (so re-runs can reuse evidence)."""
    from app.models import AuditEvidence

    rows = (
        await db.execute(
            select(AuditEvidence)
            .join(AuditFact, AuditEvidence.fact_id == AuditFact.id)
            .join(AuditRun, AuditFact.run_id == AuditRun.id)
            .where(
                AuditRun.scan_id == run.scan_id,
                or_(AuditRun.id != run.id, AuditFact.id <= cutoff, AuditFact.task_id == task.id,
                    AuditFact.id.in_(bb._loads(task.scope_json, {}).get("fact_refs", []))),
                AuditEvidence.repository_revision == run.repository_revision,
                AuditEvidence.evidence_type == "code_slice",
                AuditFact.fact_type == "code_fact",
                AuditEvidence.file_path == str(file_path)[:1024],
                AuditEvidence.line_start <= int(line_start),
                AuditEvidence.line_end >= int(line_start),
            )
            .limit(20)
        )
    ).scalars().all()
    return list(rows)


async def _submit_candidate(db: AsyncSession, *, ledger: BudgetHandle, cancel_check, **kwargs) -> None:
    async with ledger.run.write_lock:
        cancel_check()
        await _write_candidate(db, **kwargs)
        await db.commit()


async def _write_candidate(
    db: AsyncSession,
    *,
    run: AuditRun,
    task: AuditTask,
    agent_slug: str,
    candidate: dict,
    outcome: WorkerOutcome,
) -> None:
    """Evidence gate: only evidence-backed candidates become Findings."""
    file_path = str(candidate.get("file") or candidate.get("file_path") or "").strip()
    try:
        line_start = int(candidate.get("line_start") or 0)
    except (TypeError, ValueError):
        line_start = 0
    file_path = file_path.replace("\\", "/").removeprefix("./")
    title = str(candidate.get("title") or candidate.get("message") or "未命名候选").strip()[:300]
    evidence = await _evidence_for_location(
        db, run, task, outcome.visible_through, file_path, line_start,
    ) if file_path else []

    if not evidence:
        fact, created = await bb.add_fact(
            db, run.id,
            fact_type="vuln_hypothesis",
            summary=f"[假设·无代码证据] {title} @ {file_path}:{line_start}",
            source=f"worker:{agent_slug}",
            confidence=0.35,
            task_id=task.id,
            dedupe_key=f"hypothesis:{task.task_type}:{file_path}:{line_start}:{title}",
            revision=run.repository_revision,
            metadata={"reason": "未找到覆盖该行号的代码证据，不写入 Finding", "target": file_path},
            commit=False,
        )
        bb.track_task_fact(task, fact)
        if created:
            outcome.hypotheses += 1
        return

    fact, created = await bb.add_fact(
        db, run.id,
        fact_type="candidate_finding",
        summary=f"[候选·有代码证据] {title} @ {file_path}:{line_start}",
        source=f"worker:{agent_slug}",
        confidence=0.65,
        task_id=task.id,
        dedupe_key=f"candidate:{task.task_type}:{file_path}:{line_start}",
        revision=run.repository_revision,
        metadata={"target": file_path, "line_start": line_start, "task_type": task.task_type,
                  "evidence_refs": [e.id for e in evidence[:8]]},
        commit=False,
    )
    bb.track_task_fact(task, fact)
    copies = [
        SimpleNamespace(
            path=e.file_path, line_start=e.line_start, line_end=e.line_end,
            content_hash=e.content_hash,
        )
        for e in evidence[:8]
    ]
    await bb.add_evidence(
        db, fact.id, copies, revision=evidence[0].repository_revision,
        evidence_type="code_slice", summary_prefix="候选结论引用的代码证据", commit=False,
    )
    finding = await bb.link_candidate_finding(
        db, run, fact,
        {
            "title": title,
            "message": candidate.get("description") or candidate.get("message") or title,
            "file": file_path,
            "line_start": line_start,
            "line_end": line_start,
            "severity": candidate.get("severity") or "MEDIUM",
            "category": candidate.get("category"),
            "task_type": task.task_type,
            "rule_id": f"deep-audit/{task.task_type}/{file_path}:{line_start}",
        },
        commit=False,
    )
    if created:
        outcome.candidates += 1
        outcome.facts_written += 1
    if finding is not None:
        outcome.findings_linked += 1
        await log_event(
            db, run.scan_id, "candidate_linked",
            {"run_id": run.id, "fact_id": fact.id, "finding_id": finding.id, "file": file_path, "line_start": line_start,
             "evidence_ids": [e.id for e in evidence[:8]], "review_status": finding.review_status.value},
        )


async def _submit_fact(db: AsyncSession, *, ledger: BudgetHandle, cancel_check, **kwargs) -> None:
    async with ledger.run.write_lock:
        cancel_check()
        await _write_fact(db, **kwargs)
        await db.commit()


async def _write_fact(
    db: AsyncSession,
    *,
    run: AuditRun,
    task: AuditTask,
    agent_slug: str,
    fact_type: str,
    summary: str,
    dedupe_key: str,
    confidence: float,
    outcome: WorkerOutcome,
) -> None:
    fact, created = await bb.add_fact(
        db, run.id, fact_type=fact_type, summary=summary,
        source=f"worker:{agent_slug}", confidence=confidence, task_id=task.id,
        dedupe_key=dedupe_key, revision=run.repository_revision,
        metadata={"task_type": task.task_type}, commit=False,
    )
    bb.track_task_fact(task, fact)
    if created:
        outcome.facts_written += 1
        if fact_type == "vuln_hypothesis":
            outcome.hypotheses += 1


def _detect_risks(slices: list[Any], focus: str) -> list[dict]:
    """Generate candidates from inspected lines, with local Python guard hints."""
    patterns = RISK_PATTERNS.get(focus, [])
    found: list[dict] = []
    for item in slices:
        lines = item.content.splitlines()
        guarded: set[int] = set()
        if focus == "authz" and item.path.endswith(".py"):
            try:
                tree = ast.parse(item.content)
            except SyntaxError:
                tree = None
            if tree is not None:
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if any(isinstance(stmt, ast.If) and AUTHZ_CONTROL.search(ast.unparse(stmt.test))
                           and any(isinstance(child, (ast.Raise, ast.Return))
                                   or (isinstance(child, ast.Expr) and ast.unparse(child).startswith("abort("))
                                   for child in stmt.body)
                           for stmt in node.body):
                        guarded.update(range(node.lineno, node.end_lineno + 1))
        for pattern, reason, severity in patterns:
            for index, line in enumerate(lines):
                if index + 1 in guarded or line.lstrip().startswith(("#", "//")):
                    continue
                if pattern.search(line):
                    found.append(
                        {
                            "file": item.path,
                            "line_start": item.line_start + index,
                            "title": f"{reason}",
                            "description": reason,
                            "severity": severity,
                            "confidence": 0.7,
                            "task_type": focus,
                        }
                    )
                    break
    return found


async def _deterministic_investigation(
    db: AsyncSession,
    *,
    run: AuditRun,
    task: AuditTask,
    repo: ReadOnlyRepository,
    policy: BudgetPolicy,
    ledger: BudgetHandle,
    agent_slug: str,
    cancel_check,
    outcome: WorkerOutcome,
) -> None:
    """Real read-only investigation without an LLM (no credential / LLM failure)."""
    scope = json.loads(task.scope_json or "{}") if isinstance(task.scope_json, str) else (task.scope_json or {})
    focus = scope.get("focus") or task.task_type
    queries = list(scope.get("search_queries") or [])[:2]
    target = str(scope.get("target") or "")
    if "<" in target and ">" in target:
        target = ""

    # 1) Discover controllers/endpoints (real read-only tool).
    listing, _, _ = await _execute_tool(
        db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
        tool="list_controllers", arguments={"limit": 10}, agent_slug=agent_slug,
        cancel_check=cancel_check, outcome=outcome,
    )
    try:
        controllers = (json.loads(listing) or {}).get("controllers") or []
    except (json.JSONDecodeError, TypeError):
        controllers = []

    # 2) Symbol search + cross-file call chain discovery.
    def _clean_path(raw: str) -> str:
        value = str(raw or "").strip().replace("\\", "/")
        while value.startswith("./"):
            value = value[2:]
        if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
            try:
                value = Path(value).relative_to(repo.root).as_posix()
            except (ValueError, OSError):
                return ""
        return value

    related: list[dict] = []
    if target:
        cleaned = _clean_path(target.split(":", 1)[0])
        if cleaned and repo.root / cleaned in repo.files:
            related.append({"path": cleaned, "start_line": 1})
    for raw in [str(c.get("file") or "") for c in controllers[:2]]:
        cleaned = _clean_path(raw)
        if cleaned:
            related.append({"path": cleaned, "start_line": 1, "reason": "controller"})

    # One symbol search per task keeps the budget predictable; the search result
    # also carries related_service candidates for cross-file call tracing.
    for query in (queries or ["get"])[:1]:
        result, _, _ = await _execute_tool(
            db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
            tool="search_code", arguments={"query": query, "limit": 10},
            agent_slug=agent_slug, cancel_check=cancel_check, outcome=outcome,
        )
        try:
            payload = json.loads(result) or {}
        except (json.JSONDecodeError, TypeError):
            payload = {}
        for hit in list(payload.get("hits") or [])[:5]:
            cleaned = _clean_path(hit.get("file_path"))
            if cleaned:
                related.append(
                    {"path": cleaned, "start_line": max(1, int(hit.get("line_start") or 1) - 5)}
                )
        for item in list(payload.get("related_batch_candidates") or [])[:4]:
            cleaned = _clean_path(item.get("path"))
            if cleaned:
                related.append(
                    {
                        "path": cleaned,
                        "start_line": max(1, int(item.get("start_line") or 1)),
                        "reason": item.get("reason") or "related",
                    }
                )

    # 3) Batch-read the files, producing real evidence slices.
    unique: list[dict] = []
    seen: set[str] = set()
    for item in related:
        path = item["path"].replace("\\", "/")
        if not path or path in seen:
            continue
        seen.add(path)
        start = int(item.get("start_line") or 1)
        unique.append(
            {"path": path, "start_line": start, "end_line": start + min(120, policy.max_lines_per_read) - 1}
        )
        if len(unique) >= policy.max_batch_files:
            break
    if not unique:
        outcome.notes.append("未找到可读的源码入口，任务无新增调查")
        return

    _, slices, _ = await _execute_tool(
        db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
        tool="read_files_batch",
        arguments={"files": unique, "per_file_char_limit": policy.max_output_chars},
        agent_slug=agent_slug, cancel_check=cancel_check, outcome=outcome,
    )

    if len(slices) > 1:
        paths = ", ".join(item.path for item in slices)
        await _submit_fact(
            db, ledger=ledger, cancel_check=cancel_check, run=run, task=task, agent_slug=agent_slug, fact_type="code_fact",
            summary=f"已检查关联源码文件：{paths}",
            dedupe_key=f"related-files:{paths}", confidence=0.6, outcome=outcome,
        )

    # 4) Derive candidates only from code that was really read.
    for candidate in _detect_risks(slices, focus)[:4]:
        await _submit_candidate(
            db, ledger=ledger, cancel_check=cancel_check, run=run, task=task, agent_slug=agent_slug,
            candidate=candidate, outcome=outcome,
        )


async def _llm_investigation(
    db: AsyncSession,
    *,
    run: AuditRun,
    task: AuditTask,
    repo: ReadOnlyRepository,
    policy: BudgetPolicy,
    ledger: BudgetHandle,
    agent: Any | None,
    agent_slug: str,
    cancel_check,
    outcome: WorkerOutcome,
    shared_digest: str,
) -> None:
    shared = shared_digest
    task_payload = {
        "task_id": task.id,
        "task_type": task.task_type,
        "goal": task.goal,
        "scope": bb._loads(task.scope_json, {}),
    }
    system = _prompt_text(shared, task_payload)
    messages: list[dict] = [{"role": "system", "content": system}]
    model_task = None if not agent or getattr(agent, "model_task", "agent") == "default" else agent.model_task
    model = (getattr(agent, "model_override", "") or "").strip() or None
    extra_prompt = (getattr(agent, "system_prompt", "") or "").strip()
    if extra_prompt:
        messages.append({"role": "system", "content": f"AgentDefinition 附加指示：\n{extra_prompt}"})
    messages.append({"role": "user", "content": "请开始调查，先调用只读工具取得代码证据。"})

    while True:
        cancel_check()
        try:
            text = await ledger.call_model(
                chat_completion_with_usage, messages, check=cancel_check,
                persist=lambda: ledger.checkpoint(db, run),
                task=model_task, model=model, temperature=0.1,
                timeout=effective_llm_timeout(2, task=model_task),
            )
        except BudgetExceeded:
            raise
        except Exception as exc:
            cancel_check()
            ledger.run.check_time()
            outcome.coverage = "fallback_timeout" if isinstance(exc, TimeoutError) else "fallback_error"
            outcome.notes.append(f"LLM 调用失败，改用规则调查：{type(exc).__name__}")
            async with ledger.run.write_lock:
                cancel_check()
                await log_event(db, run.scan_id, "llm_fallback",
                                {"run_id": run.id, "task_id": task.id, "error_type": type(exc).__name__}, level="warn")
            await _deterministic_investigation(
                db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
                agent_slug=agent_slug, cancel_check=cancel_check, outcome=outcome,
            )
            return
        cancel_check()
        ledger.run.check_time()
        outcome.llm_rounds += 1

        parsed = parse_agent_response(text)
        action = parsed.get("action") if isinstance(parsed, dict) else None
        if not isinstance(action, str) or action not in {"tool", "understand", "candidates", "findings", "finish", "answer"}:
            outcome.coverage = "invalid_output"
            outcome.notes.append("模型输出无效，任务未有效完成")
            break

        if action == "tool":
            tool = str(parsed.get("tool") or "")
            arguments = parsed.get("arguments")
            result, _, _ = await _execute_tool(
                db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
                tool=tool, arguments=arguments, agent_slug=agent_slug,
                cancel_check=cancel_check, outcome=outcome,
            )
            messages.append({"role": "assistant", "content": text})
            messages.append(
                {"role": "user", "content": f"工具 `{tool}` 返回:\n{result[:6000]}\n\n请继续调查或输出最终 JSON。"}
            )
            continue

        if action in ("understand", "candidates"):
            items = (
                [{"title": parsed.get("app_summary")}]
                if action == "understand" and isinstance(parsed.get("app_summary"), str)
                else parsed.get("candidates")
            )
            for item in (items[:5] if isinstance(items, list) else []):
                if isinstance(item, dict):
                    await _submit_fact(
                        db, ledger=ledger, cancel_check=cancel_check, run=run, task=task, agent_slug=agent_slug,
                        fact_type="vuln_hypothesis",
                        summary=f"[假设] {str(item.get('title') or item.get('hypothesis') or '')[:300]}",
                        dedupe_key=f"hypothesis:{task.task_type}:{item.get('title')}",
                        confidence=0.4, outcome=outcome,
                    )
        elif action in ("findings", "finish"):
            items = parsed.get("findings")
            for item in (items[:8] if isinstance(items, list) else []):
                if isinstance(item, dict):
                    await _submit_candidate(
                        db, ledger=ledger, cancel_check=cancel_check, run=run, task=task, agent_slug=agent_slug,
                        candidate=item, outcome=outcome,
                    )
        if action in ("finish", "answer"):
            outcome.coverage = "covered" if outcome.evidence_count else "uncovered"
            break
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "user", "content": "已记录你的提交。请继续调查或输出 action=finish 结束。"})


async def run_worker_task(
    db: AsyncSession,
    *,
    run: AuditRun,
    task: AuditTask,
    repo: ReadOnlyRepository,
    policy: BudgetPolicy,
    ledger: BudgetHandle,
    agent: Any | None = None,
    cancel_check=None,
    use_llm: bool = False,
    shared_digest: str = "",
    visible_through: int = 0,
) -> WorkerOutcome:
    """Execute one Planner task with one general-purpose Worker."""
    if cancel_check is None:
        cancel_check = lambda: None
    agent_slug = task.agent_id or run.agent_slug or "deep-audit-worker"
    outcome = WorkerOutcome(visible_through=visible_through)
    async with ledger.run.write_lock:
        cancel_check()
        await log_event(
            db, run.scan_id, "task_started",
            {"run_id": run.id, "task_id": task.id, "task_type": task.task_type, "agent": agent_slug,
             "mode": "llm" if use_llm else "deterministic",
             "model": getattr(agent, "model_override", None) if use_llm else None},
        )
    if use_llm:
        await _llm_investigation(
            db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
            agent=agent, agent_slug=agent_slug, cancel_check=cancel_check, outcome=outcome,
            shared_digest=shared_digest,
        )
    else:
        await _deterministic_investigation(
            db, run=run, task=task, repo=repo, policy=policy, ledger=ledger,
            agent_slug=agent_slug, cancel_check=cancel_check, outcome=outcome,
        )
        outcome.coverage = "deterministic_verified" if outcome.evidence_count else "deterministic_uncovered"
    async with ledger.run.write_lock:
        cancel_check()
        await log_event(
            db, run.scan_id, "task_finished",
            {"run_id": run.id, "task_id": task.id, "agent": agent_slug,
             "summary": outcome.summary(), "coverage": outcome.coverage},
        )
    return outcome
