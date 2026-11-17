from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.database import Base, get_db
from app.dependencies.auth import require_auth
from app.main import app
from app.migrations.hooks import apply_011_agent_specialties
from app.models import AgentDefinition, AuditEvidence, AuditFact, Finding, ScanSource, ScanStatus, ScanTask
from app.services import blackboard_service, deep_audit_model_planner, deep_audit_service, deep_audit_worker, scan_service
from app.services.deep_audit_budget import BudgetExceeded, BudgetLedger, BudgetPolicy, RoleBudgetExceeded
from app.services.deep_audit_guards import ReadOnlyRepository, ToolPolicyError, execute_read_only_tool

FIXTURES = Path(__file__).parent / "fixtures"


class DeepAuditTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.engine = create_async_engine(f"sqlite+aiosqlite:///{self.root / 'acceptance.db'}")
        self.factory = async_sessionmaker(self.engine, expire_on_commit=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async def database():
            async with self.factory() as db:
                yield db

        self.enterContext(patch.dict(app.dependency_overrides, {
            get_db: database, require_auth: lambda: {"username": "test", "role": "admin"},
        }))
        self.enterContext(patch.object(deep_audit_service, "async_session", self.factory))
        self.enterContext(patch.object(settings, "repos_dir", self.root))
        self.enterContext(patch.object(settings, "llm_enabled", False))
        self.enterContext(patch.object(settings, "llm_api_key", ""))
        self.client = await self.enterAsyncContext(AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
        ))
        self.scan_ids = {}
        async with self.factory() as db:
            db.add(AgentDefinition(slug="acceptance-worker", name="Acceptance", role="worker"))
            for name in ("vuln", "safe"):
                project = self.root / name
                shutil.copytree(FIXTURES / f"deep_audit_{name}", project)
                scan = ScanTask(name=name, source=ScanSource.UPLOAD, status=ScanStatus.COMPLETED,
                                project_path=str(project))
                db.add(scan)
                await db.flush()
                self.scan_ids[name] = scan.id
            await db.commit()

    async def asyncTearDown(self):
        await self.engine.dispose()

    async def _start(self, name, **options):
        response = await self.client.post(f"/api/scans/{self.scan_ids[name]}/deep-audit/runs",
                                          json={"agent_slug": "acceptance-worker", **options})
        self.assertEqual(response.status_code, 201, response.text)
        run_id = response.json()["run"]["id"]
        task = deep_audit_service._active_runs.get(run_id)
        if task:
            await asyncio.wait_for(asyncio.shield(task), timeout=15)
        return run_id, (await self.client.get(f"/api/deep-audit/runs/{run_id}")).json()

    async def test_upgrade_existing_agent_definitions(self):
        old_engine = create_async_engine("sqlite+aiosqlite://")
        self.addAsyncCleanup(old_engine.dispose)
        async with old_engine.begin() as conn:
            await conn.execute(text("CREATE TABLE agent_definitions (id INTEGER PRIMARY KEY, slug TEXT)"))
            await conn.execute(text("INSERT INTO agent_definitions VALUES (1, 'existing-worker')"))
            await apply_011_agent_specialties(conn)
            await apply_011_agent_specialties(conn)
            row = (await conn.execute(text("SELECT id, slug, specialties FROM agent_definitions"))).one()
            self.assertEqual(tuple(row), (1, "existing-worker", None))

    async def test_role_budget_is_restored_and_shared_budget_still_applies(self):
        policy = BudgetPolicy(max_llm_rounds=2)
        role = BudgetPolicy(max_llm_rounds=1)
        ledger = BudgetLedger(policy)
        reservation, _ = await ledger.handle("worker:audit-authz", role).reserve_llm("prompt", lambda: None)
        ledger.handle("worker:audit-authz", role).settle_llm(reservation, "prompt", "", {"prompt_tokens": 5}, 1)
        restored = BudgetLedger.restore(policy, ledger.snapshot())
        with self.assertRaises(RoleBudgetExceeded):
            await restored.handle("worker:audit-authz", role).reserve_llm("prompt", lambda: None)

        async def claim(key):
            try:
                await restored.handle(key, policy).reserve_llm("prompt", lambda: None)
                return True
            except BudgetExceeded:
                return False
        self.assertEqual(sorted(await asyncio.gather(claim("worker:b"), claim("worker:c"))), [False, True])
        self.assertEqual(restored.llm_rounds, 2)

    async def _create_lineup(self):
        async with self.factory() as db:
            db.add_all([
                AgentDefinition(slug="audit-planner", name="Planner", role="planner",
                                model_override="planner-model", system_prompt="planner-instruction"),
                AgentDefinition(slug="audit-authz", name="Auth", role="worker", specialties=["authz"],
                                model_override="auth-model", system_prompt="auth-instruction"),
                AgentDefinition(slug="audit-sql", name="SQL", role="worker", specialties=["injection"],
                                model_override="sql-model", system_prompt="sql-instruction"),
                AgentDefinition(slug="audit-review", name="Review", role="reviewer"),
            ])
            await db.commit()
        return {
            "planner_slug": "audit-planner", "worker_slugs": ["audit-authz", "audit-sql"],
            "focus": ["authz", "injection"], "max_tasks": 2,
        }

    async def test_model_plan_changes_tasks_and_specialized_workers_enter_same_batch(self):
        lineup = await self._create_lineup()
        path = f"/api/scans/{self.scan_ids['vuln']}/deep-audit/plan"
        baseline = (await self.client.post(path, json={"focus": lineup["focus"]})).json()
        calls = []
        usage = {"prompt_tokens": 120, "completion_tokens": 30}
        planner_calls = 0
        both_entered = asyncio.Event()

        async def planner(messages, **kwargs):
            nonlocal planner_calls
            planner_calls += 1
            if planner_calls == 2:  # The run has already frozen its configuration.
                async with self.factory() as db:
                    row = await db.scalar(select(AgentDefinition).where(AgentDefinition.slug == "audit-sql"))
                    row.enabled = False
                    row.model_override = "changed-after-start"
                    row.system_prompt = "changed-after-start"
                    await db.commit()
            self.assertEqual(kwargs["model"], "planner-model")
            self.assertIn("planner-instruction", str(messages))
            self.assertNotIn(str(self.root), str(messages))
            return json.dumps({"tasks": [
                {"focus": "authz", "target": "app.py", "goal": "Model checks owner", "priority": 80},
                {"focus": "injection", "target": "services.py", "goal": "Model checks SQL", "priority": 70},
            ]}), usage

        async def worker(messages, **kwargs):
            model = kwargs["model"]
            calls.append(model)
            instruction = {"auth-model": "auth-instruction", "sql-model": "sql-instruction"}[model]
            self.assertIn(instruction, str(messages))
            self.assertIn("Model checks", messages[0]["content"])
            if calls.count(model) == 1:
                if len(set(calls)) == 2:
                    both_entered.set()
                await asyncio.wait_for(both_entered.wait(), timeout=3)
                file_path = "app.py" if model == "auth-model" else "services.py"
                return json.dumps({"action": "tool", "tool": "read_file", "arguments": {
                    "path": file_path, "start_line": 1, "end_line": 4,
                }}), usage
            return '{"action":"finish","findings":[]}', usage

        with patch.object(settings, "llm_api_key", "test-key"), patch.object(
            deep_audit_model_planner, "chat_completion_with_usage", side_effect=planner,
        ), patch.object(deep_audit_worker, "chat_completion_with_usage", side_effect=worker):
            preview_response = await self.client.post(path, json=lineup)
            self.assertEqual(preview_response.status_code, 200, preview_response.text)
            preview = preview_response.json()
            self.assertEqual(preview["planner_result"]["mode"], "agent_llm")
            self.assertNotEqual([t["goal"] for t in baseline["tasks"]], [t["goal"] for t in preview["tasks"]])
            self.assertEqual([t["agent_id"] for t in preview["tasks"]], ["audit-authz", "audit-sql"])
            run_id, run = await self._start("vuln", agent_slug=None, **lineup)

        self.assertEqual(run["run"]["status"], "completed", run["run"])
        self.assertEqual([t["agent_id"] for t in run["tasks"]], ["audit-authz", "audit-sql"])
        self.assertEqual(set(calls[:2]), {"auth-model", "sql-model"})
        self.assertTrue(both_entered.is_set())
        self.assertEqual(planner_calls, 2)
        self.assertEqual(run["budget_usage"]["llm_rounds"], 5)
        self.assertEqual(run["budget_usage"]["role_usage"]["planner:audit-planner"]["llm_rounds"], 1)
        self.assertEqual(run["budget_usage"]["role_usage"]["worker:audit-authz"]["tool_calls"], 1)
        self.assertEqual(run["budget_usage"]["role_usage"]["worker:audit-sql"]["tool_calls"], 1)
        self.assertNotIn("planner-instruction", json.dumps(run))
        self.assertEqual(
            {e["file_path"] for fact in run["shared_facts"] for e in fact["evidence"]},
            {"app.py", "services.py"},
        )
        listed = (await self.client.get(f"/api/scans/{self.scan_ids['vuln']}/deep-audit/runs")).json()
        self.assertEqual(listed["runs"][0]["id"], run_id)
        self.assertNotIn("auth-instruction", json.dumps(listed))

    async def test_reject_invalid_roles_and_out_of_scope_model_tasks(self):
        lineup = await self._create_lineup()
        path = f"/api/scans/{self.scan_ids['safe']}/deep-audit"
        for changes in (
            {"planner_slug": "audit-authz"}, {"worker_slugs": ["audit-planner"]},
            {"worker_slugs": ["audit-review"]}, {"worker_slugs": ["audit-authz", "audit-authz"]},
            {"agent_slug": "acceptance-worker"},
        ):
            self.assertEqual((await self.client.post(path + "/runs", json={**lineup, **changes})).status_code, 400)
        proposal = {"tasks": [{"focus": "authz", "target": "services.py", "goal": "OUT OF SCOPE", "priority": 9}]}
        with patch.object(settings, "llm_api_key", "test-key"), patch.object(
            deep_audit_model_planner, "chat_completion_with_usage",
            new=AsyncMock(return_value=(json.dumps(proposal), {"prompt_tokens": 100})),
        ):
            scope = {**lineup, "focus": ["authz"], "path_prefixes": ["app.py"]}
            response = await self.client.post(path + "/plan", json=scope)
            with patch.object(deep_audit_worker, "chat_completion_with_usage", new=AsyncMock(
                return_value=('{"action":"finish","findings":[]}', {"prompt_tokens": 100}),
            )):
                _, rejected = await self._start("vuln", agent_slug=None, **scope)
            self.assertEqual(rejected["run"]["config_snapshot"]["planner_result"]["fallback_reason"], "plan_out_of_scope")
            self.assertNotIn("OUT OF SCOPE", json.dumps(rejected["tasks"]))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["planner_result"]["fallback_reason"], "plan_out_of_scope")
        self.assertNotIn("OUT OF SCOPE", response.text)
        _, run = await self._start("safe", agent_slug=None, **lineup)
        self.assertEqual(run["run"]["status"], "completed")
        self.assertEqual(run["run"]["config_snapshot"]["planner_result"]["fallback_reason"], "llm_not_configured")
        self.assertEqual(run["budget_usage"]["llm_rounds"], 0)
        self.assertGreater(run["budget_usage"]["tool_calls"], 0)

    async def test_saved_budget_applies_to_new_runs_and_keeps_existing_snapshot(self):
        path = "/api/deep-audit/settings"
        budget = {"max_llm_rounds": 30, "max_tool_calls": 45, "max_total_tokens": 75000}
        original = (await self.client.get(path)).json()
        old_run_id, old_run = await self._start("vuln", max_tasks=1)
        self.assertNotEqual(old_run["budget_usage"]["policy"]["max_llm_rounds"], 30)

        with patch.dict(app.dependency_overrides, {require_auth: lambda: {"role": "user"}}):
            self.assertEqual((await self.client.put(path, json=budget)).status_code, 403)

        self.assertEqual((await self.client.put(path, json={**budget, "max_llm_rounds": 0})).status_code, 422)
        self.assertEqual((await self.client.get(path)).json(), original)
        response = await self.client.put(path, json=budget)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual((await self.client.get(path)).json(), budget)

        # The existing fixture uses a custom Agent, which can lower the saved ceiling.
        _, custom = await self._start("safe", max_tasks=1)
        self.assertEqual(custom["budget_usage"]["policy"]["max_llm_rounds"], 10)
        _, builtin = await self._start("safe", max_tasks=1, agent_slug=None)
        for key, value in budget.items():
            self.assertEqual(builtin["budget_usage"]["policy"][key], value)
        reloaded = (await self.client.get(f"/api/deep-audit/runs/{old_run_id}")).json()
        self.assertEqual(reloaded["budget_usage"]["policy"], old_run["budget_usage"]["policy"])

    async def test_vulnerable_and_safe_projects(self):
        scan_id = self.scan_ids["vuln"]
        preview = await self.client.post(f"/api/scans/{scan_id}/deep-audit/plan", json={})
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual({t["task_type"] for t in preview.json()["tasks"]},
                         {"authz", "injection", "business_logic"})
        seen_digests = []
        worker = deep_audit_service.run_worker_task

        async def observe(db, **kwargs):
            seen_digests.append(await blackboard_service.shared_facts_digest(db, kwargs["run"].id))
            return await worker(db, **kwargs)

        with patch.object(deep_audit_service, "run_worker_task", observe):
            run_id, result = await self._start("vuln")
        self.assertEqual(result["run"]["status"], "completed", result)
        self.assertTrue(any("只读工具" in digest for digest in seen_digests[1:]))
        self.assertEqual(result["confirmed_findings"], [])
        self.assertEqual({f["metadata"]["task_type"] for f in result["candidates"]},
                         {"authz", "injection", "business_logic"})
        self.assertEqual(len(result["candidates"]), 4)
        for candidate in result["candidates"]:
            self.assertTrue(candidate["finding_id"])
            self.assertTrue(candidate["evidence"])
            for evidence in candidate["evidence"]:
                self.assertEqual(evidence["repository_revision"], result["run"]["repository_revision"])
                lines = (self.root / "vuln" / evidence["file_path"]).read_text(encoding="utf-8").splitlines()
                body = "\n".join(lines[evidence["line_start"] - 1:evidence["line_end"]])
                self.assertEqual(evidence["content_hash"], hashlib.sha256(body.encode()).hexdigest())
        finding_id = result["candidates"][0]["finding_id"]
        confirmation = await self.client.post(f"/api/deep-audit/runs/{run_id}/findings/{finding_id}/confirm",
                                              json={"review_note": "fixture reviewed"})
        self.assertEqual(confirmation.status_code, 200, confirmation.text)
        self.assertEqual(confirmation.json()["review_status"], "confirmed")

        async with self.factory() as db:
            before = await db.scalar(select(func.count()).select_from(AuditFact))
        repeat_id, repeated = await self._start("vuln")
        self.assertTrue(all(task["status"] == "skipped" for task in repeated["tasks"]))
        wrong_run = await self.client.post(f"/api/deep-audit/runs/{repeat_id}/findings/{finding_id}/confirm", json={})
        self.assertEqual(wrong_run.status_code, 404)
        async with self.factory() as db:
            self.assertEqual(before, await db.scalar(select(func.count()).select_from(AuditFact)))

        _, safe = await self._start("safe")
        self.assertEqual(safe["run"]["status"], "completed", safe)
        self.assertEqual(safe["candidates"], [])
        for name, data in (("vulnerable", result), ("safe", safe)):
            print(f"{name}: candidates={len(data['candidates'])}, budget={data['budget_usage']}")

    async def test_cancel_retains_evidence_and_resume_refuses_changed_source(self):
        original = deep_audit_worker._execute_tool

        async def stop_after_read(db, **kwargs):
            result = await original(db, **kwargs)
            if result[1]:
                deep_audit_service.request_cancel(kwargs["run"].id)
                kwargs["cancel_check"]()
            return result

        with patch.object(deep_audit_worker, "_execute_tool", stop_after_read):
            run_id, result = await self._start("vuln")
        self.assertEqual(result["run"]["status"], "cancelled", result)
        async with self.factory() as db:
            evidence_count = await db.scalar(select(func.count()).select_from(AuditEvidence))
            self.assertGreater(evidence_count, 0)
        path = self.root / "vuln" / "app.py"
        path.write_text(path.read_text(encoding="utf-8") + "\n# new revision\n", encoding="utf-8")
        response = await self.client.post(f"/api/deep-audit/runs/{run_id}/resume")
        self.assertEqual(response.status_code, 200, response.text)
        task = deep_audit_service._active_runs.get(run_id)
        if task:
            await task
        result = (await self.client.get(f"/api/deep-audit/runs/{run_id}")).json()
        self.assertEqual(result["run"]["status"], "failed")
        async with self.factory() as db:
            self.assertEqual(evidence_count, await db.scalar(select(func.count()).select_from(AuditEvidence)))

    async def test_worker_tools_and_budget(self):
        root = self.root / "vuln"
        (root / "secrets.py").write_text("needle = 'sensitive'", encoding="utf-8")
        (root / "large.py").write_text("needle\n" * 900, encoding="utf-8")
        policy = BudgetPolicy(max_file_bytes=4096)
        repo = ReadOnlyRepository(root, policy, prefixes=("app.py",))
        def check():
            pass

        _, slices = execute_read_only_tool(repo, "read_file", {"path": "app.py"}, policy, check)
        self.assertTrue(slices)
        for path in ("services.py", "large.py"):
            _, slices = execute_read_only_tool(repo, "read_file", {"path": path}, policy, check)
            self.assertFalse(slices)
        output, _ = execute_read_only_tool(repo, "search_code", {"query": "execute"}, policy, check)
        self.assertNotIn("services.py", output)
        for tool, args in (("shell", {}), ("search_code", {"query": "../x"}), ("read_file", {"path": "app.py:ads"}),
                           ("read_file", {"path": "secrets.py"}),
                           ("read_file", {"path": "app.py", "start_line": 1.1})):
            with self.assertRaises(ToolPolicyError):
                execute_read_only_tool(repo, tool, args, policy, check)

        with patch.object(settings, "deep_audit_max_tool_calls", 1):
            _, result = await self._start("vuln", focus=["authz"])
        self.assertEqual(result["run"]["status"], "failed")
        self.assertEqual(result["budget_usage"]["exhausted_dimension"], "tool_calls")
        self.assertEqual(result["budget_usage"]["tool_calls"], 1)
        ledger = BudgetLedger.restore(BudgetPolicy(max_llm_rounds=1, max_total_tokens=128, max_seconds=1),
                                      {"elapsed_seconds": 0})
        with self.assertRaisesRegex(BudgetExceeded, "total_tokens"):
            ledger.completion_limit("a" * 128)
        ledger.llm_rounds = 1
        with self.assertRaisesRegex(BudgetExceeded, "llm_rounds"):
            ledger.check_llm()
        restored = BudgetLedger.restore(ledger.policy, {"elapsed_seconds": 1})
        with self.assertRaisesRegex(BudgetExceeded, "seconds"):
            restored.remaining_seconds()

    async def test_batch_limits_cancel_and_resume_preserve_completed_tasks(self):
        lineup = await self._create_lineup()
        lineup.update(max_tasks=3)
        peak = active = 0
        visited: list[int] = []
        completed = None

        async def worker(db, *, run, task, cancel_check, **kwargs):
            nonlocal peak, active, completed
            visited.append(task.id)
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(.04)
                if completed is None:
                    completed = task.id
                elif len(visited) == 2:
                    deep_audit_service.request_cancel(run.id)
                    cancel_check()
                return deep_audit_worker.WorkerOutcome(coverage="deterministic_verified")
            finally:
                active -= 1

        with patch.object(settings, "deep_audit_task_concurrency", 1), patch.object(
            deep_audit_service, "run_worker_task", side_effect=worker,
        ):
            run_id, result = await self._start("vuln", agent_slug=None, **lineup)
            self.assertEqual(peak, 1)
            self.assertEqual(result["run"]["status"], "cancelled")
            self.assertEqual(len(visited), 2)
            self.assertEqual(result["task_concurrency_limit"], 1)
            self.assertEqual(result["active_tasks"], [])
            response = await self.client.post(f"/api/deep-audit/runs/{run_id}/resume")
            self.assertEqual(response.status_code, 200, response.text)
            job = deep_audit_service._active_runs[run_id]
            await asyncio.wait_for(asyncio.shield(job), 12)
            finished = (await self.client.get(f"/api/deep-audit/runs/{run_id}")).json()
            self.assertEqual(finished["run"]["status"], "completed")
            self.assertEqual(visited.count(completed), 1)
            self.assertEqual(peak, 1)

    async def test_same_worker_is_not_scheduled_twice_and_concurrent_writes_dedupe(self):
        lineup = await self._create_lineup()
        lineup["max_tasks"] = 3
        active = set()
        seen = []
        both = asyncio.Event()

        async def planner(messages, **kwargs):
            return json.dumps({"tasks": [
                {"focus": "authz", "target": "app.py", "goal": "Owner", "priority": 90},
                {"focus": "authz", "target": "services.py", "goal": "Roles", "priority": 80},
                {"focus": "injection", "target": "app.py", "goal": "Input", "priority": 70},
            ]}), {"prompt_tokens": 15, "completion_tokens": 10}

        async def worker(db, *, run, task, ledger, cancel_check, repo, policy, visible_through, **kwargs):
            self.assertNotIn(task.agent_id, active)
            active.add(task.agent_id)
            seen.append(task.agent_id)
            try:
                if len(active) == 2:
                    both.set()
                if len(seen) <= 2:
                    await asyncio.wait_for(both.wait(), 3)
                outcome = deep_audit_worker.WorkerOutcome(coverage="covered", visible_through=visible_through)
                await deep_audit_worker._execute_tool(db, run=run, task=task, repo=repo, policy=policy,
                    ledger=ledger, tool="read_file", arguments={"path": "app.py", "start_line": 1, "end_line": 4},
                    agent_slug=task.agent_id, cancel_check=cancel_check, outcome=outcome)
                for _ in range(2):
                    await deep_audit_worker._submit_candidate(db, run=run, task=task,
                        agent_slug=task.agent_id, ledger=ledger, cancel_check=cancel_check, outcome=outcome,
                        candidate={"file": "app.py", "line_start": 2, "title": "Shared evidence"})
                return outcome
            finally:
                active.remove(task.agent_id)

        with patch.object(settings, "llm_api_key", "test-key"), patch.object(
            deep_audit_model_planner, "chat_completion_with_usage", side_effect=planner,
        ), patch.object(deep_audit_service, "run_worker_task", side_effect=worker):
            run_id, summary = await self._start("vuln", agent_slug=None, **lineup)
        self.assertEqual(summary["run"]["status"], "completed")
        self.assertEqual(set(seen[:2]), {"audit-authz", "audit-sql"})
        self.assertEqual(seen[2:], ["audit-authz"])
        self.assertEqual(summary["fact_counts"]["code_fact"], 1)
        self.assertEqual(summary["fact_counts"]["candidate_finding"], 2)  # one per focus
        async with self.factory() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(Finding)), 2)
        graph = (await self.client.get(f"/api/deep-audit/runs/{run_id}/audit-graph")).json()
        self.assertTrue(any(edge["type"] == "references" for edge in graph["edges"]))

    async def test_asset_snapshot_and_audit_graph_link_to_verified_source(self):
        root = self.root / "vuln"
        tiny = ('@RestController\nclass {cls} {{\n'
                '  @PostMapping("/{route}")\n'
                '  public String execute() {{ return "ok"; }}\n'
                '}}\n')
        for cls, route in (("Refund", "refund"), ("Alternate", "refund"), ("Account", "account")):
            (root / f"{cls}.java").write_text(tiny.format(cls=cls, route=route))
        lineup = await self._create_lineup()
        api = f"/api/scans/{self.scan_ids['vuln']}/deep-audit"
        first = (await self.client.post(api + "/asset-graph/build", json={})).json()
        second = (await self.client.post(api + "/asset-graph/build", json={})).json()
        self.assertEqual(first, second)
        refunds = [n for n in first["nodes"] if n["type"] == "endpoint" and n["data"]["path"] == "/refund"]
        self.assertEqual(len({n["id"] for n in refunds}), 2)
        expect_asset = next(n["id"] for n in refunds if n["data"]["file"] == "Refund.java")

        async def planner(messages, **kwargs):
            return json.dumps({"tasks": [
                {"focus": "authz", "target": "Refund.java:/refund", "goal": "Check refund", "priority": 80},
                {"focus": "injection", "target": "Account.java:/account", "goal": "Check account", "priority": 70},
            ]}), {"prompt_tokens": 30, "completion_tokens": 15}

        auth_round = 0

        async def worker(messages, **kwargs):
            nonlocal auth_round
            usage = {"prompt_tokens": 30, "completion_tokens": 15}
            if kwargs["model"] == "sql-model":
                return "invalid format", usage
            auth_round += 1
            if auth_round == 1:
                return json.dumps({"action": "tool", "tool": "read_file", "arguments": {
                    "path": "Refund.java", "start_line": 2, "end_line": 4,
                }}), usage
            return json.dumps({"action": "finish", "findings": [
                {"file": "Refund.java", "line_start": 4, "title": "Missing ownership check"},
            ]}), usage

        with patch.object(settings, "llm_api_key", "test-key"), patch.object(
            deep_audit_model_planner, "chat_completion_with_usage", side_effect=planner,
        ), patch.object(deep_audit_worker, "chat_completion_with_usage", side_effect=worker):
            rid, result = await self._start("vuln", agent_slug=None, **lineup)

        self.assertEqual(result["run"]["status"], "failed")
        self.assertEqual([t["coverage"] for t in result["tasks"]], ["covered", "invalid_output"])
        run_api = f"/api/deep-audit/runs/{rid}"
        source_graph = (await self.client.get(run_api + "/audit-graph")).json()
        auth_task = next(n for n in source_graph["nodes"] if n["type"] == "task" and n["data"]["agent_id"] == "audit-authz")
        self.assertEqual(auth_task["data"]["asset_ids"], [expect_asset])
        self.assertEqual(source_graph["asset_graph_id"], first["asset_graph_id"])
        layer = (await self.client.get(api + f"/asset-graph?run_id={rid}")).json()
        self.assertEqual(first["nodes"], layer["nodes"])
        self.assertEqual(layer["overlay"][expect_asset][0]["id"], auth_task["data"]["task_id"])
        self.assertNotIn(next(n["id"] for n in refunds if n["id"] != expect_asset), layer["overlay"])
        ev = next(n for n in source_graph["nodes"] if n["type"] == "evidence")
        url = run_api + f"/evidence/{ev['data']['id']}/source"
        response = await self.client.get(url)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("execute", response.json()["content"])
        finding = next(n for n in source_graph["nodes"] if n["type"] == "finding")
        response = await self.client.post(run_api + f"/findings/{finding['data']['finding_id']}/confirm", json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["review_status"].lower(), "confirmed")
        (root / "Refund.java").write_text(tiny.format(cls="Refund", route="refund") + "\n// new revision")
        third = (await self.client.post(api + "/asset-graph/build", json={})).json()
        self.assertNotEqual(third["asset_graph_id"], first["asset_graph_id"])
        historical = (await self.client.get(api + f"/asset-graph?run_id={rid}")).json()
        self.assertEqual(historical["nodes"], first["nodes"])
        self.assertEqual((await self.client.get(url)).status_code, 409)

    async def test_no_evidence_only_creates_a_hypothesis(self):
        async def attempt(db, *, run, task, **kwargs):
            outcome = deep_audit_worker.WorkerOutcome()
            await deep_audit_worker._submit_candidate(
                db, run=run, task=task, agent_slug=run.agent_slug,
                candidate={"file": "app.py", "line_start": 10, "title": "unsupported"},
                outcome=outcome, ledger=kwargs["ledger"], cancel_check=kwargs["cancel_check"],
            )
            return outcome

        with patch.object(deep_audit_service, "run_worker_task", attempt):
            _, result = await self._start("vuln", max_tasks=1)
        self.assertEqual(result["fact_counts"]["vuln_hypothesis"], 1)
        self.assertEqual(result["confirmed_findings"], [])
        async with self.factory() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(Finding)), 0)

    async def test_llm_round_limit_with_real_tool_and_provider_stub(self):
        provider = AsyncMock(return_value=(
            '{"action":"tool","tool":"read_file","arguments":{"path":"app.py","start_line":1,"end_line":20}}',
            {"prompt_tokens": 100, "completion_tokens": 25},
        ))
        with (
            patch.object(deep_audit_service, "is_llm_configured", return_value=True),
            patch.object(deep_audit_worker, "chat_completion_with_usage", provider),
            patch.object(settings, "deep_audit_max_llm_rounds", 1),
        ):
            _, result = await self._start("vuln", focus=["authz"], max_tasks=1)
        self.assertEqual(provider.await_count, 1)
        self.assertEqual(provider.call_args.kwargs["max_retries"], 0)
        self.assertEqual(result["budget_usage"]["total_tokens"], 125)
        self.assertEqual(result["budget_usage"]["exhausted_dimension"], "llm_rounds")
        self.assertTrue(any(fact["evidence"] for fact in result["shared_facts"]))

    @unittest.skipUnless(shutil.which("bandit"), "Bandit executable unavailable")
    async def test_existing_scan_pipeline_runs_bandit(self):
        with (
            patch.object(scan_service, "async_session", self.factory),
            patch.object(settings, "enabled_scanners", ["bandit"]),
            patch.object(settings, "llm_code_audit_enabled", False),
        ):
            for name, expected in (("vuln", True), ("safe", False)):
                scan_id = self.scan_ids[name]
                await scan_service.run_scan_pipeline(scan_id)
                async with self.factory() as db:
                    scan = await db.get(ScanTask, scan_id)
                    findings = (await db.scalars(
                        select(Finding).where(Finding.scan_id == scan_id, Finding.tool == "bandit")
                    )).all()
                self.assertEqual(scan.status, ScanStatus.COMPLETED, scan.error_message)
                self.assertEqual(bool(findings), expected)
