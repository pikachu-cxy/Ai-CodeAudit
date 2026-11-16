from __future__ import annotations

import asyncio
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.database import Base, get_db
from app.dependencies.auth import require_auth
from app.main import app
from app.models import AgentDefinition, AuditEvidence, AuditFact, Finding, ScanSource, ScanStatus, ScanTask
from app.services import blackboard_service, deep_audit_service, deep_audit_worker, scan_service
from app.services.deep_audit_budget import BudgetExceeded, BudgetLedger, BudgetPolicy
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

    async def test_no_evidence_only_creates_a_hypothesis(self):
        async def attempt(db, *, run, task, **kwargs):
            outcome = deep_audit_worker.WorkerOutcome()
            await deep_audit_worker._submit_candidate(
                db, run=run, task=task, agent_slug=run.agent_slug,
                candidate={"file": "app.py", "line_start": 10, "title": "unsupported"},
                outcome=outcome,
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
