"""Phase 2 platform management HTTP tests (ASGI + in-memory sqlite).

这些用例走真实端点，覆盖鉴权覆盖、请求校验、持久化、审计留痕和
「不伪造能力」的契约：Agent 不接调度器、MCP stdio 不执行命令、
账户页不虚构用户表。
"""
from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db
from app.dependencies.auth import require_admin
from app.main import app
from app.models import RefreshToken

LONG_SECRET = "x" * 48


async def _make_db():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


class PlatformManagementApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_admin] = lambda: {
            "username": "tester",
            "role": "admin",
        }

    def tearDown(self):
        app.dependency_overrides.clear()

    def _with_client(self, scenario):
        async def _main():
            engine, factory = await _make_db()

            async def _override_get_db():
                async with factory() as session:
                    yield session

            app.dependency_overrides[get_db] = _override_get_db
            try:
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    return await scenario(client, factory)
            finally:
                app.dependency_overrides.pop(get_db, None)
                await engine.dispose()

        return asyncio.run(_main())

    # ---------------- Stage B: Agent definitions ----------------

    def test_agent_crud_and_configuration_only_contract(self):
        async def scenario(client, factory):
            caps = await client.get("/api/agents/capabilities")
            self.assertEqual(caps.status_code, 200)
            body = caps.json()
            self.assertFalse(body["execution_wired"])
            self.assertIsNone(body["scheduler"])
            self.assertIsNone(body["blackboard"])
            self.assertEqual(body["runtime_status"], "configuration_only")
            self.assertTrue(body["resolved_models"]["agent"])

            created = await client.post(
                "/api/agents",
                json={
                    "slug": "code-worker",
                    "name": "Code Worker",
                    "role": "worker",
                    "model_task": "agent",
                    "max_files": 24,
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            row = created.json()
            self.assertEqual(row["slug"], "code-worker")
            self.assertEqual(row["max_files"], 24)
            self.assertFalse(row["execution_wired"])
            self.assertEqual(row["effective_model"], body["resolved_models"]["agent"])
            agent_id = row["id"]

            duplicate = await client.post(
                "/api/agents", json={"slug": "code-worker", "name": "Dup"}
            )
            self.assertEqual(duplicate.status_code, 409)

            invalid_role = await client.post(
                "/api/agents", json={"slug": "bad-role", "name": "Bad", "role": "hacker"}
            )
            self.assertEqual(invalid_role.status_code, 422)

            invalid_budget = await client.post(
                "/api/agents",
                json={"slug": "bad-budget", "name": "Bad", "max_files": 9999},
            )
            self.assertEqual(invalid_budget.status_code, 422)

            invalid_slug = await client.post(
                "/api/agents", json={"slug": "Bad Slug!", "name": "Bad"}
            )
            self.assertEqual(invalid_slug.status_code, 422)

            updated = await client.put(
                f"/api/agents/{agent_id}",
                json={"name": "Code Worker v2", "enabled": False},
            )
            self.assertEqual(updated.status_code, 200, updated.text)
            self.assertEqual(updated.json()["name"], "Code Worker v2")
            self.assertFalse(updated.json()["enabled"])

            empty = await client.put(f"/api/agents/{agent_id}", json={})
            self.assertEqual(empty.status_code, 400)

            listing = await client.get("/api/agents")
            self.assertEqual(len(listing.json()), 1)

            logs = await client.get("/api/accounts/audit-logs")
            actions = [item["action"] for item in logs.json()["items"]]
            self.assertIn("agent.create", actions)
            self.assertIn("agent.update", actions)

            removed = await client.delete(f"/api/agents/{agent_id}")
            self.assertEqual(removed.status_code, 200)
            self.assertEqual((await client.get("/api/agents")).json(), [])
            missing = await client.delete(f"/api/agents/{agent_id}")
            self.assertEqual(missing.status_code, 404)

        self._with_client(scenario)

    def test_agent_effective_model_follows_explicit_override(self):
        async def scenario(client, factory):
            created = await client.post(
                "/api/agents",
                json={
                    "slug": "deep-reviewer",
                    "name": "Deep Reviewer",
                    "role": "reviewer",
                    "model_task": "deep",
                    "model_override": "my-private-model",
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(created.json()["effective_model"], "my-private-model")

        self._with_client(scenario)

    # ---------------- Stage C: MCP server registry ----------------

    def test_mcp_crud_ssrf_guard_and_honest_test_results(self):
        async def scenario(client, factory):
            caps = await client.get("/api/mcp/capabilities")
            self.assertEqual(caps.status_code, 200)
            self.assertFalse(caps.json()["stdio_execution_enabled"])
            self.assertFalse(caps.json()["credential_storage_enabled"])
            self.assertFalse(caps.json()["redirects_followed"])

            created = await client.post(
                "/api/mcp/servers",
                json={
                    "slug": "internal-mcp",
                    "name": "Internal MCP",
                    "transport": "http",
                    "endpoint": "http://127.0.0.1:9999/mcp",
                    "headers": {"X-Client": "ai-audit"},
                    "timeout_seconds": 3,
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            row = created.json()
            self.assertEqual(row["args"], [])
            self.assertEqual(row["headers"], {"X-Client": "ai-audit"})
            self.assertIsNone(row["last_test_ok"])
            server_id = row["id"]

            # A real probe is attempted, but the SSRF guard blocks loopback.
            probe = await client.post(f"/api/mcp/servers/{server_id}/test")
            self.assertEqual(probe.status_code, 200, probe.text)
            self.assertFalse(probe.json()["ok"])
            self.assertEqual(probe.json()["status"], "blocked")
            self.assertTrue(probe.json()["checked_at"])

            persisted = (await client.get("/api/mcp/servers")).json()[0]
            self.assertFalse(persisted["last_test_ok"])
            self.assertIn("SSRF", persisted["last_test_message"])

            # No credential-like header may ever be stored.
            secret = await client.post(
                "/api/mcp/servers",
                json={
                    "slug": "with-secret",
                    "name": "With Secret",
                    "endpoint": "https://example.com/mcp",
                    "headers": {"Authorization": "Bearer SHOULD-NOT-BE-STORED"},
                },
            )
            self.assertEqual(secret.status_code, 422)
            self.assertNotIn("SHOULD-NOT-BE-STORED", secret.text)

            changed = await client.put(
                f"/api/mcp/servers/{server_id}",
                json={"endpoint": "https://example.com/mcp"},
            )
            self.assertEqual(changed.status_code, 200, changed.text)
            self.assertIsNone(changed.json()["last_test_ok"])
            self.assertIn("重新测试", changed.json()["last_test_message"])

            logs = await client.get("/api/accounts/audit-logs")
            actions = [item["action"] for item in logs.json()["items"]]
            self.assertIn("mcp.create", actions)
            self.assertIn("mcp.test", actions)

            removed = await client.delete(f"/api/mcp/servers/{server_id}")
            self.assertEqual(removed.status_code, 200)
            self.assertEqual((await client.get("/api/mcp/servers")).json(), [])

        self._with_client(scenario)

    def test_mcp_stdio_probe_reports_not_executed(self):
        async def scenario(client, factory):
            created = await client.post(
                "/api/mcp/servers",
                json={
                    "slug": "local-tools",
                    "name": "Local Tools",
                    "transport": "stdio",
                    "command": "node server.js",
                    "args": ["--stdio"],
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(created.json()["args"], ["--stdio"])
            server_id = created.json()["id"]

            probe = await client.post(f"/api/mcp/servers/{server_id}/test")
            self.assertEqual(probe.status_code, 200)
            self.assertFalse(probe.json()["ok"])
            self.assertEqual(probe.json()["status"], "not_executed")
            self.assertIn("未开放命令执行", probe.json()["message"])

        self._with_client(scenario)

    # ---------------- Stage D: Accounts ----------------

    def test_accounts_overview_sessions_and_cleanup(self):
        async def scenario(client, factory):
            overview = await client.get("/api/accounts/overview")
            self.assertEqual(overview.status_code, 200, overview.text)
            body = overview.json()
            self.assertEqual(body["username"], "tester")
            self.assertFalse(body["user_management_enabled"])
            self.assertEqual(body["password_source"], "env")
            self.assertGreater(body["token_expire_hours"], 0)
            self.assertEqual(body["session_count"], 0)

            now = datetime.now(timezone.utc)
            async with factory() as session:
                session.add(
                    RefreshToken(
                        local_refresh_token="abcdef123456",
                        username="tester",
                        role="admin",
                        expire_at=now + timedelta(days=1),
                        created_at=now,
                    )
                )
                session.add(
                    RefreshToken(
                        local_refresh_token="stale0000000",
                        username="tester",
                        role="user",
                        # naive value on purpose: MySQL/SQLite read back tzinfo=None
                        expire_at=(now - timedelta(days=1)).replace(tzinfo=None),
                        created_at=now - timedelta(days=8),
                    )
                )
                await session.commit()

            sessions = await client.get("/api/accounts/sessions")
            self.assertEqual(sessions.status_code, 200, sessions.text)
            items = sessions.json()["items"]
            self.assertEqual(len(items), 2)
            self.assertTrue(all(item["token_hint"].endswith("…") for item in items))
            self.assertTrue(all(len(item["token_hint"]) == 7 for item in items))
            expired = [item for item in items if item["expired"]]
            self.assertEqual(len(expired), 1)

            cleanup = await client.post("/api/accounts/sessions/cleanup")
            self.assertEqual(cleanup.status_code, 200, cleanup.text)
            self.assertEqual(cleanup.json()["removed"], 1)

            remaining = (await client.get("/api/accounts/sessions")).json()["items"]
            self.assertEqual(len(remaining), 1)
            revoked = await client.delete(f"/api/accounts/sessions/{remaining[0]['id']}")
            self.assertEqual(revoked.status_code, 200)
            again = await client.delete(f"/api/accounts/sessions/{remaining[0]['id']}")
            self.assertEqual(again.status_code, 404)

        self._with_client(scenario)

    def test_password_change_persists_and_login_uses_new_password(self):
        async def scenario(client, factory):
            wrong = await client.post(
                "/api/accounts/password",
                json={"current_password": "wrong", "new_password": "another-long-password"},
            )
            self.assertEqual(wrong.status_code, 400)

            short = await client.post(
                "/api/accounts/password",
                json={"current_password": "bootstrap-password", "new_password": "short"},
            )
            self.assertEqual(short.status_code, 422)

            changed = await client.post(
                "/api/accounts/password",
                json={
                    "current_password": "bootstrap-password",
                    "new_password": "rotated-password-2026",
                    "revoke_sessions": True,
                },
            )
            self.assertEqual(changed.status_code, 200, changed.text)
            self.assertEqual(changed.json()["password_source"], "database")
            self.assertEqual(changed.json()["password_storage"], "bcrypt")

            overview = (await client.get("/api/accounts/overview")).json()
            self.assertEqual(overview["password_source"], "database")
            self.assertEqual(overview["password_storage"], "bcrypt")

            old_login = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "bootstrap-password"},
            )
            self.assertEqual(old_login.status_code, 401)
            new_login = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "rotated-password-2026"},
            )
            self.assertEqual(new_login.status_code, 200, new_login.text)
            self.assertTrue(new_login.json()["access_token"])

            logs = (await client.get("/api/accounts/audit-logs")).json()["items"]
            change_log = [x for x in logs if x["action"] == "account.change_password"][0]
            self.assertNotIn("rotated-password-2026", str(change_log))
            self.assertNotIn("bootstrap-password", str(change_log))

        with patch.object(settings, "auth_enabled", True), patch.object(
            settings, "auth_username", "admin"
        ), patch.object(settings, "auth_password", "bootstrap-password"), patch.object(
            settings, "auth_secret_key", LONG_SECRET
        ):
            self._with_client(scenario)

    def test_admin_required_on_all_platform_endpoints(self):
        async def scenario(client, factory):
            # Drop the override so the real require_admin chain rejects anonymous calls.
            app.dependency_overrides.pop(require_admin, None)
            for path in (
                "/api/agents",
                "/api/agents/capabilities",
                "/api/mcp/servers",
                "/api/mcp/capabilities",
                "/api/accounts/overview",
                "/api/accounts/sessions",
                "/api/accounts/audit-logs",
            ):
                resp = await client.get(path)
                self.assertEqual(resp.status_code, 401, f"{path} -> {resp.status_code}")

        with patch.object(settings, "auth_enabled", True), patch.object(
            settings, "auth_secret_key", LONG_SECRET
        ):
            self._with_client(scenario)


if __name__ == "__main__":
    unittest.main()
