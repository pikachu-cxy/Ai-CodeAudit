"""白名单 HTTP 层测试（ASGI + 依赖覆盖，走内存 sqlite，不碰真实库）。

单元测试已覆盖 service 行为，这里专门锁住「路由 + 鉴权 + 请求校验 + 响应序列化」
这一段：字段名、status 取值、created_by 落库、以及 404/422/400 分支。
"""

from __future__ import annotations

import asyncio
import unittest

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base, get_db
from app.dependencies.auth import require_auth
from app.main import app
from app.models import (
    Finding,
    FindingCategory,
    Project,
    ScanSource,
    ScanStatus,
    ScanTask,
    Severity,
)

PROJECT_NAME = "whitelist-api-demo"
RULE_ID = "python.lang.security.audit.dangerous-eval"


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def _seed(factory) -> tuple[int, int, int]:
    async with factory() as s:
        project = Project(
            name=PROJECT_NAME, source_type=ScanSource.GITLAB, default_branch="main"
        )
        s.add(project)
        await s.flush()
        scan = ScanTask(
            project_id=project.id,
            name="v1",
            source=ScanSource.GITLAB,
            status=ScanStatus.COMPLETED,
            project_path="security/demo",
        )
        s.add(scan)
        await s.flush()
        finding = Finding(
            scan_id=scan.id,
            rule_id=RULE_ID,
            message="Use of eval() on untrusted input",
            file_path="src/handler.py",
            line_start=10,
            line_end=11,
            severity=Severity.HIGH,
            tool="semgrep",
            category=FindingCategory.SAST,
        )
        s.add(finding)
        await s.commit()
        return project.id, scan.id, finding.id


def _run(coro):
    return asyncio.run(coro)


class WhitelistApiTests(unittest.TestCase):
    def setUp(self):
        self.engine = None

    def tearDown(self):
        app.dependency_overrides.clear()

    def _make_client(self, factory):
        async def _override_get_db():
            async with factory() as session:
                yield session

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[require_auth] = lambda: {
            "username": "tester",
            "role": "admin",
        }
        return AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        )

    def test_full_lifecycle(self):
        async def go():
            engine, factory = await _make_db()
            try:
                project_id, _scan_id, finding_id = await _seed(factory)
                async with self._make_client(factory) as c:
                    # 初始为空
                    r = await c.get(f"/api/projects/{project_id}/whitelist")
                    self.assertEqual(r.status_code, 200)
                    self.assertEqual(r.json(), [])

                    # 加白
                    r = await c.post(
                        f"/api/projects/{project_id}/whitelist",
                        json={"finding_id": finding_id, "reason": "已评估为可接受风险"},
                    )
                    self.assertEqual(r.status_code, 200, r.text)
                    entry = r.json()
                    self.assertEqual(entry["status"], "whitelist")
                    self.assertEqual(entry["project_id"], project_id)
                    self.assertEqual(entry["created_by"], "tester")
                    self.assertEqual(entry["source_finding_id"], finding_id)
                    self.assertTrue(entry["created_at"])
                    self.assertEqual(entry["rule_id"], RULE_ID)
                    self.assertTrue(entry["fingerprint_strict"])

                    # 列表里能看到
                    r = await c.get(f"/api/projects/{project_id}/whitelist")
                    rows = r.json()
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["id"], entry["id"])

                    # 重复加白同一条 → 幂等，不新增
                    r = await c.post(
                        f"/api/projects/{project_id}/whitelist",
                        json={"finding_id": finding_id, "reason": "换个理由"},
                    )
                    self.assertEqual(r.status_code, 200, r.text)
                    self.assertEqual(r.json()["id"], entry["id"])
                    r = await c.get(f"/api/projects/{project_id}/whitelist")
                    self.assertEqual(len(r.json()), 1)

                    # 删除
                    r = await c.delete(
                        f"/api/projects/{project_id}/whitelist/{entry['id']}"
                    )
                    self.assertEqual(r.status_code, 200, r.text)
                    self.assertTrue(r.json()["ok"])
                    r = await c.get(f"/api/projects/{project_id}/whitelist")
                    self.assertEqual(r.json(), [])
            finally:
                await engine.dispose()

        _run(go())

    def test_error_branches(self):
        async def go():
            engine, factory = await _make_db()
            try:
                project_id, _scan_id, finding_id = await _seed(factory)
                async with self._make_client(factory) as c:
                    # 项目不存在
                    r = await c.get("/api/projects/999999/whitelist")
                    self.assertEqual(r.status_code, 404)

                    # 缺 reason → 422
                    r = await c.post(
                        f"/api/projects/{project_id}/whitelist",
                        json={"finding_id": finding_id},
                    )
                    self.assertEqual(r.status_code, 422)

                    # 空 reason → 422（min_length=1）
                    r = await c.post(
                        f"/api/projects/{project_id}/whitelist",
                        json={"finding_id": finding_id, "reason": ""},
                    )
                    self.assertEqual(r.status_code, 422)

                    # finding 不存在 → 400
                    r = await c.post(
                        f"/api/projects/{project_id}/whitelist",
                        json={"finding_id": 999999, "reason": "x"},
                    )
                    self.assertEqual(r.status_code, 400)

                    # 删不存在的条目 → 404
                    r = await c.delete(f"/api/projects/{project_id}/whitelist/999999")
                    self.assertEqual(r.status_code, 404)
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
