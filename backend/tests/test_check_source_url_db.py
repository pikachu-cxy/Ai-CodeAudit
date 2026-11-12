"""check-source-url 回归测试（真库，in-memory sqlite）。

背景：``GET /api/projects/check-source-url`` 在「URL 命中已有项目」时返回 500。
根因是 ``find_project_by_source_url`` 不带 ``selectinload(Project.scans)``，
把它返回的 Project 直接喂给 ``_project_summary`` 会在异步上下文里触发
``project.scans`` 懒加载 → ``sqlalchemy.exc.MissingGreenlet`` → 500。
（命中项目时会走 ``latest_scan(project)`` / ``len(project.scans)`` 两条懒加载路径。）

修复方式与同文件的 ``check-name`` 保持一致：先 ``get_project`` 重载（带 selectinload）。
本测试直接调用路由处理函数，覆盖修复后的全部分支，删掉重载即会重新变红。
"""

from __future__ import annotations

import asyncio
import unittest

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models import Project, ScanSource, ScanStatus, ScanTask
from app.routers.projects import api_check_source_url

PROJECT_URL = "https://gitlab.example.com/group/nsp"


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def _seed(session) -> tuple[int, int]:
    project = Project(
        name="nsp",
        source_type=ScanSource.GITLAB,
        source_url=PROJECT_URL,
        default_branch="main",
    )
    session.add(project)
    await session.flush()

    scan = ScanTask(
        project_id=project.id,
        name="nsp",
        source=ScanSource.GITLAB,
        status=ScanStatus.COMPLETED,
        project_path="security/nsp",
        source_url=PROJECT_URL,
        branch="main",
        total_findings=3,
        security_score=80,
    )
    session.add(scan)
    await session.commit()
    return project.id, scan.id


def _run(coro):
    return asyncio.run(coro)


class CheckSourceUrlIntegrationTests(unittest.TestCase):
    def test_existing_project_returns_summary(self):
        """命中已有项目必须返回 duplicate=True 的摘要，而不是 MissingGreenlet 500。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project_id, scan_id = await _seed(s)
                    out = await api_check_source_url(url=PROJECT_URL, db=s)

                    self.assertTrue(out.duplicate)
                    self.assertEqual(out.normalized_url, PROJECT_URL)
                    self.assertIsNotNone(out.project)
                    self.assertEqual(out.project.id, project_id)
                    self.assertEqual(out.project.name, "nsp")
                    # 这两条断言正是懒加载曾经炸掉的地方
                    self.assertEqual(out.project.scan_count, 1)
                    self.assertIsNotNone(out.project.latest_scan)
                    self.assertEqual(out.project.latest_scan.id, scan_id)
            finally:
                await engine.dispose()

        _run(go())

    def test_unknown_project_is_not_duplicate(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    await _seed(s)
                    out = await api_check_source_url(
                        url="https://gitlab.example.com/group/other-repo", db=s
                    )
                    self.assertFalse(out.duplicate)
                    self.assertIsNone(out.project)
            finally:
                await engine.dispose()

        _run(go())

    def test_empty_db_is_not_duplicate(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    out = await api_check_source_url(url=PROJECT_URL, db=s)
                    self.assertFalse(out.duplicate)
                    self.assertIsNone(out.project)
            finally:
                await engine.dispose()

        _run(go())

    def test_incomplete_url_raises_400(self):
        """只有 host 没有项目路径 → 400，不要变成 500。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    with self.assertRaises(HTTPException) as ctx:
                        await api_check_source_url(
                            url="https://gitlab.example.com/", db=s
                        )
                    self.assertEqual(ctx.exception.status_code, 400)
            finally:
                await engine.dispose()

        _run(go())

    def test_url_trailing_git_is_normalized(self):
        """带 .git / 尾斜杠的写法应命中同一个项目。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    await _seed(s)
                    out = await api_check_source_url(url=PROJECT_URL + ".git", db=s)
                    self.assertTrue(out.duplicate)
                    self.assertEqual(out.normalized_url, PROJECT_URL)
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
