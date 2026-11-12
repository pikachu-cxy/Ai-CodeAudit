"""扫描创建入口的 ``report_severities`` 贯通测试。

背景：给 ``POST /projects/{id}/scans/gitlab``（追加扫描版本）加了
``report_severities=body.report_severities`` 转发，却漏给 body 的 schema
``ProjectCreateGitLabScan`` 声明该字段 → 请求时 ``AttributeError``，
又被该端点里宽泛的 ``except Exception`` 包成 400「克隆失败: ...」，
看起来像克隆/环境问题，实际是代码 bug。

⚠️ **为什么必须走端点**：Pydantic v2 默认**忽略**未声明的额外字段
（这几个 schema 都没设 ``extra="forbid"``），所以
``ProjectCreateGitLabScan(report_severities=[...])`` **不会**报错，
只有真正 ``body.report_severities`` 取值时才炸。
因此光断言「能构造出 model」是抓不到这个 bug 的。
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models import Project, ScanSource, ScanStatus, ScanTask
from app.routers.projects import api_project_gitlab_scan
from app.schemas import (
    ProjectCreateGitLabScan,
    ScanCreateGitLab,
    WebhookScanRequest,
)

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
        total_findings=1,
        security_score=90,
    )
    session.add(scan)
    await session.commit()
    return project.id, scan.id


def _run(coro):
    return asyncio.run(coro)


class SchemaDeclaresReportSeveritiesTests(unittest.TestCase):
    """所有会喂给 create_gitlab_scan 的 body schema 都必须声明该字段。"""

    def test_all_scan_create_schemas_declare_report_severities(self):
        for model in (ScanCreateGitLab, ProjectCreateGitLabScan, WebhookScanRequest):
            self.assertIn(
                "report_severities",
                model.model_fields,
                f"{model.__name__} 缺少 report_severities 字段；"
                f"对应的路由若转发 body.report_severities 就会 AttributeError",
            )


class AppendScanForwardsReportSeveritiesTests(unittest.TestCase):
    def test_forwards_report_severities(self):
        """勾选了严重级别时，必须原样传给 create_gitlab_scan。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project_id, scan_id = await _seed(s)
                    scan = await s.get(ScanTask, scan_id)
                    body = ProjectCreateGitLabScan(
                        project_url=PROJECT_URL,
                        access_token="dummy-token",
                        report_severities=["HIGH", "CRITICAL"],
                    )
                    with patch(
                        "app.routers.projects.create_gitlab_scan",
                        new=AsyncMock(return_value=scan),
                    ) as mock_create:
                        await api_project_gitlab_scan(
                            project_id=project_id, body=body, db=s
                        )

                    kwargs = mock_create.await_args.kwargs
                    self.assertEqual(kwargs["report_severities"], ["HIGH", "CRITICAL"])
                    # 项目维度也要正确带上
                    self.assertEqual(kwargs["project_id"], project_id)
            finally:
                await engine.dispose()

        _run(go())

    def test_omitting_severities_forwards_none(self):
        """不勾选 → 传 None，保持全量报告的旧行为。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project_id, scan_id = await _seed(s)
                    scan = await s.get(ScanTask, scan_id)
                    body = ProjectCreateGitLabScan(
                        project_url=PROJECT_URL,
                        access_token="dummy-token",
                    )
                    with patch(
                        "app.routers.projects.create_gitlab_scan",
                        new=AsyncMock(return_value=scan),
                    ) as mock_create:
                        await api_project_gitlab_scan(
                            project_id=project_id, body=body, db=s
                        )

                    self.assertIsNone(
                        mock_create.await_args.kwargs["report_severities"]
                    )
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
