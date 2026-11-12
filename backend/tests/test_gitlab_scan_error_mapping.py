"""锁住「新建/追加 GitLab 扫描」与「复测」两个端点的异常 → HTTP 状态码映射。

背景：这两个端点原来都用 `except Exception as exc: raise HTTPException(400, ...)`
兜底，把**编程错误**伪装成了业务错误。真实事故：`ProjectCreateGitLabScan` 漏声明
`report_severities` 字段，追加扫描时抛
`AttributeError: 'ProjectCreateGitLabScan' object has no attribute 'report_severities'`，
前端只看到 `400 克隆失败: 'ProjectCreateGitLabScan' object has no attribute ...`，
排查方向被带偏到「克隆」上。

现在的约定：
- 已知业务/环境异常 → 各自合适的状态码（400 / 409）
- 其余异常（AttributeError / TypeError / KeyError …）→ **冒泡成 500**，不再吞掉

这些测试都走真实 HTTP 端点（ASGI），因为要验的正是路由里的 except 分支。
"""

from __future__ import annotations

import asyncio
import subprocess
import unittest
import warnings
from unittest.mock import AsyncMock, patch

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base, get_db
from app.dependencies.auth import require_auth
from app.exceptions import DuplicateGitUrlError, WebhookValidationError
from app.main import app
from app.models import Project, ScanSource

# 两个「编程错误必须成 500」的用例会故意让异常穿透 ASGI 栈，
# anyio 的内存流对象因此来不及关闭，GC 时抛 ResourceWarning。
# 属预期噪音，静音掉以免污染整套测试输出。
# 注意：`python -m unittest` 启动时会 simplefilter('default')，会冲掉模块级过滤器，
# 所以真正的挂载点在下面 _Base.setUp() 里。

GITLAB_SCAN_PATH = "/api/projects/{project_id}/scans/gitlab"
RETEST_PATH = "/api/scans/{scan_id}/retest"


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def _seed_project(factory) -> int:
    async with factory() as s:
        project = Project(
            name="err-map-demo",
            source_type=ScanSource.GITLAB,
            source_url="https://gitlab.example.com/group/demo.git",
            default_branch="main",
        )
        s.add(project)
        await s.commit()
        return project.id


def _run(coro):
    return asyncio.run(coro)


class _Base(unittest.TestCase):
    def setUp(self):
        self.engine = None
        # 见文件顶部说明：unittest 的 simplefilter('default') 会冲掉模块级过滤器，
        # setUp 在它之后执行，这里再挂一次才生效。
        warnings.filterwarnings("ignore", category=ResourceWarning)

    def tearDown(self):
        app.dependency_overrides.clear()

    def _client(self, factory, *, raise_app_exceptions: bool):
        async def _override_get_db():
            async with factory() as session:
                yield session

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[require_auth] = lambda: {
            "username": "tester",
            "role": "admin",
        }
        return AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions),
            base_url="http://test",
        )


class GitlabScanErrorMappingTests(_Base):
    """POST /api/projects/{id}/scans/gitlab"""

    def _body(self):
        return {
            "project_url": "https://gitlab.example.com/group/demo.git",
            "branch": "main",
            "access_token": "dummy-token-for-test",
            "name": "v1",
        }

    def test_programming_error_surfaces_as_500(self):
        """AttributeError 必须变成 500，而不是 400「克隆失败」。"""

        async def go():
            engine, factory = await _make_db()
            try:
                project_id = await _seed_project(factory)
                boom = AttributeError(
                    "'ProjectCreateGitLabScan' object has no attribute 'report_severities'"
                )
                with patch(
                    "app.routers.projects.create_gitlab_scan",
                    new=AsyncMock(side_effect=boom),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            GITLAB_SCAN_PATH.format(project_id=project_id),
                            json=self._body(),
                        )
                self.assertEqual(r.status_code, 500, r.text)
                # 关键：不能再被伪装成 400「克隆失败」
                self.assertNotIn("克隆失败", r.text)
            finally:
                await engine.dispose()

        _run(go())

    def test_clone_runtime_error_is_400(self):
        """真实的 git clone 失败抛 RuntimeError，仍应回 400。"""

        async def go():
            engine, factory = await _make_db()
            try:
                project_id = await _seed_project(factory)
                with patch(
                    "app.routers.projects.create_gitlab_scan",
                    new=AsyncMock(side_effect=RuntimeError("Git clone failed: 权限不足")),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            GITLAB_SCAN_PATH.format(project_id=project_id),
                            json=self._body(),
                        )
                self.assertEqual(r.status_code, 400, r.text)
                self.assertIn("Git clone failed", r.text)
            finally:
                await engine.dispose()

        _run(go())

    def test_clone_timeout_is_400(self):
        """subprocess 超时属环境类故障，仍应回 400 且保留「克隆失败」前缀。"""

        async def go():
            engine, factory = await _make_db()
            try:
                project_id = await _seed_project(factory)
                timeout = subprocess.TimeoutExpired(cmd="git clone", timeout=300)
                with patch(
                    "app.routers.projects.create_gitlab_scan",
                    new=AsyncMock(side_effect=timeout),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            GITLAB_SCAN_PATH.format(project_id=project_id),
                            json=self._body(),
                        )
                self.assertEqual(r.status_code, 400, r.text)
                self.assertIn("克隆失败", r.text)
            finally:
                await engine.dispose()

        _run(go())

    def test_webhook_validation_error_keeps_its_status(self):
        """token 权限不足等业务错误保留 WebhookValidationError 自带的状态码。"""

        async def go():
            engine, factory = await _make_db()
            try:
                project_id = await _seed_project(factory)
                err = WebhookValidationError("token_permission_insufficient", "令牌无效")
                with patch(
                    "app.routers.projects.create_gitlab_scan",
                    new=AsyncMock(side_effect=err),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            GITLAB_SCAN_PATH.format(project_id=project_id),
                            json=self._body(),
                        )
                self.assertEqual(r.status_code, err.http_status, r.text)
                self.assertIn("令牌无效", r.text)
            finally:
                await engine.dispose()

        _run(go())

    def test_duplicate_git_url_is_409(self):
        """并发/重复地址 → 409，而不是 400。"""

        async def go():
            engine, factory = await _make_db()
            try:
                project_id = await _seed_project(factory)
                async with factory() as s:
                    existing = await s.get(Project, project_id)
                    err = DuplicateGitUrlError(existing)
                with patch(
                    "app.routers.projects.create_gitlab_scan",
                    new=AsyncMock(side_effect=err),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            GITLAB_SCAN_PATH.format(project_id=project_id),
                            json=self._body(),
                        )
                self.assertEqual(r.status_code, 409, r.text)
            finally:
                await engine.dispose()

        _run(go())


class RetestErrorMappingTests(_Base):
    """POST /api/scans/{id}/retest —— 复测支持自选分支后，branch_not_found 会真实发生。"""

    def test_branch_not_found_keeps_message_and_contract_status(self):
        """branch_not_found 走 WebhookValidationError 的既定契约表（→ 405）。

        这个映射表是给 Jenkins webhook 用的、带编号的对外契约
        （app/exceptions.py: WEBHOOK_VALIDATION_ERROR_HTTP），复测端点沿用
        `exc.http_status` 而不是自作主张改码，避免和 webhook 侧不一致。
        重点是**消息要原样透出**，不能被泛化成「复测创建失败」。
        """

        async def go():
            engine, factory = await _make_db()
            try:
                err = WebhookValidationError(
                    "branch_not_found", "远程分支不存在：test"
                )
                with patch(
                    "app.routers.projects.create_retest_scan",
                    new=AsyncMock(side_effect=err),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            RETEST_PATH.format(scan_id=1),
                            json={"branch": "test", "strategy": "targeted"},
                        )
                self.assertEqual(r.status_code, err.http_status, r.text)
                # 必须原样透出「远程分支不存在」，不能被泛化成「复测创建失败」
                self.assertIn("远程分支不存在", r.text)
                self.assertNotIn("复测创建失败", r.text)
            finally:
                await engine.dispose()

        _run(go())

    def test_programming_error_surfaces_as_500(self):
        async def go():
            engine, factory = await _make_db()
            try:
                with patch(
                    "app.routers.projects.create_retest_scan",
                    new=AsyncMock(side_effect=KeyError("unexpected_key")),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            RETEST_PATH.format(scan_id=1),
                            json={"branch": "main", "strategy": "targeted"},
                        )
                self.assertEqual(r.status_code, 500, r.text)
                self.assertNotIn("复测创建失败", r.text)
            finally:
                await engine.dispose()

        _run(go())

    def test_value_error_still_400(self):
        """原有业务分支不受影响：upload 型项目的专用提示。"""

        async def go():
            engine, factory = await _make_db()
            try:
                with patch(
                    "app.routers.projects.create_retest_scan",
                    new=AsyncMock(
                        side_effect=ValueError("upload_retest_requires_new_archive")
                    ),
                ):
                    async with self._client(
                        factory, raise_app_exceptions=False
                    ) as c:
                        r = await c.post(
                            RETEST_PATH.format(scan_id=1),
                            json={"strategy": "targeted"},
                        )
                self.assertEqual(r.status_code, 400, r.text)
                self.assertIn("重新上传新版本代码", r.text)
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
