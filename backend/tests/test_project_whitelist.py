"""项目白名单（ProjectSuppression, status=whitelist）行为测试。

核心承诺：**某次扫描里把一条漏洞加白后，该项目后续扫描不再上报它。**

底层是已有的抑制引擎 —— ``_apply_project_suppressions`` 在扫描入库时按指纹匹配：
- strict 命中（tool+rule+path+message+行号分桶+owasp+subtype 全同）→ 标 review_status=false_positive
- relaxed 命中（不含行号）→ 标 ai_verdict=false_positive（软命中，UI 显示为「疑似」）

本文件覆盖加白入口、立即生效、跨扫描继承、软命中、过期失效与删除。
"""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models import (
    AiVerdict,
    Finding,
    FindingCategory,
    Project,
    ProjectSuppression,
    ReviewStatus,
    ScanEvent,
    ScanSource,
    ScanStatus,
    ScanTask,
    Severity,
)
from app.services.scan_service import (
    SUPPRESSION_STATUS_WHITELIST,
    _apply_project_suppressions,
    _canonical_suppression_fingerprint,
    _relaxed_fingerprint_for_finding,
    delete_project_suppression,
    list_project_suppressions,
    whitelist_finding,
)
from app.services.scan_diff_service import finding_fingerprint

RULE_ID = "python.lang.security.audit.dangerous-eval"
FILE_PATH = "src/service/handler.py"
MESSAGE = "Use of eval() on untrusted input"

# 扫描器/LLM 实际落库的路径常常是绝对路径（见 findings.file_path 的实测分布），
# 归一化必须把盘符与 uploads/repos 前缀都抹掉。
UPLOAD_PATH_A = r"C:\Users\tester\proj\data\uploads\run-aaa\v1\src\service\handler.py"
UPLOAD_PATH_B = r"C:\Users\tester\proj\data\uploads\run-bbb\v1\src\service\handler.py"
REPO_PATH_A = r"C:\Users\tester\proj\data\repos\aaaa11112222\src\service\handler.py"
REPO_PATH_B = r"C:\Users\tester\proj\data\repos\bbbb33334444\src\service\handler.py"


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def _new_project(session, name: str) -> Project:
    project = Project(name=name, source_type=ScanSource.GITLAB, default_branch="main")
    session.add(project)
    await session.flush()
    return project


async def _seed_scan(
    session,
    project: Project,
    *,
    name: str,
    line_start: int = 10,
    message: str = MESSAGE,
    rule_id: str = RULE_ID,
    file_path: str = FILE_PATH,
) -> tuple[ScanTask, Finding]:
    scan = ScanTask(
        project_id=project.id,
        name=name,
        source=ScanSource.GITLAB,
        status=ScanStatus.COMPLETED,
        project_path="security/demo",
        source_url="https://gitlab.example.com/group/demo",
        branch="main",
    )
    session.add(scan)
    await session.flush()

    finding = Finding(
        scan_id=scan.id,
        rule_id=rule_id,
        message=message,
        file_path=file_path,
        line_start=line_start,
        line_end=line_start + 1,
        severity=Severity.HIGH,
        tool="semgrep",
        category=FindingCategory.SAST,
    )
    session.add(finding)
    await session.commit()
    return scan, finding


def _run(coro):
    return asyncio.run(coro)


class WhitelistFindingTests(unittest.TestCase):
    def test_whitelist_requires_reason(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, finding = await _seed_scan(s, project, name="v1")
                    with self.assertRaises(ValueError):
                        await whitelist_finding(
                            s, project_id=project.id, finding_id=finding.id, reason="   "
                        )
            finally:
                await engine.dispose()

        _run(go())

    def test_whitelist_rejects_finding_from_another_project(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    p1 = await _new_project(s, "p1")
                    p2 = await _new_project(s, "p2")
                    _, finding = await _seed_scan(s, p1, name="v1")
                    with self.assertRaises(ValueError):
                        await whitelist_finding(
                            s, project_id=p2.id, finding_id=finding.id, reason="x"
                        )
            finally:
                await engine.dispose()

        _run(go())

    def test_whitelist_marks_current_finding_and_records_entry(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, finding = await _seed_scan(s, project, name="v1")

                    row = await whitelist_finding(
                        s,
                        project_id=project.id,
                        finding_id=finding.id,
                        reason="已评估为可接受风险",
                        created_by="tester",
                    )
                    self.assertEqual(row.status, SUPPRESSION_STATUS_WHITELIST)
                    self.assertEqual(row.rule_id, RULE_ID)
                    self.assertEqual(row.created_by, "tester")

                    # 当前扫描这条立刻按白名单处理，避免「加了白还在待办里」
                    await s.refresh(finding)
                    self.assertEqual(finding.review_status, ReviewStatus.FALSE_POSITIVE)
                    self.assertIn("白名单", finding.review_note or "")

                    # 事件也写进了同一个 session
                    events = (
                        await s.execute(
                            select(ScanEvent).where(ScanEvent.scan_id == finding.scan_id)
                        )
                    ).scalars().all()
                    self.assertTrue(any(e.phase == "whitelist" for e in events))
            finally:
                await engine.dispose()

        _run(go())


class WhitelistInheritanceTests(unittest.TestCase):
    def test_later_scan_suppresses_same_finding(self):
        """核心承诺：加白后，同一条漏洞在新扫描里被抑制。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, first = await _seed_scan(s, project, name="v1")
                    await whitelist_finding(
                        s,
                        project_id=project.id,
                        finding_id=first.id,
                        reason="已知风险",
                    )

                    second_scan, second = await _seed_scan(s, project, name="v2")
                    strict_hits, relaxed_hits = await _apply_project_suppressions(
                        s, second_scan
                    )
                    await s.commit()

                    self.assertEqual(strict_hits, 1)
                    self.assertEqual(relaxed_hits, 0)
                    await s.refresh(second)
                    self.assertEqual(
                        second.review_status, ReviewStatus.FALSE_POSITIVE
                    )
                    self.assertIn("白名单", second.review_note or "")
            finally:
                await engine.dispose()

        _run(go())

    def test_line_shift_within_bucket_still_matches_strictly(self):
        """行号小范围漂移（同 20 行分桶内）仍算严格命中。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, first = await _seed_scan(s, project, name="v1", line_start=10)
                    await whitelist_finding(
                        s, project_id=project.id, finding_id=first.id, reason="已知风险"
                    )

                    scan2, second = await _seed_scan(s, project, name="v2", line_start=15)
                    strict_hits, _ = await _apply_project_suppressions(s, scan2)
                    await s.commit()
                    self.assertEqual(strict_hits, 1)
                    await s.refresh(second)
                    self.assertEqual(second.review_status, ReviewStatus.FALSE_POSITIVE)
            finally:
                await engine.dispose()

        _run(go())

    def test_line_shift_across_buckets_falls_back_to_relaxed(self):
        """行号跨桶 → strict 不中，relaxed 软命中（只标 ai_verdict）。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, first = await _seed_scan(s, project, name="v1", line_start=10)
                    await whitelist_finding(
                        s, project_id=project.id, finding_id=first.id, reason="已知风险"
                    )

                    scan2, second = await _seed_scan(s, project, name="v2", line_start=200)
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()

                    self.assertEqual(strict_hits, 0)
                    self.assertEqual(relaxed_hits, 1)
                    await s.refresh(second)
                    # 软命中不改 review_status，只把 AI 判定压成误报
                    self.assertEqual(second.review_status, ReviewStatus.UNREVIEWED)
                    self.assertEqual(second.ai_verdict, AiVerdict.FALSE_POSITIVE)
                    self.assertIn("白名单", second.ai_reason or "")
            finally:
                await engine.dispose()

        _run(go())

    def test_different_rule_is_not_suppressed(self):
        """白名单只对指纹一致的漏洞生效，不能误伤同文件其他问题。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, first = await _seed_scan(s, project, name="v1")
                    await whitelist_finding(
                        s, project_id=project.id, finding_id=first.id, reason="已知风险"
                    )

                    scan2, second = await _seed_scan(
                        s, project, name="v2", rule_id="python.lang.security.audit.subprocess-shell"
                    )
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()
                    self.assertEqual((strict_hits, relaxed_hits), (0, 0))
                    await s.refresh(second)
                    self.assertEqual(second.review_status, ReviewStatus.UNREVIEWED)
                    self.assertEqual(second.ai_verdict, AiVerdict.PENDING)
            finally:
                await engine.dispose()

        _run(go())

    def test_other_project_is_unaffected(self):
        """白名单是项目级的，不能影响别的项目。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    p1 = await _new_project(s, "p1")
                    p2 = await _new_project(s, "p2")
                    _, first = await _seed_scan(s, p1, name="v1")
                    await whitelist_finding(
                        s, project_id=p1.id, finding_id=first.id, reason="已知风险"
                    )

                    scan2, second = await _seed_scan(s, p2, name="p2-v1")
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()
                    self.assertEqual((strict_hits, relaxed_hits), (0, 0))
                    await s.refresh(second)
                    self.assertEqual(second.review_status, ReviewStatus.UNREVIEWED)
            finally:
                await engine.dispose()

        _run(go())

    def test_expired_whitelist_no_longer_applies(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, first = await _seed_scan(s, project, name="v1")
                    row = await whitelist_finding(
                        s, project_id=project.id, finding_id=first.id, reason="临时豁免"
                    )
                    row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
                    await s.commit()

                    scan2, second = await _seed_scan(s, project, name="v2")
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()
                    self.assertEqual((strict_hits, relaxed_hits), (0, 0))
                    await s.refresh(second)
                    self.assertEqual(second.review_status, ReviewStatus.UNREVIEWED)
                    # 列表默认也不返回过期条目
                    self.assertEqual(await list_project_suppressions(s, project.id), [])
            finally:
                await engine.dispose()

        _run(go())


class RelaxedFingerprintPathTests(unittest.TestCase):
    """宽松指纹的路径分量必须和严指纹走同一套归一化。

    回归的缺陷：宽松指纹原来只做斜杠/大小写处理，保留了盘符和
    `data/uploads/<run>/<ver>/`、`data/repos/<hash>/` 前缀。结果是同一份代码
    换个上传批次或克隆目录就算不出同一个宽松指纹——宽松档本应比严档更宽容，
    实际却在路径维度上更严，人工确认过的误报抑制会在下次扫描时静默丢失。
    """

    @staticmethod
    def _item(file_path: str, line_start: int = 10) -> dict:
        return {
            "tool": "semgrep",
            "rule_id": RULE_ID,
            "file_path": file_path,
            "message": MESSAGE,
            "line_start": line_start,
        }

    def test_strict_and_relaxed_share_the_same_normalized_path(self):
        """两档指纹的路径分量必须逐字相同，否则宽松档不可能比严档更宽容。"""

        item = self._item(UPLOAD_PATH_A)
        strict_path = finding_fingerprint(item).split("|")[2]
        relaxed_path = _relaxed_fingerprint_for_finding(item).split("|")[2]

        self.assertEqual(strict_path, relaxed_path)
        self.assertEqual(relaxed_path, FILE_PATH)

    def test_relaxed_fingerprint_stable_across_upload_batches(self):
        """同一文件换个上传批次（run id 变了）仍算同一条。"""

        self.assertEqual(
            _relaxed_fingerprint_for_finding(self._item(UPLOAD_PATH_A)),
            _relaxed_fingerprint_for_finding(self._item(UPLOAD_PATH_B)),
        )

    def test_relaxed_fingerprint_stable_across_clone_dirs(self):
        """同一文件换次克隆（repo hash 变了）仍算同一条。"""

        self.assertEqual(
            _relaxed_fingerprint_for_finding(self._item(REPO_PATH_A)),
            _relaxed_fingerprint_for_finding(self._item(REPO_PATH_B)),
        )

    def test_relaxed_fingerprint_still_ignores_line_number(self):
        """宽松档的定义就是不看行号，修路径不能把这条性质弄丢。"""

        self.assertEqual(
            _relaxed_fingerprint_for_finding(self._item(UPLOAD_PATH_A, 10)),
            _relaxed_fingerprint_for_finding(self._item(UPLOAD_PATH_A, 900)),
        )

    def test_new_upload_batch_with_line_shift_still_suppressed(self):
        """端到端：加白后换批次重扫、行号还跨了桶，抑制依然生效。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    _, first = await _seed_scan(
                        s, project, name="v1", file_path=UPLOAD_PATH_A, line_start=10
                    )
                    await whitelist_finding(
                        s, project_id=project.id, finding_id=first.id, reason="已知风险"
                    )

                    # 新批次 run-bbb + 行号 200（跨出 20 行分桶 → 严档必然不中）
                    scan2, second = await _seed_scan(
                        s, project, name="v2", file_path=UPLOAD_PATH_B, line_start=200
                    )
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()

                    self.assertEqual(strict_hits, 0)
                    self.assertEqual(relaxed_hits, 1)
                    await s.refresh(second)
                    self.assertEqual(second.ai_verdict, AiVerdict.FALSE_POSITIVE)
            finally:
                await engine.dispose()

        _run(go())

    def test_legacy_suppression_row_still_matches_after_path_fix(self):
        """历史兼容：库里按旧口径（路径未归一化）写的条目，修复后仍然命中。

        修复前写入的 10 条抑制记录的路径分量带着盘符和前缀，如果不做读取时的
        原地归一化，修完 bug 反而会把用户标过的误报放回列表里。
        """

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    scan, finding = await _seed_scan(
                        s, project, name="v1", file_path=UPLOAD_PATH_A, line_start=10
                    )

                    # 按修复前的写法手工构造一条抑制记录：路径只做斜杠+小写。
                    legacy_path = UPLOAD_PATH_A.replace("\\", "/").strip().lower()
                    parts = _relaxed_fingerprint_for_finding(finding).split("|")
                    parts[2] = legacy_path
                    s.add(
                        ProjectSuppression(
                            project_id=project.id,
                            fingerprint_strict=(
                                "semgrep|legacy.placeholder.rule|" + legacy_path + "|x|0||"
                            ),
                            fingerprint_relaxed="|".join(parts),
                            rule_id=RULE_ID,
                            file_path=UPLOAD_PATH_A,
                            reason="历史误报",
                        )
                    )
                    await s.commit()

                    scan2, second = await _seed_scan(
                        s, project, name="v2", file_path=UPLOAD_PATH_A, line_start=200
                    )
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()

                    self.assertEqual(strict_hits, 0)
                    self.assertEqual(relaxed_hits, 1)
                    await s.refresh(second)
                    self.assertEqual(second.ai_verdict, AiVerdict.FALSE_POSITIVE)
                    self.assertIn("疑似", second.ai_reason or "")
            finally:
                await engine.dispose()

        _run(go())

    def test_legacy_strict_row_is_repaired_by_canonicalization(self):
        """旧条目连严指纹也没归一化，读取时归一化后应该恢复严命中。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    scan, finding = await _seed_scan(
                        s, project, name="v1", file_path=UPLOAD_PATH_A, line_start=10
                    )

                    # 旧口径严指纹：盘符去了、`data/uploads/<run>/<ver>/` 前缀还在。
                    legacy_path = UPLOAD_PATH_A.replace("\\", "/").strip().lower()
                    legacy_path = legacy_path[2:].lstrip("/")  # 去掉 "c:"
                    legacy_strict = "|".join(
                        [
                            "semgrep",
                            RULE_ID.lower(),
                            legacy_path,
                            MESSAGE.strip().lower(),
                            "0",
                            "",
                            "",
                        ]
                    )
                    s.add(
                        ProjectSuppression(
                            project_id=project.id,
                            fingerprint_strict=legacy_strict,
                            fingerprint_relaxed=None,
                            rule_id=RULE_ID,
                            file_path=UPLOAD_PATH_A,
                            reason="历史误报",
                        )
                    )
                    await s.commit()

                    scan2, second = await _seed_scan(
                        s, project, name="v2", file_path=UPLOAD_PATH_A, line_start=10
                    )
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan2)
                    await s.commit()

                    self.assertEqual(strict_hits, 1)
                    self.assertEqual(relaxed_hits, 0)
                    await s.refresh(second)
                    self.assertEqual(second.review_status, ReviewStatus.FALSE_POSITIVE)
            finally:
                await engine.dispose()

        _run(go())

    def test_canonicalize_helper_is_safe_on_short_input(self):
        """归一化辅助函数不能对残缺指纹抛异常或改坏它。"""

        self.assertEqual(_canonical_suppression_fingerprint(""), "")
        self.assertEqual(_canonical_suppression_fingerprint(None), "")
        self.assertEqual(_canonical_suppression_fingerprint("only|two"), "only|two")
        self.assertEqual(
            _canonical_suppression_fingerprint(
                r"a|b|C:\proj\data\repos\hhh\src\A.py|c"
            ),
            "a|b|src/a.py|c",
        )


class WhitelistManagementTests(unittest.TestCase):
    def test_list_returns_entries_for_project(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    p1 = await _new_project(s, "p1")
                    p2 = await _new_project(s, "p2")
                    _, f1 = await _seed_scan(s, p1, name="v1")
                    _, f2 = await _seed_scan(s, p2, name="v1")
                    await whitelist_finding(
                        s, project_id=p1.id, finding_id=f1.id, reason="r1"
                    )
                    await whitelist_finding(
                        s, project_id=p2.id, finding_id=f2.id, reason="r2"
                    )

                    rows = await list_project_suppressions(s, p1.id)
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0].reason, "r1")
            finally:
                await engine.dispose()

        _run(go())

    def test_delete_removes_entry_and_scoping_is_enforced(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    p1 = await _new_project(s, "p1")
                    p2 = await _new_project(s, "p2")
                    _, f1 = await _seed_scan(s, p1, name="v1")
                    row = await whitelist_finding(
                        s, project_id=p1.id, finding_id=f1.id, reason="r1"
                    )

                    # 用错项目 id 删不掉
                    self.assertFalse(
                        await delete_project_suppression(
                            s, project_id=p2.id, suppression_id=row.id
                        )
                    )
                    self.assertEqual(len(await list_project_suppressions(s, p1.id)), 1)

                    self.assertTrue(
                        await delete_project_suppression(
                            s, project_id=p1.id, suppression_id=row.id
                        )
                    )
                    self.assertEqual(await list_project_suppressions(s, p1.id), [])
                    remaining = (
                        await s.execute(select(ProjectSuppression))
                    ).scalars().all()
                    self.assertEqual(remaining, [])
            finally:
                await engine.dispose()

        _run(go())

    def test_no_whitelist_keeps_legacy_behaviour(self):
        """没有白名单时，扫描结果完全不受影响（向后兼容）。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    project = await _new_project(s, "p1")
                    scan, finding = await _seed_scan(s, project, name="v1")
                    strict_hits, relaxed_hits = await _apply_project_suppressions(s, scan)
                    self.assertEqual((strict_hits, relaxed_hits), (0, 0))
                    await s.refresh(finding)
                    self.assertEqual(finding.review_status, ReviewStatus.UNREVIEWED)
                    self.assertEqual(finding.ai_verdict, AiVerdict.PENDING)
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
