"""Integration tests for custom report scope against a real (in-memory) database.

覆盖最关键的两条约束：
1. 报告头部统计必须等于明细条数（筛选/勾选后仍成立）
2. finding_ids 必须校验归属，不能跨扫描读取
"""

from __future__ import annotations

import asyncio
import unittest

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models import (
    AiVerdict,
    Finding,
    FindingCategory,
    Project,
    ReviewStatus,
    ScanSource,
    ScanStatus,
    ScanTask,
    Severity,
)
from app.schemas import ReportFilters, ReportInclude, ReportSpec
from app.services.report_service import build_scan_report_payload


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def _seed(session) -> tuple[int, int]:
    project = Project(name="demo-project")
    session.add(project)
    await session.flush()

    scan = ScanTask(
        project_id=project.id,
        name="nightly",
        source=ScanSource.UPLOAD,
        status=ScanStatus.COMPLETED,
        project_path="",
        branch="master",
        total_findings=5,
        security_score=72,
    )
    other_scan = ScanTask(
        project_id=project.id,
        name="other",
        source=ScanSource.UPLOAD,
        status=ScanStatus.COMPLETED,
        project_path="",
    )
    session.add_all([scan, other_scan])
    await session.flush()

    rows = [
        dict(severity=Severity.CRITICAL, owasp_id="A03", ai_verdict=AiVerdict.REAL_VULN,
             review_status=ReviewStatus.CONFIRMED, tool="semgrep"),
        dict(severity=Severity.HIGH, owasp_id="A03", ai_verdict=AiVerdict.PENDING,
             review_status=ReviewStatus.UNREVIEWED, tool="semgrep"),
        dict(severity=Severity.MEDIUM, owasp_id="A01", ai_verdict=AiVerdict.FALSE_POSITIVE,
             review_status=ReviewStatus.FALSE_POSITIVE, tool="semgrep"),
        dict(severity=Severity.LOW, owasp_id="OTHER", ai_verdict=AiVerdict.PENDING,
             review_status=ReviewStatus.UNREVIEWED, tool="llm",
             category=FindingCategory.BUSINESS_LOGIC),
        dict(severity=Severity.HIGH, owasp_id="A07", ai_verdict=AiVerdict.UNCERTAIN,
             review_status=ReviewStatus.UNREVIEWED, tool="codeql"),
    ]
    for i, extra in enumerate(rows):
        session.add(
            Finding(
                scan_id=scan.id,
                rule_id=f"rule.{i}",
                message=f"问题 {i}",
                file_path=f"src/f{i}.py",
                line_start=10 + i,
                category=extra.pop("category", FindingCategory.SAST),
                **extra,
            )
        )
    # 属于另一个扫描的漏洞，用于越权校验
    session.add(
        Finding(
            scan_id=other_scan.id,
            rule_id="rule.other",
            message="其他扫描的问题",
            file_path="src/other.py",
            line_start=1,
            category=FindingCategory.SAST,
            severity=Severity.HIGH,
            tool="semgrep",
        )
    )
    await session.commit()
    return scan.id, other_scan.id


def _run(coro):
    return asyncio.run(coro)


class ReportPayloadIntegrationTests(unittest.TestCase):
    def test_full_scope_matches_legacy_behaviour(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as session:
                    scan_id, _ = await _seed(session)
                    payload = await build_scan_report_payload(session, scan_id, None)
                    self.assertEqual(payload["stats"]["total"], 5)
                    self.assertEqual(len(payload["findings"]), 5)
                    self.assertEqual(payload["meta"]["scope"], "all")
                    # 全量时保留扫描安全分
                    self.assertEqual(payload["stats"]["security_score"], 72)
                    # 默认按危害级别排序，Critical 在最前
                    self.assertEqual(payload["findings"][0]["severity"], "CRITICAL")
            finally:
                await engine.dispose()

        _run(go())

    def test_selected_ids_scope_and_stats_consistency(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as session:
                    scan_id, _ = await _seed(session)
                    payload = await build_scan_report_payload(session, scan_id, None)
                    ids = [f["id"] for f in payload["findings"]]
                    picked = ids[:2]

                    spec = ReportSpec(finding_ids=picked)
                    scoped = await build_scan_report_payload(session, scan_id, spec)

                    self.assertEqual(scoped["meta"]["scope"], "selected")
                    self.assertEqual(len(scoped["findings"]), 2)
                    # 关键约束：头部统计 == 明细条数
                    self.assertEqual(scoped["stats"]["total"], 2)
                    self.assertEqual(sum(scoped["stats"]["by_severity"].values()), 2)
                    self.assertEqual({f["id"] for f in scoped["findings"]}, set(picked))
                    # 子集不应沿用整次扫描的安全分
                    self.assertIsNone(scoped["stats"]["security_score"])
            finally:
                await engine.dispose()

        _run(go())

    def test_finding_ids_from_other_scan_are_rejected(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as session:
                    scan_id, other_scan_id = await _seed(session)
                    foreign = (
                        await session.execute(
                            Finding.__table__.select().where(Finding.scan_id == other_scan_id)
                        )
                    ).first()
                    with self.assertRaises(ValueError) as ctx:
                        await build_scan_report_payload(
                            session, scan_id, ReportSpec(finding_ids=[foreign.id])
                        )
                    self.assertIn("不属于本次扫描", str(ctx.exception))
            finally:
                await engine.dispose()

        _run(go())

    def test_filter_scope_narrows_and_recomputes_stats(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as session:
                    scan_id, _ = await _seed(session)
                    spec = ReportSpec(filters=ReportFilters(severity=["HIGH"]))
                    payload = await build_scan_report_payload(session, scan_id, spec)

                    self.assertEqual(payload["meta"]["scope"], "filtered")
                    self.assertEqual(payload["stats"]["total"], 2)
                    self.assertTrue(all(f["severity"] == "HIGH" for f in payload["findings"]))
                    self.assertEqual(payload["stats"]["by_severity"], {"HIGH": 2})
                    self.assertEqual(sum(payload["stats"]["by_tool"].values()), 2)
            finally:
                await engine.dispose()

        _run(go())

    def test_false_positive_toggle_removes_entries(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as session:
                    scan_id, _ = await _seed(session)

                    keep = await build_scan_report_payload(
                        session, scan_id, ReportSpec(include=ReportInclude(false_positive=True))
                    )
                    drop = await build_scan_report_payload(
                        session, scan_id, ReportSpec(include=ReportInclude(false_positive=False))
                    )

                    self.assertEqual(keep["stats"]["total"], 5)
                    self.assertEqual(drop["stats"]["total"], 4)
                    self.assertNotIn(
                        "false_positive", [f["review_status"] for f in drop["findings"]]
                    )
                    self.assertEqual(drop["stats"]["by_review"].get("false_positive"), None)
            finally:
                await engine.dispose()

        _run(go())

    def test_selected_ids_are_sorted_by_severity(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as session:
                    scan_id, _ = await _seed(session)
                    base = await build_scan_report_payload(session, scan_id, None)
                    # 故意倒序传入
                    reversed_ids = [f["id"] for f in reversed(base["findings"])]
                    payload = await build_scan_report_payload(
                        session, scan_id, ReportSpec(finding_ids=reversed_ids)
                    )
                    severities = [f["severity"] for f in payload["findings"]]
                    self.assertEqual(severities[0], "CRITICAL")
                    self.assertEqual(severities[-1], "LOW")
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
