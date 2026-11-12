"""Unit tests for custom report scope: filtering, stats recompute, content switches."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from app.models import (
    AiVerdict,
    ExternalReviewStatus,
    FindingCategory,
    ReviewStatus,
    Severity,
)
from app.schemas import ReportFilters, ReportInclude, ReportSpec
from app.services.report_service import (
    _build_markdown_report,
    _finding_payload,
    _group_findings,
    _include_flags,
    _match_filters,
    _report_filename,
    _resolve_scope,
    _scope_slug,
    _sort_findings,
    _stats_from_findings,
)


def _finding(
    *,
    fid: int,
    severity=Severity.MEDIUM,
    category=FindingCategory.SAST,
    tool: str = "semgrep",
    rule_id: str = "rule.x",
    message: str = "问题描述",
    file_path: str = "src/a.py",
    line_start: int = 10,
    owasp_id: str | None = "A03",
    subtype: str | None = "sql_injection",
    ai_verdict=AiVerdict.PENDING,
    review_status=ReviewStatus.UNREVIEWED,
    external_status=ExternalReviewStatus.UNREVIEWED,
    metadata_json: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=fid,
        severity=severity,
        category=category,
        tool=tool,
        rule_id=rule_id,
        message=message,
        message_zh=None,
        file_path=file_path,
        line_start=line_start,
        code_snippet="line1\nline2",
        metadata_json=metadata_json,
        ai_verdict=ai_verdict,
        ai_reason="AI 理由",
        ai_confidence=0.9,
        review_status=review_status,
        review_note="",
        external_status=external_status,
        external_note="",
        owasp_id=owasp_id,
        owasp_name="注入",
        vuln_subtype=subtype,
        vuln_subtype_name="SQL 注入",
    )


def _scan() -> SimpleNamespace:
    return SimpleNamespace(project_path=None)


class ReportScopeTests(unittest.TestCase):
    def test_resolve_scope_prefers_finding_ids(self):
        spec = ReportSpec(finding_ids=[1, 2], filters=ReportFilters(severity=["HIGH"]))
        self.assertEqual(_resolve_scope(spec), "selected")
        self.assertEqual(_resolve_scope(ReportSpec(filters=ReportFilters(severity=["HIGH"]))), "filtered")
        self.assertEqual(_resolve_scope(ReportSpec()), "all")
        self.assertEqual(_resolve_scope(None), "all")

    def test_scope_slug_distinguishes_export_variants(self):
        self.assertEqual(_scope_slug("all", 120), "all")
        self.assertEqual(_scope_slug("selected", 3), "selected-3")
        self.assertEqual(_scope_slug("filtered", 12), "filtered-12")

    def test_filename_includes_scope_and_timestamp(self):
        payload = {
            "meta": {"project_name": "demo", "scope": "selected"},
            "stats": {"total": 3},
        }
        name = _report_filename(payload, 42, "pdf")
        self.assertTrue(name.startswith("demo-selected-3-scan-42-"))
        self.assertTrue(name.endswith(".pdf"))

    def test_stats_recompute_matches_findings_count(self):
        payload = [
            {"severity": "CRITICAL", "ai_verdict": "real_vuln", "tool": "semgrep",
             "category": "sast", "review_status": "confirmed", "owasp_id": "A03",
             "vuln_subtype": "sql_injection", "rule_id": "r1"},
            {"severity": "HIGH", "ai_verdict": "pending", "tool": "semgrep",
             "category": "sast", "review_status": "unreviewed", "owasp_id": "A03",
             "vuln_subtype": "sql_injection", "rule_id": "r1"},
            {"severity": "LOW", "ai_verdict": "pending", "tool": "llm",
             "category": "business_logic", "review_status": "unreviewed", "owasp_id": "OTHER",
             "vuln_subtype": "other", "rule_id": "r2"},
        ]
        stats = _stats_from_findings(payload)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["by_severity"]["CRITICAL"], 1)
        self.assertEqual(stats["by_severity"]["HIGH"], 1)
        self.assertEqual(stats["by_tool"]["semgrep"], 2)
        # llm 聚合分类 = business_logic + authorization
        self.assertEqual(stats["by_category"]["llm"], 1)
        self.assertEqual(stats["top_rules"][0], {"rule_id": "r1", "count": 2})

    def test_stats_total_always_equals_detail_count(self):
        for count in (0, 1, 7):
            payload = [{"severity": "LOW"} for _ in range(count)]
            self.assertEqual(_stats_from_findings(payload)["total"], len(payload))


class ReportFilterTests(unittest.TestCase):
    def test_severity_filter_is_case_insensitive(self):
        f = _finding(fid=1, severity=Severity.CRITICAL)
        self.assertTrue(_match_filters(f, ReportFilters(severity=["critical"])))
        self.assertFalse(_match_filters(f, ReportFilters(severity=["HIGH"])))

    def test_owasp_and_source_filters(self):
        f = _finding(fid=1, owasp_id="A03")
        self.assertTrue(_match_filters(f, ReportFilters(owasp=["a03"])))
        self.assertFalse(_match_filters(f, ReportFilters(owasp=["A01"])))
        self.assertTrue(_match_filters(f, ReportFilters(source=["sast"])))
        self.assertFalse(_match_filters(f, ReportFilters(source=["llm"])))

    def test_llm_category_aggregates_business_logic_and_authorization(self):
        biz = _finding(fid=1, category=FindingCategory.BUSINESS_LOGIC, tool="llm")
        authz = _finding(fid=2, category=FindingCategory.AUTHORIZATION, tool="llm")
        sast = _finding(fid=3, category=FindingCategory.SAST)
        self.assertTrue(_match_filters(biz, ReportFilters(category=["llm"])))
        self.assertTrue(_match_filters(authz, ReportFilters(category=["llm"])))
        self.assertFalse(_match_filters(sast, ReportFilters(category=["llm"])))

    def test_keyword_matches_rule_path_and_id(self):
        f = _finding(fid=77, rule_id="java.sql.injection", file_path="src/User.java")
        self.assertTrue(_match_filters(f, ReportFilters(keyword="sql.injection")))
        self.assertTrue(_match_filters(f, ReportFilters(keyword="src/User")))
        self.assertTrue(_match_filters(f, ReportFilters(keyword="77")))
        self.assertFalse(_match_filters(f, ReportFilters(keyword="不存在的关键词")))

    def test_combined_filters_are_intersected(self):
        f = _finding(fid=1, severity=Severity.HIGH, tool="semgrep")
        self.assertTrue(
            _match_filters(f, ReportFilters(severity=["HIGH"], tool=["semgrep"], source=["sast"]))
        )
        self.assertFalse(
            _match_filters(f, ReportFilters(severity=["HIGH"], tool=["codeql"]))
        )

    def test_empty_filters_match_everything(self):
        f = _finding(fid=1)
        self.assertTrue(_match_filters(f, ReportFilters()))
        self.assertTrue(_match_filters(f, None))


class ReportSortTests(unittest.TestCase):
    def test_severity_sort_is_ranked_not_alphabetical(self):
        findings = [
            _finding(fid=1, severity=Severity.UNKNOWN),
            _finding(fid=2, severity=Severity.CRITICAL),
            _finding(fid=3, severity=Severity.LOW),
            _finding(fid=4, severity=Severity.HIGH),
            _finding(fid=5, severity=Severity.MEDIUM),
        ]
        ordered = [f.id for f in _sort_findings(findings, "severity")]
        self.assertEqual(ordered, [2, 4, 5, 3, 1])

    def test_file_sort_groups_by_path_then_line(self):
        findings = [
            _finding(fid=1, file_path="src/b.py", line_start=5),
            _finding(fid=2, file_path="src/a.py", line_start=90),
            _finding(fid=3, file_path="src/a.py", line_start=10),
        ]
        self.assertEqual([f.id for f in _sort_findings(findings, "file")], [3, 2, 1])

    def test_id_sort_is_stable(self):
        findings = [_finding(fid=9), _finding(fid=2), _finding(fid=5)]
        self.assertEqual([f.id for f in _sort_findings(findings, "id")], [2, 5, 9])


class ReportGroupTests(unittest.TestCase):
    def test_group_by_severity_follows_severity_rank(self):
        findings = [
            {"id": 1, "severity": "LOW"},
            {"id": 2, "severity": "CRITICAL"},
            {"id": 3, "severity": "LOW"},
        ]
        groups = _group_findings(findings, "severity")
        self.assertEqual([label for label, _ in groups], ["CRITICAL", "LOW"])
        self.assertEqual(len(groups[1][1]), 2)

    def test_group_by_none_returns_single_bucket(self):
        findings = [{"id": 1, "severity": "LOW"}]
        groups = _group_findings(findings, "none")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "")

    def test_empty_findings_produce_no_groups(self):
        self.assertEqual(_group_findings([], "severity"), [])


class ReportIncludeTests(unittest.TestCase):
    def test_defaults_match_legacy_report(self):
        flags = _include_flags(None)
        self.assertTrue(flags["snippet"])
        self.assertTrue(flags["ai_reason"])
        self.assertTrue(flags["false_positive"])
        self.assertFalse(flags["poc"])

    def test_include_switches_gate_payload_fields(self):
        poc = {"poc_type": "curl", "title": "PoC", "poc_content": "curl {BASE_URL}"}
        meta = json.dumps({"verification_poc": poc, "recommendation": "改用参数化查询"})
        finding = _finding(fid=1, metadata_json=meta)

        off = _include_flags(ReportSpec(include=ReportInclude(snippet=False, ai_reason=False, poc=False, remediation=False)))
        payload_off = _finding_payload(finding, _scan(), off)
        self.assertEqual(payload_off["snippet"], "")
        self.assertEqual(payload_off["ai_reason"], "")
        self.assertNotIn("poc", payload_off)
        self.assertNotIn("remediation", payload_off)

        on = _include_flags(ReportSpec(include=ReportInclude(snippet=True, ai_reason=True, poc=True, remediation=True)))
        payload_on = _finding_payload(finding, _scan(), on)
        self.assertTrue(payload_on["snippet"])
        self.assertEqual(payload_on["ai_reason"], "AI 理由")
        self.assertEqual(payload_on["poc"]["poc_type"], "curl")
        self.assertEqual(payload_on["remediation"], "改用参数化查询")

    def test_retest_is_attached_when_provided(self):
        flags = _include_flags(ReportSpec())
        retest = {"verdict": "fixed", "method": "pattern", "created_at": "2026-09-01 10:00:00"}
        payload = _finding_payload(_finding(fid=1), _scan(), flags, retest)
        self.assertEqual(payload["retest"]["verdict"], "fixed")

    def test_payload_carries_external_status_and_subtype(self):
        flags = _include_flags(ReportSpec())
        payload = _finding_payload(
            _finding(fid=1, external_status=ExternalReviewStatus.VULN_EXISTS), _scan(), flags
        )
        self.assertEqual(payload["external_status"], "vuln_exists")
        self.assertEqual(payload["vuln_subtype"], "sql_injection")


class ReportMarkdownTests(unittest.TestCase):
    def _payload(self, group_by: str = "severity") -> dict:
        return {
            "meta": {
                "title": "自定义报告",
                "scan_id": 42,
                "scope_label": "自定义勾选（1 条）",
                "generated_at": "2026-09-18 02:00:00 UTC",
                "group_by": group_by,
                "online_url": "http://localhost:5173/?scanId=42",
            },
            "stats": {"total": 1, "by_severity": {"HIGH": 1}, "by_owasp": {"A03": 1}, "by_tool": {"semgrep": 1}},
            "findings": [
                {
                    "id": 7,
                    "severity": "HIGH",
                    "source": "sast",
                    "tool": "semgrep",
                    "rule_id": "java.sql.injection",
                    "title": "SQL 注入",
                    "message": "拼接 SQL",
                    "file_path": "src/User.java",
                    "line_start": 88,
                    "snippet": "select * from users",
                    "ai_verdict": "real_vuln",
                    "ai_reason": "外部输入拼接",
                    "review_status": "confirmed",
                    "external_status": "vuln_exists",
                    "vuln_subtype": "sql_injection",
                    "vuln_subtype_name": "SQL 注入",
                    "remediation": "改用参数化查询",
                    "retest": {"verdict": "still_present", "method": "pattern", "created_at": "2026-09-10 09:00:00"},
                    "poc": {"title": "SQLi PoC", "poc_type": "curl", "poc_content": "curl {BASE_URL}", "safety_note": "仅授权环境"},
                }
            ],
        }

    def test_markdown_renders_new_sections(self):
        md = _build_markdown_report(self._payload(group_by="none"))
        self.assertIn("# 自定义报告", md)
        self.assertIn("报告范围：自定义勾选（1 条）", md)
        self.assertIn("**修复建议**", md)
        self.assertIn("改用参数化查询", md)
        self.assertIn("复测结论：仍然存在", md)
        self.assertIn("**验证 PoC**", md)
        self.assertIn("curl {BASE_URL}", md)
        self.assertIn("漏洞子类型：SQL 注入", md)

    def test_markdown_renders_group_heading(self):
        md = _build_markdown_report(self._payload(group_by="severity"))
        self.assertIn("### 分组：HIGH（1 条）", md)

    def test_markdown_falls_back_to_legacy_title(self):
        payload = self._payload(group_by="none")
        payload["meta"].pop("title")
        payload["meta"]["project_name"] = "demo-project"
        md = _build_markdown_report(payload)
        self.assertIn("# 安全审计报告：demo-project", md)


if __name__ == "__main__":
    unittest.main()
