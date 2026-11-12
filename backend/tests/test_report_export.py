from __future__ import annotations

import json
import unittest

from app.services.report_service import _build_markdown_report, _render_pdf_html


def _sample_payload() -> dict:
    return {
        "meta": {
            "project_name": "demo-project",
            "scan_id": 42,
            "scan_name": "nightly",
            "branch": "master",
            "version": "v1.2.3",
            "created_at": "2026-08-19 12:00:00",
            "completed_at": "2026-08-19 12:10:00",
            "online_url": "http://localhost:5173/?scanId=42",
            "tools": ["semgrep", "llm"],
        },
        "stats": {
            "total": 1,
            "by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_owasp": {"A03": 1},
            "by_tool": {"semgrep": 1},
        },
        "findings": [
            {
                "id": 7,
                "severity": "CRITICAL",
                "category": "sast",
                "source": "sast",
                "tool": "semgrep",
                "rule_id": "java.sql.injection",
                "title": "SQL 注入风险",
                "message": "拼接 SQL 未参数化",
                "file_path": "src/main/UserController.java",
                "line_start": 88,
                "snippet": "String sql = \"select * from users where id=\" + id;",
                "ai_verdict": "real_vuln",
                "ai_reason": "外部输入拼接到 SQL 字符串",
                "ai_confidence": 0.97,
                "review_status": "confirmed",
                "review_note": "需改预编译参数",
                "owasp_id": "A03",
                "owasp_name": "注入",
            }
        ],
    }


class ReportExportTests(unittest.TestCase):
    def test_markdown_report_contains_ai_friendly_fields(self):
        md = _build_markdown_report(_sample_payload())
        self.assertIn("# 安全审计报告：demo-project", md)
        self.assertIn("扫描 ID：42", md)
        self.assertIn("SQL 注入风险", md)
        self.assertIn("src/main/UserController.java:88", md)
        self.assertIn("```", md)
        self.assertNotIn("<table>", md)

    def test_pdf_template_render_contains_expected_sections(self):
        html = _render_pdf_html(_sample_payload())
        self.assertIn("demo-project", html)
        self.assertIn("漏洞汇总", html)
        self.assertIn("漏洞详情", html)
        self.assertIn("#7 SQL 注入风险", html)

    def test_pdf_generation_magic_bytes_when_weasyprint_available(self):
        from app.services.report_service import _load_weasyprint

        available, loaded = _load_weasyprint()
        if not available:
            self.skipTest("WeasyPrint not installed in local test env")
            return
        html = _render_pdf_html(_sample_payload())
        pdf = loaded(string=html).write_pdf()
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 1024)

    def test_json_structure_stable(self):
        payload = _sample_payload()
        blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        parsed = json.loads(blob.decode("utf-8"))
        self.assertIn("meta", parsed)
        self.assertIn("stats", parsed)
        self.assertIn("findings", parsed)
        self.assertEqual(parsed["findings"][0]["rule_id"], "java.sql.injection")


if __name__ == "__main__":
    unittest.main()
