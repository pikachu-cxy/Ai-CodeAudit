"""Tests for scan coverage derivation."""

import json
import unittest

from app.services.scan_coverage import build_scan_coverage


def _summary(*runs: dict) -> str:
    return json.dumps(list(runs), ensure_ascii=False)


def _inventory(**kwargs):
    base = {
        "source": "semgrep_registry",
        "configs": ["p/security-audit"],
        "total_rules": 10,
        "by_subtype": {
            "sql_injection": 2,
            "xss": 2,
            "path_traversal": 1,
            "hardcoded_secret": 1,
        },
        "by_owasp": {"A01": 1, "A02": 1, "A03": 4},
        "sample_rules_by_subtype": {"sql_injection": ["x.sql"]},
        "sample_rules_by_owasp": {"A03": ["x.sql"]},
        "inventory_error": None,
        "resolved_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(kwargs)
    return base


class ScanCoverageTests(unittest.TestCase):
    def test_semgrep_ran_marks_sql_injection_checked(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": False,
            "error": None,
            "detail": {
                "configs": ["p/security-audit", "p/java"],
                "rule_inventory": _inventory(configs=["p/security-audit", "p/java"]),
            },
        }))
        self.assertTrue(cov["sast_checked"])
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "checked")
        self.assertIn("semgrep", sql["sources"])
        self.assertEqual(cov["semgrep_configs"], ["p/security-audit", "p/java"])

    def test_both_sast_failed_marks_sql_injection_not_checked(self):
        cov = build_scan_coverage(_summary(
            {
                "scanner": "semgrep",
                "findings": 0,
                "skipped": True,
                "skip_reason": "未检测到 semgrep 可执行文件",
            },
            {
                "scanner": "codeql",
                "findings": 0,
                "error": "CodeQL 未安装",
            },
        ))
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "not_checked")
        self.assertFalse(cov["sast_checked"])

    def test_gitleaks_ran_marks_secrets_checked(self):
        cov = build_scan_coverage(_summary({
            "scanner": "gitleaks",
            "findings": 3,
            "skipped": False,
            "error": None,
        }))
        secrets = next(c for c in cov["capabilities"] if c["id"] == "secrets")
        self.assertEqual(secrets["status"], "checked")
        self.assertEqual(secrets["sources"], ["gitleaks"])

    def test_sca_scanner_marks_vulnerable_dependency(self):
        cov = build_scan_coverage(_summary({
            "scanner": "pip_audit",
            "findings": 2,
            "skipped": False,
            "error": None,
        }))
        dep = next(c for c in cov["capabilities"] if c["id"] == "vulnerable_dependency")
        self.assertEqual(dep["status"], "checked")
        self.assertIn("pip_audit", dep["sources"])

    def test_enabled_but_not_run_scanner(self):
        cov = build_scan_coverage(
            _summary({
                "scanner": "semgrep",
                "findings": 1,
                "skipped": False,
                "error": None,
                "detail": {"configs": ["p/java"], "rule_inventory": _inventory()},
            }),
            enabled_scanners=["semgrep", "codeql", "gitleaks"],
        )
        by_id = {s["id"]: s for s in cov["scanners"]}
        self.assertEqual(by_id["codeql"]["status"], "not_run")
        self.assertEqual(by_id["gitleaks"]["status"], "not_run")
        self.assertEqual(by_id["semgrep"]["status"], "ran")

    def test_empty_summary(self):
        cov = build_scan_coverage(None)
        self.assertFalse(cov["sast_checked"])
        self.assertEqual(cov["semgrep_configs"], [])
        self.assertEqual(len(cov["owasp_categories"]), 10)
        a04 = next(c for c in cov["owasp_categories"] if c["id"] == "A04")
        self.assertEqual(a04["status"], "not_checked")

    def test_semgrep_ran_marks_owasp_a03_a01_checked(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": False,
            "error": None,
            "detail": {
                "configs": ["p/security-audit", "p/owasp-top-ten", "p/java"],
                "rule_inventory": _inventory(
                    configs=["p/security-audit", "p/owasp-top-ten", "p/java"],
                    by_owasp={"A01": 2, "A03": 10},
                ),
            },
        }))
        a03 = next(c for c in cov["owasp_categories"] if c["id"] == "A03")
        a01 = next(c for c in cov["owasp_categories"] if c["id"] == "A01")
        self.assertEqual(a03["status"], "checked")
        self.assertEqual(a01["status"], "checked")
        self.assertIn("semgrep", a03["sources"])

    def test_sca_only_marks_a06_not_a03(self):
        cov = build_scan_coverage(_summary({
            "scanner": "pip_audit",
            "findings": 1,
            "skipped": False,
            "error": None,
        }))
        a06 = next(c for c in cov["owasp_categories"] if c["id"] == "A06")
        a03 = next(c for c in cov["owasp_categories"] if c["id"] == "A03")
        self.assertEqual(a06["status"], "checked")
        self.assertEqual(a03["status"], "not_checked")

    def test_llm_meta_marks_focus_audited(self):
        meta = {
            "audited_focus": ["authz", "injection"],
            "status": "completed",
            "ran": True,
        }
        cov = build_scan_coverage(
            _summary({
                "scanner": "semgrep",
                "findings": 0,
                "skipped": False,
                "error": None,
                "detail": {"rule_inventory": _inventory()},
            }),
            llm_audit_meta=meta,
            configured_llm_focus=["authz", "business_logic", "injection"],
        )
        llm = cov["llm_audit"]
        self.assertTrue(llm["ran"])
        self.assertEqual(llm["status"], "completed")
        by_id = {f["id"]: f for f in llm["focus_areas"]}
        self.assertEqual(by_id["authz"]["status"], "audited")
        self.assertEqual(by_id["injection"]["status"], "audited")
        self.assertEqual(by_id["business_logic"]["status"], "skipped")

    def test_llm_not_run_configured_focus(self):
        from app.services.llm_audit_coverage import build_llm_audit_coverage

        llm = build_llm_audit_coverage(
            scan_status="completed",
            configured_focus=["authz", "business_logic"],
        )
        by_id = {f["id"]: f for f in llm["focus_areas"]}
        self.assertEqual(by_id["authz"]["status"], "configured")
        self.assertEqual(by_id["injection"]["status"], "not_run")

    def test_llm_business_logic_upgrades_a04(self):
        meta = {
            "audited_focus": ["business_logic"],
            "status": "completed",
            "ran": True,
        }
        cov = build_scan_coverage(None, llm_audit_meta=meta)
        a04 = next(c for c in cov["owasp_categories"] if c["id"] == "A04")
        self.assertEqual(a04["status"], "checked")
        self.assertIn("llm:business_logic", a04["sources"])

    def test_partial_inventory_marks_capabilities_partial(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": False,
            "error": None,
            "detail": {
                "configs": ["p/security-audit", "p/java"],
                "rule_inventory": _inventory(
                    inventory_error="p/java: fetch failed",
                    by_subtype={"sql_injection": 2},
                ),
            },
        }))
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "partial")
        self.assertIn("部分规则包未解析", sql["note"] or "")
        a03 = next(c for c in cov["owasp_categories"] if c["id"] == "A03")
        self.assertEqual(a03["status"], "partial")

    def test_compact_strips_samples_and_scanner_detail(self):
        cov = build_scan_coverage(
            _summary({
                "scanner": "semgrep",
                "findings": 1,
                "skipped": False,
                "error": None,
                "detail": {
                    "configs": ["p/java"],
                    "shards": [{"targets": ["a"]}],
                    "rule_inventory": _inventory(),
                },
            }),
            compact=True,
        )
        semgrep = next(s for s in cov["scanners"] if s["id"] == "semgrep")
        self.assertIsNone(semgrep["detail"])
        evidence = cov["semgrep_rule_evidence"]
        self.assertEqual(evidence["sample_rules_by_subtype"], {})
        self.assertEqual(evidence["sample_rules_by_owasp"], {})

    def test_error_preferred_over_skipped(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": True,
            "skip_reason": "timeout",
            "error": "killed",
        }))
        semgrep = next(s for s in cov["scanners"] if s["id"] == "semgrep")
        self.assertEqual(semgrep["status"], "failed")

    def test_deserialization_capability_emitted(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": False,
            "error": None,
            "detail": {
                "rule_inventory": _inventory(by_subtype={"deserialization": 3, "sql_injection": 1}),
            },
        }))
        deser = next(c for c in cov["capabilities"] if c["id"] == "deserialization")
        self.assertEqual(deser["status"], "checked")
        self.assertEqual(deser["rule_count"], 3)

    def test_llm_ran_without_focus_does_not_mark_all_audited(self):
        from app.services.llm_audit_coverage import build_llm_audit_coverage

        llm = build_llm_audit_coverage(
            scan_status="completed",
            llm_audit_meta={"audited_focus": [], "status": "completed", "ran": True},
            configured_focus=["authz", "injection", "business_logic"],
        )
        by_id = {f["id"]: f for f in llm["focus_areas"]}
        self.assertEqual(by_id["authz"]["status"], "skipped")
        self.assertEqual(by_id["injection"]["status"], "skipped")
        self.assertNotEqual(by_id["authz"]["status"], "audited")

    def test_semgrep_ran_without_inventory_does_not_claim_checked(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 5,
            "skipped": False,
            "error": None,
            "detail": {"configs": ["p/java"]},
        }))
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "not_checked")
        a03 = next(c for c in cov["owasp_categories"] if c["id"] == "A03")
        self.assertEqual(a03["status"], "not_checked")

    def test_ensure_rule_inventory_persisted_backfills(self):
        from unittest.mock import patch

        from app.services.scan_coverage import ensure_rule_inventory_persisted

        raw = _summary({
            "scanner": "semgrep",
            "findings": 1,
            "skipped": False,
            "error": None,
            "detail": {"configs": ["p/java"]},
        })
        fake = _inventory(source="semgrep_cli_dump", configs=["p/java"], by_subtype={"sql_injection": 4})
        with patch(
            "app.services.semgrep_rule_inventory.build_rule_inventory_summary",
            return_value=fake,
        ):
            new_raw, changed = ensure_rule_inventory_persisted(raw)
        self.assertTrue(changed)
        data = json.loads(new_raw)
        inv = data[0]["detail"]["rule_inventory"]
        self.assertTrue(str(inv["source"]).startswith("backfill:"))
        cov = build_scan_coverage(new_raw)
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "checked")


if __name__ == "__main__":
    unittest.main()
