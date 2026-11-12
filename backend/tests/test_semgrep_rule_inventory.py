"""Tests for Semgrep rule inventory (实锤) and coverage gating."""

import json
import unittest
from unittest.mock import patch

from app.services.scan_coverage import build_scan_coverage
from app.services.semgrep_rule_inventory import (
    build_rule_inventory_summary,
    format_inventory_log_line,
    languages_from_configs,
    languages_from_source_counts,
    parse_rules_yaml,
    rule_matches_project_languages,
)


SAMPLE_YAML = """
rules:
  - id: java.lang.security.audit.sqli.jdbc-sqli
    message: Possible SQL injection
    severity: ERROR
    languages: [java]
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
    pattern: $X
  - id: javascript.browser.security.xss.raw-html
    message: XSS
    severity: WARNING
    languages: [javascript]
    metadata:
      cwe: ["CWE-79"]
      owasp: ["A03:2021 - Injection"]
    pattern: $Y
  - id: generic.secrets.security.detected-generic-api-key
    message: Hardcoded secret
    severity: ERROR
    languages: [generic]
    metadata:
      cwe: ["CWE-798"]
      owasp: ["A02:2021 - Cryptographic Failures"]
    pattern: $Z
"""

MIXED_LANG_YAML = """
rules:
  - id: java.lang.security.audit.sqli.jdbc-sqli
    message: Possible SQL injection
    severity: ERROR
    languages: [java]
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
    pattern: $X
  - id: go.lang.security.audit.sqli
    message: Go SQL injection
    severity: ERROR
    languages: [go]
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
    pattern: $G
  - id: ruby.lang.security.audit.xss
    message: Ruby XSS
    severity: WARNING
    languages: [ruby]
    metadata:
      cwe: ["CWE-79"]
      owasp: ["A03:2021 - Injection"]
    pattern: $R
  - id: generic.secrets.security.detected-generic-api-key
    message: Hardcoded secret
    severity: ERROR
    languages: [generic]
    metadata:
      cwe: ["CWE-798"]
      owasp: ["A02:2021 - Cryptographic Failures"]
    pattern: $Z
  - id: multi.lang.no-language-tag
    message: Universal pattern
    severity: INFO
    metadata:
      cwe: ["CWE-200"]
    pattern: $U
"""


def _summary(*runs: dict) -> str:
    return json.dumps(list(runs), ensure_ascii=False)


class ParseRulesYamlTests(unittest.TestCase):
    def test_parse_maps_cwe_to_subtype(self):
        rules = parse_rules_yaml(SAMPLE_YAML, config="p/test")
        by_id = {r["id"]: r for r in rules}
        self.assertEqual(by_id["java.lang.security.audit.sqli.jdbc-sqli"]["subtype"], "sql_injection")
        self.assertIn("A03", by_id["java.lang.security.audit.sqli.jdbc-sqli"]["owasp"])
        self.assertEqual(by_id["javascript.browser.security.xss.raw-html"]["subtype"], "xss")
        self.assertEqual(
            by_id["generic.secrets.security.detected-generic-api-key"]["subtype"],
            "hardcoded_secret",
        )


class LanguageFilterTests(unittest.TestCase):
    def test_languages_from_source_counts(self):
        langs = languages_from_source_counts({"p/java": 120, "p/golang": 0})
        self.assertEqual(langs, {"java", "kotlin"})

    def test_languages_from_configs_ignores_security_packs(self):
        langs = languages_from_configs(["p/security-audit", "p/owasp-top-ten", "p/java"])
        self.assertEqual(langs, {"java", "kotlin"})

    def test_rule_matches_keeps_generic_and_empty(self):
        self.assertTrue(
            rule_matches_project_languages({"languages": ["generic"]}, {"java"})
        )
        self.assertTrue(rule_matches_project_languages({"languages": []}, {"java"}))
        self.assertFalse(
            rule_matches_project_languages({"languages": ["go"]}, {"java"})
        )
        self.assertTrue(
            rule_matches_project_languages({"languages": ["java"]}, {"java"})
        )

    def test_build_summary_filters_go_ruby_for_java_project(self):
        mixed = parse_rules_yaml(MIXED_LANG_YAML, config="p/security-audit")

        def fake_resolve(config: str):
            return list(mixed), None

        with patch(
            "app.services.semgrep_rule_inventory.resolve_config_rules",
            side_effect=fake_resolve,
        ):
            inv = build_rule_inventory_summary(
                ["p/security-audit", "p/java"],
                project_languages={"java"},
            )

        self.assertTrue(inv["filtered"])
        self.assertEqual(inv["project_languages"], ["java"])
        self.assertEqual(inv["unfiltered_total_rules"], 5)
        self.assertEqual(inv["total_rules"], 3)  # java + generic + empty langs
        samples = []
        for ids in (inv.get("sample_rules_by_subtype") or {}).values():
            samples.extend(ids)
        for ids in (inv.get("sample_rules_by_owasp") or {}).values():
            samples.extend(ids)
        joined = " ".join(samples)
        self.assertIn("java.lang.security.audit.sqli.jdbc-sqli", joined)
        self.assertNotIn("go.lang.security.audit.sqli", joined)
        self.assertNotIn("ruby.lang.security.audit.xss", joined)
        self.assertIn("generic.secrets.security.detected-generic-api-key", joined)

    def test_build_summary_without_languages_keeps_all(self):
        mixed = parse_rules_yaml(MIXED_LANG_YAML, config="p/security-audit")

        def fake_resolve(config: str):
            return list(mixed), None

        with patch(
            "app.services.semgrep_rule_inventory.resolve_config_rules",
            side_effect=fake_resolve,
        ):
            inv = build_rule_inventory_summary(["p/security-audit"])

        self.assertFalse(inv["filtered"])
        self.assertEqual(inv["total_rules"], 5)
        self.assertEqual(inv["unfiltered_total_rules"], 5)


class CoverageWithInventoryTests(unittest.TestCase):
    def test_inventory_marks_sql_checked(self):
        inv = {
            "source": "semgrep_registry",
            "configs": ["p/security-audit"],
            "total_rules": 3,
            "by_subtype": {"sql_injection": 1, "xss": 1},
            "by_owasp": {"A03": 2, "A02": 1},
            "sample_rules_by_subtype": {
                "sql_injection": ["java.lang.security.audit.sqli.jdbc-sqli"],
            },
            "sample_rules_by_owasp": {"A03": ["java.lang.security.audit.sqli.jdbc-sqli"]},
            "inventory_error": None,
            "resolved_at": "2026-01-01T00:00:00+00:00",
            "filtered": True,
            "project_languages": ["java"],
            "unfiltered_total_rules": 80,
        }
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": False,
            "error": None,
            "detail": {"configs": ["p/security-audit"], "rule_inventory": inv},
        }))
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "checked")
        self.assertEqual(sql["rule_count"], 1)
        a03 = next(c for c in cov["owasp_categories"] if c["id"] == "A03")
        self.assertEqual(a03["status"], "checked")
        self.assertEqual(a03["rule_count"], 2)
        evidence = cov["semgrep_rule_evidence"]
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["total_rules"], 3)
        self.assertTrue(evidence["filtered"])
        self.assertEqual(evidence["unfiltered_total_rules"], 80)

    def test_semgrep_ran_without_inventory_not_checked(self):
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "skipped": False,
            "error": None,
            "detail": {"configs": ["p/security-audit"]},
        }))
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "not_checked")
        self.assertIn("规则清单", sql["note"] or "")

    def test_inventory_zero_subtype_not_checked(self):
        inv = {
            "source": "semgrep_registry",
            "configs": ["p/python"],
            "total_rules": 5,
            "by_subtype": {"weak_crypto": 5},
            "by_owasp": {"A02": 5},
            "sample_rules_by_subtype": {},
            "sample_rules_by_owasp": {},
            "inventory_error": None,
        }
        cov = build_scan_coverage(_summary({
            "scanner": "semgrep",
            "findings": 0,
            "detail": {"configs": ["p/python"], "rule_inventory": inv},
        }))
        sql = next(c for c in cov["capabilities"] if c["id"] == "sql_injection")
        self.assertEqual(sql["status"], "not_checked")
        self.assertEqual(sql["rule_count"], 0)

    def test_build_summary_from_parsed_rules(self):
        rules = parse_rules_yaml(SAMPLE_YAML, config="p/test")
        by_subtype: dict[str, int] = {}
        for r in rules:
            by_subtype[r["subtype"]] = by_subtype.get(r["subtype"], 0) + 1
        self.assertGreaterEqual(by_subtype.get("sql_injection", 0), 1)

    def test_format_log_line(self):
        line = format_inventory_log_line({
            "total_rules": 10,
            "by_subtype": {"sql_injection": 3, "xss": 2},
            "source": "semgrep_registry",
        })
        self.assertIn("共 10 条", line)
        self.assertIn("sql_injection=3", line)


if __name__ == "__main__":
    unittest.main()
