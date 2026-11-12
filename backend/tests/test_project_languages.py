"""Tests for optional project scan_languages and detected_languages."""

from __future__ import annotations

import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from app.services.project_languages import (
    detected_languages_from_scanner_summary,
    detected_languages_from_source_counts,
    normalize_scan_languages,
    packs_for_languages,
)
from app.services.scanners.semgrep import (
    SECURITY_BASE_CONFIGS,
    reset_forced_scan_languages,
    resolve_semgrep_configs,
    set_forced_scan_languages,
)


class NormalizeScanLanguagesTests(unittest.TestCase):
    def test_dedupe_and_aliases(self):
        self.assertEqual(
            normalize_scan_languages(["Java", "python", "golang", "c#", "java"]),
            ["java", "python", "go", "csharp"],
        )

    def test_empty(self):
        self.assertEqual(normalize_scan_languages(None), [])
        self.assertEqual(normalize_scan_languages([]), [])
        self.assertEqual(normalize_scan_languages(""), [])


class DetectedLanguagesTests(unittest.TestCase):
    def test_from_source_counts_order_and_primary(self):
        rows = detected_languages_from_source_counts(
            {"p/java": 80, "p/python": 20, "p/javascript": 5}
        )
        self.assertEqual([r["id"] for r in rows], ["java", "python", "javascript"])
        self.assertTrue(rows[0]["primary"])
        self.assertFalse(rows[1]["primary"])
        self.assertEqual(rows[0]["file_count"], 80)
        self.assertEqual(rows[0]["label"], "Java")

    def test_from_scanner_summary(self):
        summary = (
            '[{"scanner":"semgrep","detail":{"source_counts":{"p/python":10,"p/java":3}}}]'
        )
        rows = detected_languages_from_scanner_summary(summary)
        self.assertEqual([r["id"] for r in rows], ["python", "java"])
        self.assertTrue(rows[0]["primary"])


class ForcedSemgrepConfigsTests(unittest.TestCase):
    def tearDown(self):
        # Ensure context does not leak across tests.
        token = set_forced_scan_languages(None)
        reset_forced_scan_languages(token)

    def test_empty_forced_matches_auto_behavior(self):
        counts = Counter({"p/java": 50, "p/python": 10})
        with patch("app.services.scanners.semgrep.settings") as mock_settings:
            mock_settings.semgrep_config = "auto"
            auto_configs, auto_reason = resolve_semgrep_configs(Path("."), counts)

        token = set_forced_scan_languages([])
        try:
            with patch("app.services.scanners.semgrep.settings") as mock_settings:
                mock_settings.semgrep_config = "auto"
                forced_empty, _ = resolve_semgrep_configs(Path("."), counts)
        finally:
            reset_forced_scan_languages(token)

        self.assertEqual(forced_empty, auto_configs)
        self.assertIn("p/java", auto_configs)
        for base in SECURITY_BASE_CONFIGS:
            self.assertIn(base, auto_configs)
        self.assertIn("安全规则", auto_reason)

    def test_forced_java_python_includes_packs(self):
        counts = Counter({"p/java": 40, "p/python": 30, "p/javascript": 5})
        token = set_forced_scan_languages(["java", "python"])
        try:
            configs, reason = resolve_semgrep_configs(Path("."), counts)
        finally:
            reset_forced_scan_languages(token)

        for base in SECURITY_BASE_CONFIGS:
            self.assertIn(base, configs)
        self.assertIn("p/java", configs)
        self.assertIn("p/python", configs)
        self.assertNotIn("p/javascript", configs)
        self.assertIn("用户指定扫描语言", reason)
        self.assertEqual(packs_for_languages(["java", "python"]), ["p/java", "p/python"])

    def test_forced_skips_missing_language_files(self):
        counts = Counter({"p/java": 10})
        token = set_forced_scan_languages(["java", "python"])
        try:
            configs, reason = resolve_semgrep_configs(Path("."), counts)
        finally:
            reset_forced_scan_languages(token)

        self.assertIn("p/java", configs)
        self.assertNotIn("p/python", configs)
        self.assertIn("跳过 p/python", reason)

    def test_plan_uses_forced_packs(self):
        from app.services.scanners.semgrep import _PLAN_CACHE, plan_semgrep_scan

        _PLAN_CACHE.clear()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Main.java").write_text("class Main {}", encoding="utf-8")
            (root / "app.py").write_text("print(1)\n", encoding="utf-8")
            token = set_forced_scan_languages(["java", "python"])
            try:
                plan = plan_semgrep_scan(root)
            finally:
                reset_forced_scan_languages(token)

        self.assertIn("p/java", plan.configs)
        self.assertIn("p/python", plan.configs)
        for base in SECURITY_BASE_CONFIGS:
            self.assertIn(base, plan.configs)


if __name__ == "__main__":
    unittest.main()
