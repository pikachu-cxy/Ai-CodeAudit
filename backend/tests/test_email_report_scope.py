"""扫描完成邮件的报告范围（严重级别筛选）单元测试。

覆盖：严重级别规范化、notify_emails_json 读写、向后兼容（未配置时行为与旧版完全一致）。
"""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from app.models import Severity
from app.schemas import ReportSpec
from app.services.report_service import _match_filters, _resolve_scope
from app.services.scan_service import (
    _email_report_spec,
    _normalize_report_severities,
    _pack_notify_emails_json,
    _report_severities_from_notify,
    _unpack_notify_emails_json,
)


class NormalizeSeveritiesTests(unittest.TestCase):
    def test_falsy_values_yield_empty(self):
        for value in (None, [], (), "", {}):
            with self.subTest(value=repr(value)):
                self.assertEqual(_normalize_report_severities(value), [])

    def test_lowercase_is_upcased(self):
        self.assertEqual(_normalize_report_severities(["critical", "high"]), ["CRITICAL", "HIGH"])

    def test_whitespace_is_trimmed(self):
        self.assertEqual(_normalize_report_severities(["  high  "]), ["HIGH"])

    def test_duplicates_collapse(self):
        self.assertEqual(_normalize_report_severities(["HIGH", "high", "High"]), ["HIGH"])

    def test_sorted_by_severity_not_by_input_order(self):
        self.assertEqual(
            _normalize_report_severities(["LOW", "CRITICAL", "MEDIUM", "HIGH"]),
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )

    def test_unknown_is_dropped(self):
        # UNKNOWN 不是用户可选的严重级别，必须被剔除。
        self.assertEqual(_normalize_report_severities(["HIGH", "UNKNOWN"]), ["HIGH"])

    def test_garbage_is_dropped(self):
        self.assertEqual(_normalize_report_severities(["HIGH", "banana", ""]), ["HIGH"])

    def test_all_garbage_yields_empty(self):
        self.assertEqual(_normalize_report_severities(["nope", "UNKNOWN"]), [])


class PackNotifyEmailsTests(unittest.TestCase):
    def test_omitting_severities_keeps_legacy_payload_shape(self):
        raw = _pack_notify_emails_json(["a@x.com"])
        self.assertNotIn("report_severities", json.loads(raw))
        self.assertEqual(_unpack_notify_emails_json(raw), (["a@x.com"], True))

    def test_severities_are_persisted_normalized(self):
        raw = _pack_notify_emails_json(
            ["a@x.com"], report_severities=["high", "CRITICAL", "HIGH"]
        )
        self.assertEqual(json.loads(raw)["report_severities"], ["CRITICAL", "HIGH"])

    def test_empty_severities_does_not_add_key(self):
        raw = _pack_notify_emails_json(["a@x.com"], report_severities=[])
        self.assertNotIn("report_severities", json.loads(raw))

    def test_garbage_severities_does_not_add_key(self):
        raw = _pack_notify_emails_json(["a@x.com"], report_severities=["nope"])
        self.assertNotIn("report_severities", json.loads(raw))

    def test_legacy_empty_email_behaviour_unchanged(self):
        self.assertIsNone(_pack_notify_emails_json([], send_html_report=True))
        raw = _pack_notify_emails_json([], send_html_report=False)
        self.assertEqual(_unpack_notify_emails_json(raw), ([], False))

    def test_send_html_report_flag_survives_alongside_severities(self):
        raw = _pack_notify_emails_json(
            ["a@x.com"], send_html_report=False, report_severities=["CRITICAL"]
        )
        self.assertEqual(_unpack_notify_emails_json(raw), (["a@x.com"], False))
        self.assertEqual(json.loads(raw)["report_severities"], ["CRITICAL"])


class ReadSeveritiesTests(unittest.TestCase):
    def test_blank_values_yield_empty(self):
        for raw in (None, "", "   "):
            with self.subTest(raw=repr(raw)):
                self.assertEqual(_report_severities_from_notify(raw), [])

    def test_malformed_json_degrades_to_no_filter(self):
        self.assertEqual(_report_severities_from_notify("{not json"), [])

    def test_legacy_list_payload_yields_empty(self):
        self.assertEqual(_report_severities_from_notify(json.dumps(["a@x.com"])), [])

    def test_dict_without_key_yields_empty(self):
        self.assertEqual(_report_severities_from_notify(json.dumps({"emails": ["a@x.com"]})), [])

    def test_roundtrip_through_pack(self):
        raw = _pack_notify_emails_json(["a@x.com"], report_severities=["low", "critical"])
        self.assertEqual(_report_severities_from_notify(raw), ["CRITICAL", "LOW"])


class EmailReportSpecTests(unittest.TestCase):
    @staticmethod
    def _scan(raw):
        return SimpleNamespace(notify_emails_json=raw)

    def test_unconfigured_scans_get_no_spec_so_report_stays_full(self):
        """未配置时必须返回 None，让邮件继续走全量报告（向后兼容的关键）。"""
        cases = {
            "no notify config": None,
            "legacy list": json.dumps(["a@x.com"]),
            "dict without severities": _pack_notify_emails_json(["a@x.com"]),
            "empty severities": _pack_notify_emails_json(["a@x.com"], report_severities=[]),
        }
        for label, raw in cases.items():
            with self.subTest(case=label):
                self.assertIsNone(_email_report_spec(self._scan(raw)))

    def test_configured_severities_become_a_filtered_spec(self):
        scan = self._scan(
            _pack_notify_emails_json(["a@x.com"], report_severities=["high", "critical"])
        )
        spec = _email_report_spec(scan)
        self.assertIsInstance(spec, ReportSpec)
        assert spec is not None and spec.filters is not None
        self.assertEqual(spec.filters.severity, ["CRITICAL", "HIGH"])
        self.assertIsNone(spec.finding_ids)

    def test_spec_counts_as_filtered_scope(self):
        scan = self._scan(_pack_notify_emails_json(["a@x.com"], report_severities=["CRITICAL"]))
        self.assertEqual(_resolve_scope(_email_report_spec(scan)), "filtered")

    def test_produced_filters_keep_only_the_selected_severities(self):
        scan = self._scan(
            _pack_notify_emails_json(["a@x.com"], report_severities=["CRITICAL", "HIGH"])
        )
        spec = _email_report_spec(scan)
        assert spec is not None
        critical = SimpleNamespace(severity=Severity.CRITICAL)
        high = SimpleNamespace(severity=Severity.HIGH)
        medium = SimpleNamespace(severity=Severity.MEDIUM)
        low = SimpleNamespace(severity=Severity.LOW)

        self.assertTrue(_match_filters(critical, spec.filters))
        self.assertTrue(_match_filters(high, spec.filters))
        self.assertFalse(_match_filters(medium, spec.filters))
        self.assertFalse(_match_filters(low, spec.filters))


if __name__ == "__main__":
    unittest.main()
