"""Unit tests for targeted retest queue selection rules."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from app.models import AiVerdict, ExternalReviewStatus, ReviewStatus, Severity
from app.services.retest_service import build_retest_queue, is_in_retest_queue


def _finding(
    *,
    fid: int,
    tool: str = "semgrep",
    review_status=ReviewStatus.UNREVIEWED,
    external_status=ExternalReviewStatus.UNREVIEWED,
    ai_verdict=AiVerdict.PENDING,
    severity=Severity.MEDIUM,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=fid,
        tool=tool,
        review_status=review_status,
        external_status=external_status,
        ai_verdict=ai_verdict,
        severity=severity,
    )


class RetestQueueTests(unittest.TestCase):
    def test_default_includes_unreviewed_sast(self):
        f = _finding(fid=1, tool="semgrep", review_status=ReviewStatus.UNREVIEWED)
        self.assertTrue(is_in_retest_queue(f))
        queue = build_retest_queue([f])
        self.assertEqual([x.id for x in queue], [1])

    def test_default_includes_llm_and_confirmed(self):
        findings = [
            _finding(fid=1, tool="llm"),
            _finding(fid=2, tool="semgrep", review_status=ReviewStatus.CONFIRMED),
            _finding(fid=3, tool="codeql", review_status=ReviewStatus.UNREVIEWED),
        ]
        queue = build_retest_queue(findings)
        self.assertEqual([x.id for x in queue], [1, 2, 3])

    def test_default_excludes_false_positives(self):
        findings = [
            _finding(fid=1, review_status=ReviewStatus.FALSE_POSITIVE),
            _finding(fid=2, external_status=ExternalReviewStatus.FALSE_POSITIVE),
            _finding(fid=3, ai_verdict=AiVerdict.FALSE_POSITIVE),
            _finding(fid=4, tool="semgrep"),
        ]
        queue = build_retest_queue(findings)
        self.assertEqual([x.id for x in queue], [4])
        for fp in findings[:3]:
            self.assertFalse(is_in_retest_queue(fp))

    def test_selected_includes_false_positive(self):
        fp = _finding(fid=9, review_status=ReviewStatus.FALSE_POSITIVE)
        queue = build_retest_queue([fp], finding_ids=[9])
        self.assertEqual([x.id for x in queue], [9])

    def test_selected_includes_unreviewed_sast(self):
        f = _finding(fid=5, tool="semgrep", review_status=ReviewStatus.UNREVIEWED)
        queue = build_retest_queue([f], finding_ids=[5])
        self.assertEqual([x.id for x in queue], [5])

    def test_selected_only_returns_matching_ids_including_fp(self):
        findings = [
            _finding(fid=1, tool="semgrep"),
            _finding(fid=2, review_status=ReviewStatus.FALSE_POSITIVE),
            _finding(fid=3, tool="llm"),
        ]
        queue = build_retest_queue(findings, finding_ids=[2, 3, 999])
        self.assertEqual([x.id for x in queue], [2, 3])


if __name__ == "__main__":
    unittest.main()
