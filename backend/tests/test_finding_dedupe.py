"""漏洞去重与唯一标识的行为测试。

系统里同时存在三套指纹，且**都不落库**（`findings` 表没有 fingerprint 列，也没有
唯一约束），去重完全发生在应用层内存中：

- 严指纹 ``finding_fingerprint``：tool + rule_id + 归一化路径 + message + 行号 20 行分桶 + owasp + subtype
- 跨工具指纹 ``cross_tool_fingerprint``：**故意丢掉 tool 和 rule_id**，才可能跨工具合并
- 宽松指纹 ``_relaxed_fingerprint_for_finding``：保留 tool/rule/message，**丢掉行号**

以及两条彼此独立的去重流水线：

- SAST：``dedupe_sast_findings`` 两趟（同工具 → 跨工具），被合并项写进 ``metadata_json``
- LLM：``normalize_and_dedupe_llm_findings`` 按「同文件 + 行区间重叠」合并。判定谓词里
  **没有漏洞类型**——这正是「LLM 把同一漏洞标成不同类型也会合并」能成立的原因，
  代价是同一行上的两个真漏洞会被错并（见 LlmOverlapKnownLimitationTests）。

本文件把这些语义钉住，包括上面这些刻意为之的取舍和已知缺陷。
"""

from __future__ import annotations

import json
import unittest

from app.models import FindingCategory, Severity
from app.services.finding_dedupe import (
    CROSS_TOOL_SCANNERS,
    cross_tool_fingerprint,
    dedupe_sast_findings,
)
from app.services.llm_audit_service import (
    DEDUP_LINE_TOLERANCE,
    _finding_priority_key,
    _findings_duplicate,
    _same_file,
    filter_new_llm_findings,
    normalize_and_dedupe_llm_findings,
)
from app.services.scan_diff_service import finding_fingerprint

UPLOAD_A = r"C:\proj\data\uploads\run-aaa\v1\src\api\order.py"
UPLOAD_B = r"C:\proj\data\uploads\run-bbb\v1\src\api\order.py"


def _sast(
    tool: str,
    *,
    path: str = "src/api/user.py",
    line: int = 100,
    rule_id: str = "rule.a",
    message: str = "unsafe query",
    severity: Severity = Severity.HIGH,
    owasp: str = "A03",
    subtype: str = "sql_injection",
) -> dict:
    return {
        "tool": tool,
        "rule_id": rule_id,
        "message": message,
        "file_path": path,
        "line_start": line,
        "line_end": line,
        "severity": severity,
        "category": FindingCategory.SAST.value,
        "owasp_id": owasp,
        "vuln_subtype": subtype,
    }


def _llm(
    path: str = "src/api/order.py",
    line: int = 120,
    *,
    category: FindingCategory = FindingCategory.BUSINESS_LOGIC,
    title: str = "订单状态机缺少终态校验，可重复退款",
    confidence: float = 0.8,
    severity: Severity = Severity.HIGH,
    rule_id: str = "llm.business_logic.order_state",
) -> dict:
    return {
        "file_path": path,
        "line_start": line,
        "line_end": line,
        "category": category,
        "message": title,
        "tool": "llm",
        "rule_id": rule_id,
        "ai_confidence": confidence,
        "severity": severity,
    }


class _OrmLike:
    """模拟 ORM Finding：``finding_to_dedupe_ref`` 走 hasattr(file_path) 分支。"""

    def __init__(self, **kw):
        self.file_path = kw.get("file_path")
        self.line_start = kw.get("line_start")
        self.line_end = kw.get("line_end")
        self.category = kw.get("category")
        self.message = kw.get("message")
        self.tool = kw.get("tool", "llm")
        self.rule_id = kw.get("rule_id")
        self.message_zh = kw.get("message_zh")
        self.owasp_id = kw.get("owasp_id")
        self.vuln_subtype = kw.get("vuln_subtype")


class SastSameToolDedupeTests(unittest.TestCase):
    """第一趟：同工具、严指纹相同 → 只留一条。"""

    def test_identical_fingerprint_keeps_highest_severity(self):
        items = [
            _sast("semgrep", severity=Severity.HIGH),
            _sast("semgrep", severity=Severity.CRITICAL),
        ]
        kept, skipped_same, skipped_cross = dedupe_sast_findings(items)

        self.assertEqual(len(kept), 1)
        self.assertEqual(skipped_same, 1)
        self.assertEqual(skipped_cross, 0)
        self.assertEqual(kept[0]["severity"], Severity.CRITICAL)

    def test_fingerprint_includes_tool_so_other_tools_go_to_cross_pass(self):
        """严指纹含 tool，所以「同工具趟」永远看不到两个不同工具。

        工具优先级（codeql > semgrep）只在跨工具趟里起作用。
        """

        items = [_sast("semgrep"), _sast("codeql")]
        kept, skipped_same, skipped_cross = dedupe_sast_findings(items)

        self.assertEqual(skipped_same, 0)
        self.assertEqual(skipped_cross, 1)
        self.assertEqual(kept[0]["tool"], "codeql")

    def test_line_outside_same_bucket_is_not_merged(self):
        """行号跨出 20 行分桶 → 严指纹不同，两条都留。"""

        items = [_sast("semgrep", line=100), _sast("semgrep", line=200)]
        kept, skipped_same, skipped_cross = dedupe_sast_findings(items)

        self.assertEqual(len(kept), 2)
        self.assertEqual((skipped_same, skipped_cross), (0, 0))

    def test_different_rule_id_is_not_merged(self):
        items = [
            _sast("semgrep", rule_id="rule.a"),
            _sast("semgrep", rule_id="rule.b"),
        ]
        kept, _, _ = dedupe_sast_findings(items)
        self.assertEqual(len(kept), 2)

    def test_empty_input(self):
        self.assertEqual(dedupe_sast_findings([]), ([], 0, 0))


class SastCrossToolDedupeTests(unittest.TestCase):
    """第二趟：跨工具指纹相同且桶内至少两个工具 → 合并，并留痕。"""

    def test_two_tools_same_location_are_merged_with_trace(self):
        items = [_sast("semgrep"), _sast("codeql")]
        kept, skipped_same, skipped_cross = dedupe_sast_findings(items)

        self.assertEqual(len(kept), 1)
        self.assertEqual(skipped_same, 0)
        self.assertEqual(skipped_cross, 1)

        # 工具优先级：codeql(0) 胜过 semgrep(1)
        self.assertEqual(kept[0]["tool"], "codeql")

        # 被合并方必须留痕，否则事后无从判断这里吞过一条
        meta = json.loads(kept[0]["metadata_json"])
        self.assertEqual(meta["sources"], ["codeql", "semgrep"])
        self.assertEqual(len(meta["merged_from"]), 1)
        self.assertEqual(meta["merged_from"][0]["tool"], "semgrep")
        self.assertEqual(meta["merged_from"][0]["rule_id"], "rule.a")

    def test_single_tool_bucket_is_not_merged(self):
        """只有一个工具时不能合并——跨工具去重的前提是两个独立工具都报了。"""

        items = [
            _sast("semgrep", rule_id="rule.a"),
            _sast("semgrep", rule_id="rule.b"),
        ]
        kept, _, skipped_cross = dedupe_sast_findings(items)
        self.assertEqual(len(kept), 2)
        self.assertEqual(skipped_cross, 0)

    def test_generic_classification_without_high_severity_is_not_merged(self):
        """双方分类都是泛化的（A04/other）且无高危 → 不合并，避免误并。"""

        items = [
            _sast("semgrep", severity=Severity.MEDIUM, owasp="A04", subtype="other"),
            _sast("codeql", severity=Severity.LOW, owasp="A04", subtype="other"),
        ]
        kept, _, skipped_cross = dedupe_sast_findings(items)
        self.assertEqual(len(kept), 2)
        self.assertEqual(skipped_cross, 0)

    def test_generic_classification_with_critical_severity_is_merged(self):
        """同样是泛化分类，但出现 CRITICAL → 仍然合并。"""

        items = [
            _sast("semgrep", severity=Severity.CRITICAL, owasp="A04", subtype="other"),
            _sast("codeql", severity=Severity.MEDIUM, owasp="A04", subtype="other"),
        ]
        kept, _, skipped_cross = dedupe_sast_findings(items)
        self.assertEqual(len(kept), 1)
        self.assertEqual(skipped_cross, 1)
        self.assertEqual(kept[0]["severity"], Severity.CRITICAL)

    def test_tool_outside_whitelist_passes_through(self):
        """不在 CROSS_TOOL_SCANNERS 里的工具不参与跨工具合并。"""

        self.assertNotIn("llm", CROSS_TOOL_SCANNERS)
        items = [
            _sast("llm", rule_id="rule.a"),
            _sast("llm", rule_id="rule.b"),
        ]
        kept, _, skipped_cross = dedupe_sast_findings(items)
        self.assertEqual(len(kept), 2)
        self.assertEqual(skipped_cross, 0)

    def test_cross_tool_fingerprint_ignores_tool_and_rule(self):
        a = _sast("semgrep", rule_id="rule.a")
        b = _sast("codeql", rule_id="rule.b")
        self.assertEqual(cross_tool_fingerprint(a), cross_tool_fingerprint(b))


class LlmOverlapDedupeTests(unittest.TestCase):
    """LLM 侧按位置重叠合并，判定谓词里不含漏洞类型。"""

    def test_same_vulnerability_with_different_labels_is_merged(self):
        """核心承诺：同一漏洞被 LLM 标成不同类型，也会并成一条。"""

        business_logic = _llm(
            "src/api/order.py", 120, category=FindingCategory.BUSINESS_LOGIC
        )
        authorization = _llm(
            "src/api/order.py",
            122,
            category=FindingCategory.AUTHORIZATION,
            title="水平越权：可越权查看他人订单",
            confidence=0.6,
        )

        out = normalize_and_dedupe_llm_findings([business_logic, authorization])

        self.assertEqual(len(out), 1)
        # 优先级：authorization 优先于 business_logic，与置信度无关
        self.assertEqual(out[0]["category"], FindingCategory.AUTHORIZATION)
        self.assertEqual(out[0]["message"], authorization["message"])

    def test_same_vulnerability_far_apart_is_not_merged(self):
        """已知不足：行号相距超过容差就不合并，同一漏洞会报两条。"""

        near = _llm("src/api/order.py", 120)
        far = _llm("src/api/order.py", 120 + DEDUP_LINE_TOLERANCE + 10)

        out = normalize_and_dedupe_llm_findings([near, far])
        self.assertEqual(len(out), 2)

    def test_zero_line_start_is_not_merged_with_known_line(self):
        """已知不足：一侧没给出行号（line_start=0）时合不进已知行号的那条。"""

        unknown = _llm("src/api/order.py", 0)
        known = _llm("src/api/order.py", 120)

        out = normalize_and_dedupe_llm_findings([unknown, known])
        self.assertEqual(len(out), 2)

    def test_both_zero_line_start_are_merged(self):
        """两侧都没行号时视为重叠，会合并。"""

        a = _llm("src/api/order.py", 0)
        b = _llm("src/api/order.py", 0)
        out = normalize_and_dedupe_llm_findings([a, b])
        self.assertEqual(len(out), 1)

    def test_same_basename_in_different_directories_is_not_merged(self):
        """回归：原来只比 basename，不同目录的同名文件会被当成同一文件。"""

        a = _llm("src/module_a/config.py", 50, title="配置里硬编码了数据库口令")
        b = _llm("src/module_b/config.py", 50, title="配置里硬编码了第三方密钥")

        self.assertFalse(_same_file(a, b))
        out = normalize_and_dedupe_llm_findings([a, b])
        self.assertEqual(len(out), 2)

    def test_absolute_upload_path_matches_repo_relative_path(self):
        """回归：绝对上传路径与仓库内相对路径必须算同一文件。"""

        absolute = _llm(UPLOAD_A, 120)
        relative = _llm("src/api/order.py", 122)

        self.assertTrue(_same_file(absolute, relative))
        out = normalize_and_dedupe_llm_findings([absolute, relative])
        self.assertEqual(len(out), 1)

    def test_different_upload_batches_are_the_same_file(self):
        a = _llm(UPLOAD_A, 120)
        b = _llm(UPLOAD_B, 121)
        self.assertTrue(_same_file(a, b))

    def test_filename_only_path_still_matches_pathed_file(self):
        """LLM 有时只回一个光秃秃的文件名，这个退化分支要保住。"""

        bare = _llm("order.py", 120)
        pathed = _llm("src/api/order.py", 122)

        self.assertTrue(_same_file(bare, pathed))
        out = normalize_and_dedupe_llm_findings([bare, pathed])
        self.assertEqual(len(out), 1)

    def test_different_basename_is_not_merged(self):
        a = _llm("src/api/order.py", 120)
        b = _llm("src/api/invoice.py", 120)
        self.assertFalse(_same_file(a, b))

    def test_severity_breaks_tie_towards_the_more_severe(self):
        """回归：类别与置信度相同时，留下的必须是更严重的那条。

        `_finding_priority_key` 原来把严重级别索引取了负，排序意图正好反过来，
        于是同一漏洞的两条描述在打平时会留下 MEDIUM 而不是 CRITICAL。
        """

        critical = _llm("src/api/order.py", 120, severity=Severity.CRITICAL, confidence=0.8)
        medium = _llm("src/api/order.py", 121, severity=Severity.MEDIUM, confidence=0.8)

        self.assertLess(
            _finding_priority_key(critical), _finding_priority_key(medium)
        )
        out = normalize_and_dedupe_llm_findings([critical, medium])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], Severity.CRITICAL)

    def test_string_severity_also_participates_in_tie_break(self):
        """严重级别以字符串形态传入时也要参与排序，不能一律并列。"""

        critical = _llm("src/api/order.py", 120, severity="CRITICAL", confidence=0.8)
        low = _llm("src/api/order.py", 121, severity="LOW", confidence=0.8)

        self.assertLess(_finding_priority_key(critical), _finding_priority_key(low))

    def test_authorization_label_wins_over_higher_confidence_business_logic(self):
        az = _llm(
            "src/api/order.py",
            120,
            category=FindingCategory.AUTHORIZATION,
            title="水平越权：可越权查看他人订单",
            confidence=0.3,
        )
        bl = _llm("src/api/order.py", 121, confidence=0.99)

        out = normalize_and_dedupe_llm_findings([bl, az])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["category"], FindingCategory.AUTHORIZATION)

    def test_mislabeled_business_logic_is_reclassified_to_authorization(self):
        item = _llm(
            "src/api/user.py",
            30,
            category=FindingCategory.BUSINESS_LOGIC,
            title="存在水平越权，可越权查看他人资料",
        )
        out = normalize_and_dedupe_llm_findings([item])

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["category"], FindingCategory.AUTHORIZATION)
        self.assertTrue(out[0]["rule_id"].startswith("llm.authorization."))

    def test_plain_business_logic_is_left_alone(self):
        item = _llm("src/api/user.py", 30)
        out = normalize_and_dedupe_llm_findings([item])
        self.assertEqual(out[0]["category"], FindingCategory.BUSINESS_LOGIC)

    def test_empty_input(self):
        self.assertEqual(normalize_and_dedupe_llm_findings([]), [])


class LlmOverlapKnownLimitationTests(unittest.TestCase):
    """把已知缺陷钉住，修好之后这些用例需要改成断言「不合并」。

    判定谓词刻意不含漏洞类型（这是跨类型合并能成立的前提），代价就是同一行区间上
    两个**真正不同**的漏洞会被错并成一条，而且合并过程不留任何痕迹——不像 SAST 的
    跨工具路径会写 metadata_json.sources / merged_from。
    """

    def test_two_distinct_vulnerabilities_on_same_line_are_wrongly_merged(self):
        sql_injection = _llm(
            "src/api/order.py",
            120,
            title="SQL 注入：orderBy 参数直接拼接进查询",
        )
        hardcoded_secret = _llm(
            "src/api/order.py",
            120,
            title="硬编码数据库口令",
        )

        out = normalize_and_dedupe_llm_findings([sql_injection, hardcoded_secret])

        self.assertEqual(len(out), 1, "当前行为：两个不同漏洞被并成一条（已知缺陷）")
        # 被丢弃那条的类型 / 规则 / 原文都没有任何地方记录
        self.assertNotIn("metadata_json", out[0])

    def test_findings_duplicate_ignores_vulnerability_type(self):
        """把谓词的性质直接写出来，避免以后有人误以为它看类型。"""

        a = _llm("src/api/order.py", 120, title="SQL 注入")
        b = _llm("src/api/order.py", 121, title="硬编码数据库口令")

        self.assertTrue(_findings_duplicate(a, b))


class LlmPersistGateTests(unittest.TestCase):
    """落库闸门：只跟库里已有的 ``tool == "llm"`` 记录比，用同一套重叠规则。"""

    def test_duplicate_against_existing_row_is_dropped(self):
        existing = [
            _OrmLike(
                file_path="src/api/order.py",
                line_start=120,
                line_end=121,
                category=FindingCategory.BUSINESS_LOGIC,
                message="订单状态机缺少终态校验，可重复退款",
                tool="llm",
                rule_id="llm.business_logic.order_state",
            )
        ]
        accepted, skipped = filter_new_llm_findings(
            [_llm("src/api/order.py", 122)], existing
        )

        self.assertEqual(accepted, [])
        self.assertEqual(skipped, 1)

    def test_same_line_but_different_file_is_kept(self):
        existing = [
            _OrmLike(
                file_path="src/api/order.py",
                line_start=120,
                line_end=121,
                category=FindingCategory.BUSINESS_LOGIC,
                message="x",
                tool="llm",
            )
        ]
        accepted, skipped = filter_new_llm_findings(
            [_llm("src/api/invoice.py", 120)], existing
        )

        self.assertEqual(len(accepted), 1)
        self.assertEqual(skipped, 0)

    def test_duplicates_within_the_new_batch_are_collapsed(self):
        accepted, skipped = filter_new_llm_findings(
            [_llm("src/api/order.py", 120), _llm("src/api/order.py", 121)], []
        )

        self.assertEqual(len(accepted), 1)
        self.assertEqual(skipped, 1)

    def test_no_existing_rows_accepts_everything(self):
        accepted, skipped = filter_new_llm_findings(
            [_llm("src/api/order.py", 120), _llm("src/api/invoice.py", 10)], []
        )
        self.assertEqual(len(accepted), 2)
        self.assertEqual(skipped, 0)


class FingerprintStabilityTests(unittest.TestCase):
    """指纹必须在「换个上传批次 / 换个克隆目录」后保持不变，否则去重与抑制都会失效。"""

    def test_strict_fingerprint_survives_new_upload_batch(self):
        a = _sast("semgrep", path=UPLOAD_A)
        b = _sast("semgrep", path=UPLOAD_B)
        self.assertEqual(finding_fingerprint(a), finding_fingerprint(b))
        self.assertIn("src/api/order.py", finding_fingerprint(a))

    def test_strict_fingerprint_changes_across_line_bucket(self):
        a = _sast("semgrep", line=100)
        b = _sast("semgrep", line=200)
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_strict_fingerprint_ignores_line_drift_within_bucket(self):
        a = _sast("semgrep", line=100)
        b = _sast("semgrep", line=115)
        self.assertEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_strict_fingerprint_separates_different_files_with_same_basename(self):
        a = _sast("semgrep", path="src/a/config.py")
        b = _sast("semgrep", path="src/b/config.py")
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))


if __name__ == "__main__":
    unittest.main()
