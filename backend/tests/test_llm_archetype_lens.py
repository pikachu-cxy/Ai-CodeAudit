"""Tests for archetype-specific audit lenses (prompt + entry-surface file discovery)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.models import FindingCategory
from app.services.llm_archetype_lens import (
    ARCHETYPE_LENSES,
    LENS_ARCHETYPES,
    LENS_RISK_TAGS,
    build_lens_prompt,
    collect_lens_files,
    lens_types,
)
from app.services.llm_audit_service import (
    LENS_MAX_FILES,
    RISK_TAG_LABELS,
    infer_risk_tags,
    llm_items_to_findings,
    run_archetype_lens_audit,
)
from app.services.project_archetype_service import (
    CLI_TOOL,
    HTTP_API,
    MQ_CONSUMER,
    RPC_SERVICE,
    SCHEDULED_JOB,
    SDK_LIBRARY,
    ArchetypeHit,
    clear_archetype_cache,
)


def hit(archetype: str, score: int = 6) -> ArchetypeHit:
    return ArchetypeHit(archetype, score, min(0.95, score / 6))


class _ProjectFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        clear_archetype_cache()
        self.addCleanup(clear_archetype_cache)

    def write(self, rel: str, content: str = "") -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path


class LensTableIntegrityTests(unittest.TestCase):
    def test_every_lens_has_risks_and_locators(self):
        self.assertEqual(set(LENS_ARCHETYPES), set(ARCHETYPE_LENSES))
        for archetype, spec in ARCHETYPE_LENSES.items():
            with self.subTest(archetype=archetype):
                self.assertGreaterEqual(len(spec.risk_focus), 5)
                self.assertTrue(spec.path_keywords)
                self.assertTrue(spec.code_patterns)
                self.assertEqual(spec.archetype, archetype)
                self.assertTrue(spec.label)

    def test_http_api_has_no_lens(self):
        # HTTP 服务本来就有端点驱动审计，不该再走形态视角
        self.assertNotIn(HTTP_API, ARCHETYPE_LENSES)

    def test_declared_risk_tags_are_whitelisted(self):
        # `_normalize_risk_tag` 会把白名单外的标签静默丢掉，写错一个词很难发现
        unknown = [t for t in LENS_RISK_TAGS if t not in RISK_TAG_LABELS]
        self.assertEqual(unknown, [], f"这些标签不在 RISK_TAG_LABELS 里，会被静默丢弃: {unknown}")

    def test_prompt_lists_the_declared_tags(self):
        prompt = build_lens_prompt([MQ_CONSUMER])
        for tag in LENS_RISK_TAGS:
            self.assertIn(tag, prompt)


class LensSelectionTests(unittest.TestCase):
    def test_filters_http_and_keeps_order(self):
        hits = [hit(HTTP_API, 12), hit(MQ_CONSUMER), hit(SCHEDULED_JOB)]
        self.assertEqual(lens_types(hits), [MQ_CONSUMER, SCHEDULED_JOB])

    def test_dedupes(self):
        self.assertEqual(lens_types([hit(MQ_CONSUMER), hit(MQ_CONSUMER)]), [MQ_CONSUMER])

    def test_empty(self):
        self.assertEqual(lens_types([]), [])
        self.assertEqual(lens_types(None), [])


class LensPromptTests(unittest.TestCase):
    def test_single_archetype_prompt(self):
        prompt = build_lens_prompt([MQ_CONSUMER])
        self.assertIn("消息队列消费者", prompt)
        self.assertIn("消息体不可信", prompt)
        self.assertIn("entry_surface", prompt)
        # 必须明确禁止硬编 HTTP 路径，否则模型会照旧填 /api/xxx
        self.assertIn("不要", prompt)
        self.assertIn("HTTP", prompt)

    def test_multi_archetype_prompt_has_separate_sections(self):
        prompt = build_lens_prompt([MQ_CONSUMER, SCHEDULED_JOB, SDK_LIBRARY])
        self.assertIn("消息队列消费者视角", prompt)
        self.assertIn("定时任务 / 批处理视角", prompt)
        self.assertIn("SDK / 公共库视角", prompt)
        # 段落之间要留空行，否则小标题会贴在上一段末尾
        self.assertIn("\n\n【定时任务", prompt)
        self.assertIn("\n\n【SDK", prompt)

    def test_empty_or_http_only_returns_blank(self):
        self.assertEqual(build_lens_prompt([]), "")
        self.assertEqual(build_lens_prompt([HTTP_API]), "")
        self.assertEqual(build_lens_prompt(["nonexistent"]), "")

    def test_each_lens_prompt_renders(self):
        for archetype in LENS_ARCHETYPES:
            with self.subTest(archetype=archetype):
                prompt = build_lens_prompt([archetype])
                self.assertIn(ARCHETYPE_LENSES[archetype].risk_focus[0][:8], prompt)


class CollectLensFilesTests(_ProjectFixture):
    def test_mq_consumer_files_found_by_annotation(self):
        self.write(
            "src/main/java/com/demo/mq/consumer/OrderConsumer.java",
            "@Component\npublic class OrderConsumer {\n"
            "  @RabbitListener(queues = \"order.queue\")\n"
            "  public void onMessage(String body) {}\n}\n",
        )
        # 这个文件不含任何入口面特征，不该被选中
        self.write("src/main/java/com/demo/util/StringUtils.java", "public class StringUtils {}\n")

        selected = collect_lens_files(self.root, [MQ_CONSUMER], max_files=5)
        rel = {p.relative_to(self.root).as_posix() for p in selected}
        self.assertEqual(len(rel), 1, rel)
        self.assertIn("OrderConsumer.java", next(iter(rel)))

    def test_cron_files_found_by_annotation(self):
        self.write(
            "src/main/java/com/demo/job/PopMsgJob.java",
            "public class PopMsgJob {\n  @XxlJob(\"popMsg\")\n  public void run() {}\n}\n",
        )
        selected = collect_lens_files(self.root, [SCHEDULED_JOB], max_files=5)
        self.assertEqual(len(selected), 1)
        self.assertIn("PopMsgJob.java", selected[0].name)

    def test_python_sdk_files_found_by_path_keyword(self):
        self.write("demo_sdk/crypto/cipher.py", "def encrypt(data, key):\n    return data\n")
        selected = collect_lens_files(self.root, [SDK_LIBRARY], max_files=5)
        self.assertEqual(len(selected), 1)
        self.assertIn("cipher.py", selected[0].name)

    def test_test_paths_are_skipped(self):
        self.write(
            "src/test/java/com/demo/ConsumerTest.java",
            "@RabbitListener(queues = \"q\")\npublic class ConsumerTest {}\n",
        )
        self.assertEqual(collect_lens_files(self.root, [MQ_CONSUMER], max_files=5), [])

    def test_no_matching_files_returns_empty(self):
        self.write("src/main/java/com/demo/util/A.java", "public class A {}\n")
        self.assertEqual(collect_lens_files(self.root, [MQ_CONSUMER], max_files=5), [])

    def test_empty_types_returns_empty(self):
        self.write(
            "src/main/java/com/demo/mq/consumer/C.java",
            "@RabbitListener(queues = \"q\")\npublic class C {}\n",
        )
        self.assertEqual(collect_lens_files(self.root, [], max_files=5), [])
        self.assertEqual(collect_lens_files(self.root, [HTTP_API], max_files=5), [])
        self.assertEqual(collect_lens_files(self.root, [MQ_CONSUMER], max_files=0), [])

    def test_max_files_is_respected(self):
        for i in range(6):
            self.write(
                f"src/main/java/com/demo/mq/consumer/Consumer{i}.java",
                "@RabbitListener(queues = \"q\")\npublic class C {}\n",
            )
        self.assertEqual(len(collect_lens_files(self.root, [MQ_CONSUMER], max_files=2)), 2)

    def test_ranking_prefers_annotation_hits_over_directory_only(self):
        # 只有目录名命中（+2）vs 目录名 + 注解命中（+2+5）
        self.write("src/main/java/com/demo/mq/Plain.java", "public class Plain {}\n")
        self.write(
            "src/main/java/com/demo/mq/RealConsumer.java",
            "@RabbitListener(queues = \"q\")\npublic class RealConsumer {}\n",
        )
        selected = collect_lens_files(self.root, [MQ_CONSUMER], max_files=1)
        self.assertEqual([p.name for p in selected], ["RealConsumer.java"])


class EntrySurfaceMappingTests(_ProjectFixture):
    def _item(self, **overrides) -> dict:
        item = {
            "category": "business_logic",
            "severity": "HIGH",
            "title": "消息体中的 userId 被直接用于鉴权",
            "description": "消费者信任消息体里的 userId",
            "file": "mq/consumer/OrderConsumer.java",
            "line_start": 10,
            "line_end": 20,
            "evidence": "String userId = msg.getUserId();",
            "confidence": 0.8,
        }
        item.update(overrides)
        return item

    def test_entry_surface_falls_back_into_api_endpoint(self):
        self.write("mq/consumer/OrderConsumer.java", "class OrderConsumer {}\n")
        findings = llm_items_to_findings(
            [self._item(entry_surface="order.queue", entry_code_ref="mq/consumer/OrderConsumer.java:12")],
            self.root,
            FindingCategory.BUSINESS_LOGIC,
            rule_prefix="archetype",
            lock_category=False,
        )
        self.assertEqual(len(findings), 1)
        meta = json.loads(findings[0]["metadata_json"])
        self.assertEqual(meta["api_endpoint"], "order.queue")
        self.assertEqual(meta["endpoint_code_ref"], "mq/consumer/OrderConsumer.java:12")
        # 非 HTTP 入口面要用「入口面」而不是「接口」来标注
        self.assertIn("入口面: order.queue", findings[0]["ai_reason"])
        self.assertNotIn("接口: order.queue", findings[0]["ai_reason"])

    def test_explicit_api_endpoint_wins_and_keeps_http_label(self):
        self.write("api/order.py", "x = 1\n")
        findings = llm_items_to_findings(
            [self._item(file="api/order.py", api_endpoint="GET /api/order/{id}", entry_surface="ignored")],
            self.root,
            FindingCategory.BUSINESS_LOGIC,
            lock_category=False,
        )
        meta = json.loads(findings[0]["metadata_json"])
        self.assertEqual(meta["api_endpoint"], "GET /api/order/{id}")
        self.assertIn("接口: GET /api/order/{id}", findings[0]["ai_reason"])

    def test_archetype_rule_prefix_is_applied(self):
        self.write("mq/consumer/OrderConsumer.java", "class OrderConsumer {}\n")
        findings = llm_items_to_findings(
            [self._item()],
            self.root,
            FindingCategory.BUSINESS_LOGIC,
            rule_prefix="archetype",
            lock_category=False,
        )
        self.assertTrue(findings[0]["rule_id"].startswith("archetype."), findings[0]["rule_id"])

    def test_new_risk_tags_survive_inference(self):
        self.write("mq/consumer/OrderConsumer.java", "class OrderConsumer {}\n")
        findings = llm_items_to_findings(
            [self._item(risk_tags=["message_trust", "idempotency", "not_a_real_tag"])],
            self.root,
            FindingCategory.BUSINESS_LOGIC,
            lock_category=False,
        )
        meta = json.loads(findings[0]["metadata_json"])
        self.assertIn("message_trust", meta["risk_tags"])
        self.assertNotIn("not_a_real_tag", meta["risk_tags"])

    def test_unlocked_category_keeps_authorization(self):
        self.write("mq/consumer/OrderConsumer.java", "class OrderConsumer {}\n")
        findings = llm_items_to_findings(
            [self._item(category="authorization")],
            self.root,
            FindingCategory.BUSINESS_LOGIC,
            lock_category=False,
        )
        self.assertEqual(findings[0]["category"], FindingCategory.AUTHORIZATION)

    def test_infer_risk_tags_covers_lens_labels(self):
        tags = infer_risk_tags(
            {"title": "消息体信任", "description": "消费者信任消息体里的 tenantId，重复消费导致重复扣款"},
            FindingCategory.BUSINESS_LOGIC,
        )
        self.assertIn("message_trust", tags)


class RunLensAuditTests(_ProjectFixture):
    def _mq_project(self):
        self.write(
            "mq/consumer/OrderConsumer.java",
            "@RabbitListener(queues = \"order.queue\")\npublic class OrderConsumer {}\n",
        )

    async def _run(self, archetypes, llm_reply, **kwargs):
        with patch("app.services.llm_audit_service.is_llm_configured", return_value=True), patch(
            "app.services.llm_audit_service.chat_completion", new=AsyncMock(return_value=llm_reply)
        ):
            return await run_archetype_lens_audit(self.root, archetypes, **kwargs)

    def test_returns_empty_without_lensable_archetype(self):
        self._mq_project()
        # 没有形态 → 不该发起任何 LLM 调用
        with patch("app.services.llm_audit_service.chat_completion", new=AsyncMock()) as mock:
            result = asyncio_run(run_archetype_lens_audit(self.root, [hit(HTTP_API, 12)]))
        self.assertEqual(result, [])
        mock.assert_not_called()

    def test_runs_and_maps_findings(self):
        self._mq_project()
        reply = json.dumps(
            [
                {
                    "category": "authorization",
                    "severity": "HIGH",
                    "title": "消息体中的 userId 未做归属校验",
                    "description": "消费者直接用消息体 userId 查库",
                    "file": "mq/consumer/OrderConsumer.java",
                    "line_start": 1,
                    "line_end": 3,
                    "evidence": "msg.getUserId()",
                    "entry_surface": "order.queue",
                    "risk_tags": ["message_trust", "idor"],
                    "confidence": 0.85,
                }
            ],
            ensure_ascii=False,
        )
        result = asyncio_run(self._run([hit(MQ_CONSUMER)], reply))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["category"], FindingCategory.AUTHORIZATION)
        self.assertTrue(result[0]["rule_id"].startswith("archetype."))
        self.assertEqual(result[0]["tool"], "llm")

    def test_no_entry_surface_files_skips_llm(self):
        self.write("unrelated/Thing.java", "public class Thing {}\n")
        with patch("app.services.llm_audit_service.chat_completion", new=AsyncMock()) as mock:
            result = asyncio_run(run_archetype_lens_audit(self.root, [hit(MQ_CONSUMER)]))
        self.assertEqual(result, [])
        mock.assert_not_called()

    def test_raises_when_all_batches_fail(self):
        self._mq_project()
        with patch("app.services.llm_audit_service.is_llm_configured", return_value=True), patch(
            "app.services.llm_audit_service.chat_completion",
            new=AsyncMock(side_effect=RuntimeError("boom")),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio_run(run_archetype_lens_audit(self.root, [hit(MQ_CONSUMER)]))
        self.assertIn("形态视角审计失败", str(ctx.exception))

    def test_batch_size_caps_llm_calls(self):
        for i in range(LENS_MAX_FILES + 4):
            self.write(
                f"mq/consumer/Consumer{i}.java",
                "@RabbitListener(queues = \"q\")\npublic class C {}\n",
            )
        with patch("app.services.llm_audit_service.is_llm_configured", return_value=True), patch(
            "app.services.llm_audit_service.chat_completion", new=AsyncMock(return_value="[]")
        ) as mock:
            asyncio_run(run_archetype_lens_audit(self.root, [hit(MQ_CONSUMER)]))
        # 16 个文件 / 每批 8 个 → 恰好 2 次调用
        self.assertEqual(mock.await_count, 2)


def asyncio_run(coro):
    import asyncio

    return asyncio.run(coro)


if __name__ == "__main__":
    unittest.main()
