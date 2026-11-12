"""Tests for static project-archetype detection and archetype-aware file scoring."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.llm_audit_service import _score_file, collect_audit_files
from app.services.project_archetype_service import (
    CLI_TOOL,
    HTTP_API,
    MQ_CONSUMER,
    RPC_SERVICE,
    SCHEDULED_JOB,
    SDK_LIBRARY,
    clear_archetype_cache,
    detect_archetypes,
    format_summary,
    primary_archetype,
    score_profile,
    summarize,
)


class _ProjectFixture(unittest.TestCase):
    """Common tempdir helper — writes files and returns the project root."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        # detect_archetypes 有 90s TTL 缓存，测试里目录内容会变，必须每次清空
        clear_archetype_cache()
        self.addCleanup(clear_archetype_cache)

    def write(self, rel: str, content: str = "") -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def types(self, **kwargs) -> list[str]:
        return [h.type for h in detect_archetypes(self.root, **kwargs)]

    def hit(self, archetype: str, **kwargs):
        for h in detect_archetypes(self.root, **kwargs):
            if h.type == archetype:
                return h
        return None


class ManifestDetectionTests(_ProjectFixture):
    def test_java_kafka_consumer_from_dependency_and_annotation(self):
        self.write(
            "pom.xml",
            "<project><dependencies><dependency>"
            "<artifactId>spring-kafka</artifactId>"
            "</dependency></dependencies></project>",
        )
        self.write(
            "src/main/java/com/demo/consumer/OrderConsumer.java",
            "@Component\npublic class OrderConsumer {\n"
            "  @KafkaListener(topics = \"order\")\n"
            "  public void onMessage(String msg) {}\n}\n",
        )

        hits = detect_archetypes(self.root)
        types = [h.type for h in hits]
        self.assertIn(MQ_CONSUMER, types)
        mq = next(h for h in hits if h.type == MQ_CONSUMER)
        self.assertGreaterEqual(mq.confidence, 0.9)
        joined = " ".join(mq.evidence)
        self.assertIn("pom.xml", joined)
        self.assertIn("OrderConsumer.java", joined)

    def test_python_apscheduler_scheduled_job(self):
        self.write("requirements.txt", "fastapi==0.110\nAPScheduler==3.10\n")
        self.write(
            "app/tasks/report_job.py",
            "from apscheduler.schedulers.background import BackgroundScheduler\n"
            "scheduler = BackgroundScheduler()\n"
            "@scheduler.scheduled_job('cron', hour=1)\n"
            "def build_report():\n    pass\n",
        )

        hits = detect_archetypes(self.root)
        self.assertIn(SCHEDULED_JOB, [h.type for h in hits])
        self.assertIn("apscheduler", " ".join(hits[0].evidence).lower())

    def test_go_grpc_service(self):
        self.write("go.mod", "module example.com/demo\n\ngo 1.21\n")
        self.write(
            "internal/rpc/server.go",
            "package main\n\nfunc main() {\n"
            "\ts := grpc.NewServer()\n"
            "\tpb.RegisterOrderServer(s, &impl{})\n"
            "}\n",
        )
        self.write(
            "internal/rpc/impl.go",
            "package rpc\n\nfunc (i *impl) GetOrder(ctx context.Context) error { return nil }\n",
        )

        types = self.types()
        self.assertIn(RPC_SERVICE, types)

    def test_node_grpc_and_cron_multilabel(self):
        self.write(
            "package.json",
            '{"name":"demo","dependencies":{"@grpc/grpc-js":"^1.9.0","node-cron":"^3.0.0"}}',
        )
        self.write("src/grpc/service.ts", "import { Server } from '@grpc/grpc-js';\n")
        self.write("src/jobs/cleanup.ts", "cron.schedule('0 0 * * *', () => {});\n")

        types = self.types()
        # 多标签：同一项目既是 RPC 服务又是定时任务
        self.assertIn(RPC_SERVICE, types)
        self.assertIn(SCHEDULED_JOB, types)

    def test_cobra_cli_tool(self):
        self.write("go.mod", "module example.com/cli\n\ngo 1.21\n")
        self.write("cmd/root.go", "var rootCmd = &cobra.Command{Use: \"demo\"}\n")
        self.write(
            "main.go",
            "package main\n\nfunc main() {\n\trootCmd.Execute()\n}\n",
        )

        self.assertIn(CLI_TOOL, self.types())

    def test_test_tree_does_not_provide_signals(self):
        # @KafkaListener 只出现在测试目录里，不应该被当作生产 MQ 消费者证据
        self.write("pom.xml", "<project><artifactId>demo</artifactId></project>")
        self.write(
            "src/test/java/com/demo/ConsumerTest.java",
            "@KafkaListener(topics = \"order\")\npublic class ConsumerTest {}\n",
        )
        self.assertNotIn(MQ_CONSUMER, self.types())


class LibraryDetectionTests(_ProjectFixture):
    def test_python_distribution_without_entry_point(self):
        self.write(
            "pyproject.toml",
            "[build-system]\nrequires = [\"setuptools\"]\n\n"
            "[project]\nname = \"demo-sdk\"\nversion = \"1.0.0\"\n",
        )
        self.write("demo_sdk/crypto/cipher.py", "def encrypt(data, key):\n    return data\n")

        hits = detect_archetypes(self.root, controller_count=0)
        sdk = next((h for h in hits if h.type == SDK_LIBRARY), None)
        self.assertIsNotNone(sdk)
        # 发行元数据(3) + 无可执行入口(2) = 5/6
        self.assertGreaterEqual(sdk.confidence, 0.8)
        self.assertIn("pyproject.toml", " ".join(sdk.evidence))

    def test_entry_point_lowers_library_confidence(self):
        self.write(
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"1.0.0\"\n",
        )
        self.write("demo/core.py", "def run():\n    pass\n")

        without_entry = detect_archetypes(self.root, controller_count=0)
        sdk_without = next(h for h in without_entry if h.type == SDK_LIBRARY)

        self.write("demo/__main__.py", "if __name__ == \"__main__\":\n    run()\n")
        clear_archetype_cache()  # 目录已变，作废缓存
        with_entry = detect_archetypes(self.root, controller_count=0)
        sdk_with = next(h for h in with_entry if h.type == SDK_LIBRARY)

        self.assertLess(sdk_with.score, sdk_without.score)

    def test_jar_packaging_without_spring_boot_plugin(self):
        self.write(
            "pom.xml",
            "<project><artifactId>demo-lib</artifactId>"
            "<packaging>jar</packaging></project>",
        )
        self.write("src/main/java/com/demo/StringUtils.java", "public class StringUtils {}\n")

        types = self.types(controller_count=0)
        self.assertIn(SDK_LIBRARY, types)

    def test_go_service_is_not_reported_as_library(self):
        # 只有 go.mod 是弱证据，配合 package main 就不该被判成库
        self.write("go.mod", "module example.com/svc\n\ngo 1.21\n")
        self.write(
            "main.go",
            "package main\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", nil)\n}\n",
        )
        self.assertNotIn(SDK_LIBRARY, self.types(controller_count=0))

    def test_multimodule_maven_child_dependency_is_seen(self):
        # 依赖声明在子模块 pom 里，根 pom 只是聚合器 —— 不能因为根 pom 已占位就漏读
        self.write(
            "pom.xml",
            "<project><packaging>pom</packaging>"
            "<modules><module>svc</module></modules></project>",
        )
        self.write(
            "svc/pom.xml",
            "<project><artifactId>svc</artifactId><dependencies><dependency>"
            "<artifactId>spring-kafka</artifactId></dependency></dependencies></project>",
        )
        self.write(
            "svc/src/main/java/com/demo/SvcConsumer.java",
            "@KafkaListener(topics = \"t\")\npublic class SvcConsumer {}\n",
        )
        self.assertIn(MQ_CONSUMER, self.types(controller_count=0))

    def test_aggregator_pom_is_not_a_library(self):
        self.write(
            "pom.xml",
            "<project><packaging>pom</packaging>"
            "<modules><module>a</module></modules></project>",
        )
        self.write("a/pom.xml", "<project><artifactId>a</artifactId></project>")
        self.write("a/src/main/java/com/demo/A.java", "public class A {}\n")
        self.assertNotIn(SDK_LIBRARY, self.types(controller_count=0))


class HttpAuthorityTests(_ProjectFixture):
    def _spring_project(self):
        self.write(
            "pom.xml",
            "<project><artifactId>demo</artifactId>"
            "<dependencies><dependency><artifactId>spring-boot-starter-web</artifactId>"
            "</dependency></dependencies></project>",
        )
        self.write(
            "src/main/java/com/demo/controller/OrderController.java",
            "@RestController\n@RequestMapping(\"/api/order\")\npublic class OrderController {}\n",
        )

    def test_controller_count_zero_suppresses_http_archetype(self):
        self._spring_project()
        # 端点发现说没有 HTTP 端点 —— 以它为准，正则不得把库/消费者项目翻成 HTTP 服务
        self.assertNotIn(HTTP_API, self.types(controller_count=0))

    def test_controller_count_positive_yields_http_archetype(self):
        self._spring_project()
        hit = self.hit(HTTP_API, controller_count=12)
        self.assertIsNotNone(hit)
        self.assertEqual(primary_archetype(detect_archetypes(self.root, controller_count=12)), HTTP_API)

    def test_regex_fallback_when_controller_count_unknown(self):
        self._spring_project()
        self.assertIn(HTTP_API, self.types(controller_count=None))


class NestedRepoAndRuleTableTests(_ProjectFixture):
    """夹带的嵌套仓库副本、以及规则表文件，都不该影响本项目形态判断。"""

    def test_nested_git_repo_is_excluded(self):
        """被扫项目里夹带 clone 下来的另一个仓库时，后者的注解和依赖都不算本项目证据。"""
        self.write("app/api/order.py", "def get_order(oid):\n    return oid\n")
        (self.root / "data" / "repos" / "deadbeef" / ".git").mkdir(parents=True)
        self.write(
            "data/repos/deadbeef/pom.xml",
            "<project><dependencies><dependency>"
            "<artifactId>spring-cloud-starter-openfeign</artifactId>"
            "</dependency></dependencies></project>",
        )
        self.write(
            "data/repos/deadbeef/src/main/java/com/x/api/feign/PayClient.java",
            'package com.x.api.feign;\n@FeignClient(name = "pay")\npublic interface PayClient {}\n',
        )

        self.assertNotIn(RPC_SERVICE, self.types(controller_count=0))

    def test_nested_gitfile_also_excluded(self):
        """.git 是文件（submodule / worktree 的 gitfile）时同样要剔除。"""
        self.write("app/main.py", "def main():\n    pass\n")
        (self.root / "vendor" / "legacy").mkdir(parents=True)
        self.write("vendor/legacy/.git", "gitdir: ../../.git/modules/legacy\n")
        self.write(
            "vendor/legacy/job/CleanJob.java",
            'package job;\n@Scheduled(cron = "0 0 1 * * ?")\npublic class CleanJob {}\n',
        )

        self.assertNotIn(SCHEDULED_JOB, self.types(controller_count=0))

    def test_root_git_dir_does_not_disable_detection(self):
        """项目根本身是 git 仓库时，不能把自己也当成嵌套仓库剔掉。"""
        (self.root / ".git").mkdir()
        self.write("pom.xml", "<project><dependencies><dependency>"
                              "<artifactId>spring-boot-starter-amqp</artifactId>"
                              "</dependency></dependencies></project>")
        self.write(
            "app/mq/OrderConsumer.java",
            'package mq;\n@RabbitListener(queues = "order")\npublic class OrderConsumer {}\n',
        )

        self.assertIn(MQ_CONSUMER, self.types(controller_count=0))

    def test_rule_table_dropped_even_when_http_filter_applies(self):
        """规则表判定必须用原始命中数，不能被 HTTP 过滤「洗白」。

        回归用例：下面这行同时写出 8 种框架特征（其中 3 种属 HTTP）。当
        controller_count 已知时 HTTP 特征会被跳过，过滤后只剩 5 个 —— 恰好不满足
        `> 5`，修复前会整表漏网，把项目判成 RPC + MQ。
        """
        self.write("app/user.py", "def get_user(uid):\n    return uid\n")
        patterns = (
            r"@RabbitListener|@KafkaListener|@Scheduled|@XxlJob|@DubboService"
            r"|@GrpcService|@FeignClient|@GetMapping|@RestController|@RequestMapping"
        )
        self.write("tools/signal_table.py", "\n".join(f'SIG_{i} = r"{patterns}"' for i in range(8)))

        self.assertEqual(self.types(controller_count=0), [])

    def test_normal_file_with_few_annotations_is_kept(self):
        """正常生产文件只命中一两个特征，不能被误判成规则表。"""
        self.write(
            "app/mq/OrderConsumer.java",
            'package mq;\n@RabbitListener(queues = "order")\npublic class OrderConsumer {}\n',
        )
        self.write("app/api/OrderApi.java", "package api;\n@RestController\npublic class OrderApi {}\n")

        types = self.types(controller_count=0)
        self.assertIn(MQ_CONSUMER, types)


class OutputShapeTests(_ProjectFixture):
    def test_empty_project_returns_no_hits(self):
        self.assertEqual(detect_archetypes(self.root), [])
        self.assertEqual(primary_archetype([]), None)
        self.assertEqual(format_summary([]), "未识别到明确项目形态")
        self.assertEqual(summarize([]), [])

    def test_hit_serialization_and_ranking(self):
        self.write("requirements.txt", "APScheduler==3.10\ncelery==5.3\n")
        hits = detect_archetypes(self.root)
        self.assertTrue(hits)
        # 按得分降序
        self.assertEqual([h.score for h in hits], sorted([h.score for h in hits], reverse=True))
        payload = hits[0].to_dict()
        self.assertEqual(
            set(payload.keys()),
            {"type", "label", "confidence", "score", "evidence"},
        )
        self.assertEqual(payload["type"], SCHEDULED_JOB)
        self.assertEqual(payload["label"], "定时任务 / 批处理")

    def test_missing_directory_is_safe(self):
        self.assertEqual(detect_archetypes(self.root / "nope"), [])


class ScoreProfileTests(unittest.TestCase):
    def test_empty_hits_produce_inactive_profile(self):
        profile = score_profile([])
        self.assertFalse(profile.active)
        self.assertEqual(profile.describe(), "未识别到明确形态")

    def test_library_profile_lifts_crypto_above_api(self):
        from app.services.project_archetype_service import ArchetypeHit

        profile = score_profile([ArchetypeHit(SDK_LIBRARY, 6, 0.95)])
        self.assertTrue(profile.active)

        crypto = _score_file(Path("crypto/cipher.go"), profile)
        api = _score_file(Path("api/handler.go"), profile)
        self.assertGreater(crypto, api)

        # 不传 profile 时仍是旧的 HTTP 视角
        self.assertLess(_score_file(Path("crypto/cipher.go")), _score_file(Path("api/handler.go")))

    def test_absence_of_http_penalizes_controller_paths(self):
        from app.services.project_archetype_service import ArchetypeHit

        profile = score_profile([ArchetypeHit(MQ_CONSUMER, 6, 0.95)])
        self.assertEqual(profile.negative.get("controllers"), 3)
        penalized = _score_file(Path("controllers/OrderController.java"), profile)
        baseline = _score_file(Path("controllers/OrderController.java"))
        self.assertLess(penalized, baseline)

    def test_http_project_has_no_absence_penalty(self):
        from app.services.project_archetype_service import ArchetypeHit

        profile = score_profile([ArchetypeHit(HTTP_API, 12, 0.95)])
        self.assertEqual(profile.negative, {})
        self.assertIn("api", profile.positive)

    def test_test_penalty_follows_exclude_setting(self):
        from app.services.project_archetype_service import ArchetypeHit

        hits = [ArchetypeHit(SDK_LIBRARY, 6, 0.95)]
        with patch(
            "app.services.project_archetype_service.exclude_test_paths_enabled",
            return_value=True,
        ):
            enabled = score_profile(hits)
        with patch(
            "app.services.project_archetype_service.exclude_test_paths_enabled",
            return_value=False,
        ):
            disabled = score_profile(hits)

        self.assertGreater(enabled.test_penalty, 0)
        self.assertEqual(disabled.test_penalty, 0)
        test_file = Path("tests/test_auth.py")
        self.assertLess(_score_file(test_file, enabled), _score_file(test_file, disabled))


class CollectAuditFilesTests(_ProjectFixture):
    def test_library_project_selects_crypto_not_tests(self):
        self.write(
            "pyproject.toml",
            "[project]\nname = \"demo-sdk\"\nversion = \"1.0.0\"\n",
        )
        for name in ("cipher", "hmac", "signature", "serializer", "deserialize"):
            self.write(f"demo_sdk/crypto/{name}.py", f"def {name}(data):\n    return data\n")
        # 测试文件带 auth/user 关键词，旧打分下会被优先选中
        for i in range(5):
            self.write(f"tests/test_auth_{i}.py", "def test_auth():\n    pass\n")
        self.write("demo_sdk/api/client.py", "def request(url):\n    return url\n")

        selected = collect_audit_files(self.root, max_files=6)
        rel = {p.relative_to(self.root).as_posix() for p in selected}

        self.assertTrue(any("crypto/" in r for r in rel), rel)
        self.assertFalse(any(r.startswith("tests/") for r in rel), rel)

    def test_explicit_empty_archetypes_restores_legacy_scoring(self):
        self.write("pyproject.toml", "[project]\nname = \"demo-sdk\"\nversion = \"1.0.0\"\n")
        self.write("demo_sdk/crypto/cipher.py", "def encrypt():\n    pass\n")
        for i in range(3):
            self.write(f"tests/test_auth_{i}.py", "def test_auth():\n    pass\n")

        # 显式传空列表 == 关闭形态加权，回到旧行为（测试文件仍会被选中）
        selected = collect_audit_files(self.root, max_files=3, archetypes=[])
        rel = [p.relative_to(self.root).as_posix() for p in selected]
        self.assertTrue(any(r.startswith("tests/") for r in rel), rel)

    def test_max_files_is_respected(self):
        for i in range(10):
            self.write(f"src/mod_{i}.py", "x = 1\n")
        self.assertEqual(len(collect_audit_files(self.root, max_files=4)), 4)


if __name__ == "__main__":
    unittest.main()
