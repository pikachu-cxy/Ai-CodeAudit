"""静态识别项目形态（archetype），为 LLM 审计提供「场景先验」。

**为什么需要它**

原有 LLM 审计是**纯 HTTP 端点驱动**的：先 discover 出 Controller / Route，
识别不到 HTTP 路由就降级成「文件采样」，而文件采样打分（`_score_file`）同样偏爱
`api/routes/controllers` 目录和 `auth/user/order` 这类关键词。结果是两类误伤：

1. SDK / 公共库、MQ 消费者、定时任务、RPC 服务这些**本来就没有 HTTP 端点**的项目，
   被判成「无端点」→ 降级 → 采样出来的文件与真正的风险面（加解密、序列化、
   签名校验、反序列化入口）毫不相关。
2. 即使有 HTTP 端点，`tests/test_auth.py` 也会因为文件名含 `auth` 被加权选中
   （`SKIP_DIRS` 不含 test 目录），白白吃掉采样配额。

本模块只做一件事：**用静态证据判断「这个项目是什么形态」**。

- 纯静态：不调 LLM、不碰数据库、不发网络请求
- 多标签：一个项目可以同时是 RPC 服务 + MQ 消费者 + 定时任务
- 可解释：每个形态都带上命中的证据（依赖清单 / 代码特征 / 目录布局）

输出被 `llm_audit_service` 用来给候选文件打分加权（见 `score_profile`）；
后续也可以被端点发现、审计策略派发复用。

**已知取舍**：代码特征只扫源码扩展名，不解析 Spring XML 里的
`<task:scheduled-tasks>` / `<int-kafka:...>`，这类遗留配置依赖清单通常也能兜住。
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from app.services.file_service import SKIP_DIRS
from app.services.path_filters import exclude_test_paths_enabled, is_test_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 形态定义
# ---------------------------------------------------------------------------

HTTP_API = "http_api"
RPC_SERVICE = "rpc_service"
MQ_CONSUMER = "mq_consumer"
SCHEDULED_JOB = "scheduled_job"
CLI_TOOL = "cli_tool"
SDK_LIBRARY = "sdk_library"

ARCHETYPE_LABELS: dict[str, str] = {
    HTTP_API: "HTTP 接口服务",
    RPC_SERVICE: "RPC 服务（gRPC / Dubbo / Thrift）",
    MQ_CONSUMER: "消息队列消费者",
    SCHEDULED_JOB: "定时任务 / 批处理",
    CLI_TOOL: "命令行工具",
    SDK_LIBRARY: "SDK / 公共库",
}

# 识别阈值：满分饱和点与入选最低分。权重设计上「一条依赖」= 3 分，
# 所以单独一条依赖（0.5 置信度）就能入选，但要两条证据才接近满分。
_SATURATION = 6
_MIN_SCORE = 3
_MAX_CONFIDENCE = 0.95
_MAX_EVIDENCE = 3

# 扫描预算：形态识别是「顺路」做的事，不能比审计本身还慢。
_MAX_SCAN_FILES = 400
_MAX_SCAN_BYTES = 6_000_000
_MAX_FILE_READ = 40_000
_MAX_MANIFEST_READ = 60_000
_MAX_MANIFEST_FILES = 12
# 嵌套清单只认到第 3 层（`module/pom.xml` 是多模块 Maven 的常见形态）；
# 再深就是被扫项目里夹带的其它仓库副本，不该影响形态判断。
_MAX_MANIFEST_DEPTH = 3
# 单个文件里同时命中这么多种框架特征，只可能是「规则表 / 文档 / 测试夹具」，
# 不是真实生产代码（本项目自己的 project_archetype_service.py 就是典型例子）。
_MAX_SIGNALS_PER_FILE = 5
# 被扫项目里夹带嵌套仓库副本（`data/repos/<hash>/`、`vendor/`、git submodule）时，
# 这些副本的注解和依赖都不属于本项目。靠深度阈值挡不住——`src/main/java/com/x/...`
# 这种合法路径本身就有 10 层以上，所以改用「祖先目录里存在 .git 即视为独立仓库」这个精确判据。
_GIT_ENTRY = ".git"

_SCAN_EXTENSIONS = {
    ".py", ".java", ".go", ".js", ".ts", ".tsx", ".jsx",
    ".php", ".rb", ".cs", ".kt", ".rs", ".scala", ".vue",
}

_MANIFEST_NAMES = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
)

_CACHE_TTL_SECONDS = 90
_ARCHETYPE_CACHE: dict[str, tuple[float, list["ArchetypeHit"]]] = {}


def _cache_get(key: str) -> list["ArchetypeHit"] | None:
    entry = _ARCHETYPE_CACHE.get(key)
    if not entry:
        return None
    expires_at, value = entry
    if expires_at < time.time():
        _ARCHETYPE_CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: list["ArchetypeHit"]) -> list["ArchetypeHit"]:
    _ARCHETYPE_CACHE[key] = (time.time() + _CACHE_TTL_SECONDS, value)
    return value


def clear_archetype_cache() -> None:
    """清空形态识别缓存。

    同一路径可能被复测复用（重新 clone 后目录内容已变），TTL 内的旧结论不能信；
    扫描入口会先清一次。
    """
    _ARCHETYPE_CACHE.clear()


@dataclass
class ArchetypeHit:
    """一个被识别出来的项目形态。"""

    type: str
    score: int
    confidence: float
    evidence: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return ARCHETYPE_LABELS.get(self.type, self.type)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "label": self.label,
            "confidence": round(self.confidence, 2),
            "score": self.score,
            "evidence": list(self.evidence),
        }


# ---------------------------------------------------------------------------
# 信号表
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DepSignal:
    """依赖清单里的包名信号。`needle` 对清单全文做小写子串匹配。"""

    archetype: str
    weight: int
    label: str
    needle: str


@dataclass(frozen=True)
class _CodeSignal:
    """源码特征信号（注解 / 装饰器 / 框架 API 调用）。"""

    archetype: str
    weight: int
    label: str
    pattern: re.Pattern[str]


def _sig(archetype: str, weight: int, label: str, needle: str) -> _DepSignal:
    return _DepSignal(archetype, weight, label, needle.lower())


_DEP_SIGNALS: tuple[_DepSignal, ...] = (
    # ---- MQ 消费者 -------------------------------------------------------
    _sig(MQ_CONSUMER, 3, "spring-kafka", "spring-kafka"),
    _sig(MQ_CONSUMER, 3, "kafka-clients", "kafka-clients"),
    _sig(MQ_CONSUMER, 3, "spring-rabbit", "spring-rabbit"),
    _sig(MQ_CONSUMER, 3, "amqp-client", "amqp-client"),
    _sig(MQ_CONSUMER, 3, "rocketmq", "rocketmq"),
    _sig(MQ_CONSUMER, 3, "spring-cloud-stream", "spring-cloud-stream"),
    _sig(MQ_CONSUMER, 3, "pulsar-client", "pulsar-client"),
    _sig(MQ_CONSUMER, 3, "spring-boot-starter-amqp", "spring-boot-starter-amqp"),
    _sig(MQ_CONSUMER, 3, "kafka-python", "kafka-python"),
    _sig(MQ_CONSUMER, 3, "confluent-kafka", "confluent-kafka"),
    _sig(MQ_CONSUMER, 3, "aiokafka", "aiokafka"),
    _sig(MQ_CONSUMER, 3, "aio-pika", "aio-pika"),
    _sig(MQ_CONSUMER, 3, "pika", "pika=="),
    _sig(MQ_CONSUMER, 3, "kombu", "kombu"),
    _sig(MQ_CONSUMER, 3, "kafkajs", "kafkajs"),
    _sig(MQ_CONSUMER, 3, "amqplib", "amqplib"),
    _sig(MQ_CONSUMER, 3, "@nestjs/microservices", "@nestjs/microservices"),
    _sig(MQ_CONSUMER, 3, "bullmq", "bullmq"),
    _sig(MQ_CONSUMER, 3, "segmentio/kafka-go", "segmentio/kafka-go"),
    _sig(MQ_CONSUMER, 3, "shopify/sarama", "shopify/sarama"),
    _sig(MQ_CONSUMER, 3, "rabbitmq/amqp091-go", "rabbitmq/amqp091-go"),
    _sig(MQ_CONSUMER, 3, "nsqio/go-nsq", "nsqio/go-nsq"),
    # ---- 定时任务 / 批处理 -----------------------------------------------
    _sig(SCHEDULED_JOB, 3, "spring-boot-starter-quartz", "spring-boot-starter-quartz"),
    _sig(SCHEDULED_JOB, 3, "quartz", "quartz"),
    _sig(SCHEDULED_JOB, 3, "xxl-job", "xxl-job"),
    _sig(SCHEDULED_JOB, 3, "elastic-job", "elastic-job"),
    _sig(SCHEDULED_JOB, 3, "shedlock", "shedlock"),
    _sig(SCHEDULED_JOB, 3, "spring-batch", "spring-batch"),
    _sig(SCHEDULED_JOB, 3, "apscheduler", "apscheduler"),
    _sig(SCHEDULED_JOB, 3, "celery", "celery"),
    _sig(SCHEDULED_JOB, 3, "django-celery-beat", "django-celery-beat"),
    _sig(SCHEDULED_JOB, 3, "apache-airflow", "apache-airflow"),
    _sig(SCHEDULED_JOB, 3, "prefect", "prefect"),
    _sig(SCHEDULED_JOB, 3, "dagster", "dagster"),
    _sig(SCHEDULED_JOB, 3, "node-cron", "node-cron"),
    _sig(SCHEDULED_JOB, 3, "node-schedule", "node-schedule"),
    _sig(SCHEDULED_JOB, 3, "agenda", '"agenda"'),
    _sig(SCHEDULED_JOB, 3, "@nestjs/schedule", "@nestjs/schedule"),
    _sig(SCHEDULED_JOB, 3, "robfig/cron", "robfig/cron"),
    _sig(SCHEDULED_JOB, 3, "go-co-op/gocron", "go-co-op/gocron"),
    _sig(SCHEDULED_JOB, 3, "hibiken/asynq", "hibiken/asynq"),
    # ---- RPC -------------------------------------------------------------
    _sig(RPC_SERVICE, 3, "dubbo", "dubbo"),
    _sig(RPC_SERVICE, 3, "grpc-netty", "grpc-netty"),
    _sig(RPC_SERVICE, 3, "grpc-spring-boot-starter", "grpc-spring-boot-starter"),
    _sig(RPC_SERVICE, 3, "spring-cloud-starter-openfeign", "spring-cloud-starter-openfeign"),
    _sig(RPC_SERVICE, 3, "thrift", "thrift"),
    _sig(RPC_SERVICE, 3, "sofa-rpc", "sofa-rpc"),
    _sig(RPC_SERVICE, 3, "grpcio", "grpcio"),
    _sig(RPC_SERVICE, 3, "nameko", "nameko"),
    _sig(RPC_SERVICE, 3, "google.golang.org/grpc", "google.golang.org/grpc"),
    _sig(RPC_SERVICE, 3, "cloudwego/kitex", "cloudwego/kitex"),
    _sig(RPC_SERVICE, 3, "apache/dubbo-go", "apache/dubbo-go"),
    _sig(RPC_SERVICE, 3, "@grpc/grpc-js", "@grpc/grpc-js"),
    # ---- 命令行工具 ------------------------------------------------------
    _sig(CLI_TOOL, 3, "picocli", "picocli"),
    _sig(CLI_TOOL, 3, "commons-cli", "commons-cli"),
    _sig(CLI_TOOL, 3, "click", "click=="),
    _sig(CLI_TOOL, 3, "typer", "typer"),
    _sig(CLI_TOOL, 3, "python-fire", "fire=="),
    _sig(CLI_TOOL, 3, "commander", '"commander"'),
    _sig(CLI_TOOL, 3, "yargs", '"yargs"'),
    _sig(CLI_TOOL, 3, "oclif", "oclif"),
    _sig(CLI_TOOL, 3, "spf13/cobra", "spf13/cobra"),
    _sig(CLI_TOOL, 3, "urfave/cli", "urfave/cli"),
)

_CODE_SIGNALS: tuple[_CodeSignal, ...] = (
    # ---- HTTP 接口（仅在未提供 controller_count 时作为兜底）--------------
    _CodeSignal(HTTP_API, 3, "@RestController", re.compile(r"@RestController\b")),
    _CodeSignal(HTTP_API, 3, "@RequestMapping", re.compile(r"@RequestMapping\b")),
    _CodeSignal(HTTP_API, 3, "@GetMapping/@PostMapping", re.compile(r"@(?:Get|Post|Put|Delete|Patch)Mapping\b")),
    _CodeSignal(HTTP_API, 3, "Flask/FastAPI 路由装饰器", re.compile(r"@\w+\.(?:route|get|post|put|delete|patch)\s*\(")),
    _CodeSignal(HTTP_API, 3, "@Controller（NestJS）", re.compile(r"@Controller\s*\(")),
    _CodeSignal(HTTP_API, 2, "Express/Koa 路由注册", re.compile(r"\b(?:app|router|r)\.(?:get|post|put|delete|patch)\s*\(")),
    _CodeSignal(HTTP_API, 2, "FastAPI()", re.compile(r"\bFastAPI\s*\(")),
    # ---- MQ 消费者 -------------------------------------------------------
    _CodeSignal(MQ_CONSUMER, 3, "@KafkaListener", re.compile(r"@KafkaListener\b")),
    _CodeSignal(MQ_CONSUMER, 3, "@RabbitListener", re.compile(r"@RabbitListener\b")),
    _CodeSignal(MQ_CONSUMER, 3, "@RocketMQMessageListener", re.compile(r"@RocketMQMessageListener\b")),
    _CodeSignal(MQ_CONSUMER, 3, "@JmsListener", re.compile(r"@JmsListener\b")),
    _CodeSignal(MQ_CONSUMER, 3, "@SqsListener", re.compile(r"@SqsListener\b")),
    _CodeSignal(MQ_CONSUMER, 2, "@StreamListener", re.compile(r"@StreamListener\b")),
    _CodeSignal(MQ_CONSUMER, 2, "implements MessageListener", re.compile(r"implements\s+[\w.]*MessageListener\b")),
    _CodeSignal(MQ_CONSUMER, 3, "Celery 任务装饰器", re.compile(r"@(?:shared_task|app\.task|celery\.task)\b")),
    _CodeSignal(MQ_CONSUMER, 3, "Celery()", re.compile(r"\bCelery\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "KafkaConsumer(", re.compile(r"\bKafkaConsumer\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "pika 消费循环", re.compile(r"basic_consume\s*\(|\bBlockingConnection\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "@MessagePattern（NestJS）", re.compile(r"@MessagePattern\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "@EventPattern（NestJS）", re.compile(r"@EventPattern\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "kafkajs consumer", re.compile(r"consumer\.subscribe\s*\(|new\s+Kafka\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "amqplib 消费", re.compile(r"channel\.consume\s*\(|amqp\.connect\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "kafka-go NewReader", re.compile(r"kafka\.NewReader\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "sarama NewConsumer", re.compile(r"sarama\.NewConsumer\w*\s*\(")),
    _CodeSignal(MQ_CONSUMER, 3, "amqp.Dial", re.compile(r"\bamqp\.Dial\w*\s*\(")),
    # ---- 定时任务 / 批处理 -----------------------------------------------
    _CodeSignal(SCHEDULED_JOB, 3, "@Scheduled", re.compile(r"@Scheduled\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "@XxlJob", re.compile(r"@XxlJob\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 2, "@EnableScheduling", re.compile(r"@EnableScheduling\b")),
    _CodeSignal(SCHEDULED_JOB, 3, "QuartzJobBean", re.compile(r"extends\s+\w*QuartzJobBean\b")),
    _CodeSignal(SCHEDULED_JOB, 3, "celery beat crontab", re.compile(r"\bcrontab\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "@periodic_task", re.compile(r"@periodic_task\b")),
    _CodeSignal(SCHEDULED_JOB, 3, "BackgroundScheduler/BlockingScheduler", re.compile(r"\b(?:Background|Blocking)Scheduler\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "schedule.every()", re.compile(r"\bschedule\.every\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "@Cron（NestJS）", re.compile(r"@Cron\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "new CronJob(", re.compile(r"new\s+CronJob\s*\(|cron\.schedule\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "agenda.define(", re.compile(r"agenda\.define\s*\(")),
    _CodeSignal(SCHEDULED_JOB, 3, "cron.New()", re.compile(r"\bcron\.New\s*\(")),
    # ---- RPC -------------------------------------------------------------
    _CodeSignal(RPC_SERVICE, 3, "@DubboService", re.compile(r"@DubboService\b")),
    _CodeSignal(RPC_SERVICE, 3, "@DubboReference", re.compile(r"@DubboReference\b")),
    _CodeSignal(RPC_SERVICE, 3, "@GrpcService", re.compile(r"@GrpcService\b")),
    _CodeSignal(RPC_SERVICE, 3, "@FeignClient", re.compile(r"@FeignClient\b")),
    _CodeSignal(RPC_SERVICE, 3, "gRPC ImplBase", re.compile(r"extends\s+\w*ImplBase\b")),
    _CodeSignal(RPC_SERVICE, 2, "BindableService", re.compile(r"\bBindableService\b")),
    _CodeSignal(RPC_SERVICE, 3, "add_*Servicer_to_server", re.compile(r"add_\w+Servicer_to_server\s*\(")),
    _CodeSignal(RPC_SERVICE, 3, "grpc.server(", re.compile(r"\bgrpc\.server\s*\(")),
    _CodeSignal(RPC_SERVICE, 3, "grpc.NewServer(", re.compile(r"\bgrpc\.NewServer\s*\(")),
    _CodeSignal(RPC_SERVICE, 3, "Register*Server(", re.compile(r"\bRegister\w*Server\s*\(")),
    _CodeSignal(RPC_SERVICE, 3, "@GrpcMethod（NestJS）", re.compile(r"@GrpcMethod\s*\(")),
    # ---- 命令行工具 ------------------------------------------------------
    _CodeSignal(CLI_TOOL, 3, "argparse.ArgumentParser", re.compile(r"\bArgumentParser\s*\(")),
    _CodeSignal(CLI_TOOL, 3, "@click.command / @click.group", re.compile(r"@click\.(?:command|group)\b")),
    _CodeSignal(CLI_TOOL, 3, "typer.Typer()", re.compile(r"\bTyper\s*\(")),
    _CodeSignal(CLI_TOOL, 3, "picocli @Command", re.compile(r"@CommandLine\.Command\b")),
    _CodeSignal(CLI_TOOL, 3, "cobra.Command{", re.compile(r"cobra\.Command\s*\{")),
    _CodeSignal(CLI_TOOL, 2, "flag.Parse()", re.compile(r"\bflag\.Parse\s*\(")),
    _CodeSignal(CLI_TOOL, 3, "yargs/commander program", re.compile(r"\byargs\s*\(|\.command\s*\(\s*[\"']\w")),
    _CodeSignal(CLI_TOOL, 2, "node shebang", re.compile(r"^#!.*\bnode\b", re.MULTILINE)),
    _CodeSignal(CLI_TOOL, 2, "python shebang", re.compile(r"^#!.*\bpython[0-9.]*\b", re.MULTILINE)),
)

# 目录名信号：强信号（2 分）足以独立表达形态，弱信号（1 分）只是佐证。
_STRONG_LAYOUT_DIRS: dict[str, tuple[str, ...]] = {
    MQ_CONSUMER: ("consumer", "consumers", "listener", "listeners", "subscriber", "subscribers", "mq"),
    SCHEDULED_JOB: ("job", "jobs", "scheduler", "schedulers", "cron", "batch", "worker", "workers"),
    RPC_SERVICE: ("rpc", "grpc", "dubbo", "thrift", "proto", "protos", "idl"),
    CLI_TOOL: ("cmd", "cli", "commands"),
    HTTP_API: ("controller", "controllers", "routes", "routers", "handlers", "views", "middleware"),
}

_WEAK_LAYOUT_DIRS: dict[str, tuple[str, ...]] = {
    SDK_LIBRARY: ("lib", "libs", "sdk", "core", "pkg", "internal", "common", "utils", "util"),
    MQ_CONSUMER: ("kafka", "rabbitmq", "rocketmq", "amqp", "queue", "queues"),
    SCHEDULED_JOB: ("task", "tasks", "crontab"),
}

# 可执行入口：有入口就不太可能是「被别的服务调用的库」。
_ENTRY_POINT_RE = re.compile(
    r"__name__\s*==\s*[\"']__main__[\"']"      # Python
    r"|\bpackage\s+main\b"                      # Go
    r"|func\s+main\s*\(\s*\)"                   # Go
    r"|\bfn\s+main\s*\(\s*\)"                   # Rust
    r"|static\s+void\s+main\s*\("               # Java / C#
    r"|\bint\s+main\s*\("                       # C / C++
    r"|\buvicorn\.run\s*\(|\bapp\.run\s*\(",    # 常见 Web 启动写法
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# 打分加权：把形态翻译成「路径关键词权重」
# ---------------------------------------------------------------------------

# 库/组件项目的风险面集中在「加解密、序列化、签名、网络、文件」这些**基础能力**上，
# 而不是 `api/routes/`。下面这些权重就是为了把 `crypto/cipher.go` 抬到
# `api/handler.go` 之上。
_ARCHETYPE_PATH_WEIGHTS: dict[str, dict[str, int]] = {
    SDK_LIBRARY: {
        "crypto": 5, "cipher": 5, "encrypt": 5, "decrypt": 5, "hmac": 4,
        "signature": 4, "sign": 4, "hash": 3, "digest": 3, "key": 3,
        "secret": 4, "credential": 4, "password": 4, "token": 3,
        "deserialize": 5, "unserialize": 5, "pickle": 4, "marshal": 3,
        "serializer": 4, "serialization": 4, "codec": 4, "encoder": 3, "decoder": 3,
        "oauth": 3, "jwt": 3, "acl": 3, "policy": 3, "permission": 3,
        "protocol": 3, "transport": 3, "socket": 3, "net": 2, "tls": 4,
        "url": 3, "uri": 2, "redirect": 3, "path": 3, "archive": 3,
        "zip": 3, "tar": 3, "xml": 3, "yaml": 3, "template": 3,
        "sql": 3, "query": 3, "command": 3, "exec": 4, "process": 3,
        "random": 3, "temp": 3, "client": 3, "connection": 3, "pool": 2,
        "core": 3, "wrapper": 2, "adapter": 2, "provider": 2, "manager": 2,
        "util": 2, "helper": 2, "common": 2, "config": 2, "option": 2,
    },
    RPC_SERVICE: {
        "service": 3, "impl": 3, "handler": 3, "endpoint": 3, "servicer": 4,
        "provider": 3, "consumer": 3, "stub": 3, "idl": 3, "proto": 3,
        "grpc": 4, "dubbo": 4, "thrift": 4, "feign": 4, "interceptor": 3,
        "filter": 3, "serializer": 3, "codec": 3, "auth": 3, "token": 3,
        "permission": 3, "user": 2, "order": 2, "account": 2, "transfer": 2,
        "deserialize": 4, "request": 2, "response": 2, "invoke": 3, "proxy": 2,
    },
    MQ_CONSUMER: {
        "consumer": 5, "listener": 5, "subscriber": 4, "handler": 3,
        "message": 3, "msg": 2, "queue": 3, "topic": 3, "channel": 3,
        "dispatch": 3, "callback": 3, "retry": 3, "idempot": 4, "dedup": 3,
        "kafka": 4, "rabbit": 4, "rocketmq": 4, "amqp": 4, "mq": 3,
        "event": 3, "payload": 3, "deserialize": 4, "unmarshal": 3,
        "serializer": 3, "order": 2, "payment": 2, "transfer": 2, "coupon": 2,
        "auth": 2, "user": 2, "sign": 3, "verify": 3, "validate": 3,
    },
    SCHEDULED_JOB: {
        "job": 5, "task": 4, "scheduler": 5, "cron": 5, "batch": 4,
        "worker": 3, "process": 3, "executor": 3, "retry": 3, "lock": 3,
        "distribut": 3, "compensat": 3, "reconcile": 3, "settle": 3,
        "sync": 3, "import": 3, "export": 3, "report": 3, "statistic": 3,
        "order": 2, "payment": 2, "transfer": 2, "refund": 2, "coupon": 2,
        "account": 2, "balance": 3, "amount": 3, "user": 2, "auth": 2,
        "config": 2, "sql": 2, "dao": 2, "mapper": 2, "repository": 2,
    },
    CLI_TOOL: {
        "command": 4, "cli": 4, "cmd": 3, "arg": 3, "option": 3, "flag": 3,
        "console": 3, "shell": 3, "exec": 4, "subprocess": 4, "process": 3,
        "path": 3, "file": 3, "io": 2, "config": 3, "env": 3, "credential": 3,
        "token": 3, "secret": 3, "install": 3, "deploy": 3, "template": 3,
        "download": 3, "upload": 3, "url": 3, "registry": 3, "cache": 2,
    },
    HTTP_API: {
        "controller": 4, "route": 4, "router": 4, "api": 3, "handler": 3,
        "endpoint": 3, "middleware": 3, "filter": 3, "interceptor": 3,
        "auth": 3, "login": 3, "permission": 3, "role": 3, "admin": 3,
        "token": 3, "session": 3, "user": 3, "account": 3, "order": 3,
        "payment": 3, "transfer": 3, "upload": 3, "download": 3, "file": 2,
    },
}

# 形态「缺席」时的降权：项目不是 HTTP 服务，`api/routes/controllers` 这类
# 目录就不该继续吃 +3 的基线权重。
_ARCHETYPE_ABSENCE_PENALTIES: dict[str, dict[str, int]] = {
    HTTP_API: {
        "controllers": 3, "controller": 3, "routes": 3, "router": 3,
        "handlers": 2, "handler": 2, "views": 2, "middleware": 2, "api": 2,
    },
}

# 测试代码降权：只在 `exclude_test_paths` 打开时生效（与全局扫描口径一致）。
_TEST_PATH_PENALTY = 6


@dataclass(frozen=True)
class ArchetypeScoreProfile:
    """由形态推导出的文件打分权重。`positive` 加权，`negative` 降权。"""

    archetypes: tuple[str, ...] = ()
    positive: dict[str, int] = field(default_factory=dict)
    negative: dict[str, int] = field(default_factory=dict)
    test_penalty: int = 0

    @property
    def active(self) -> bool:
        """是否含有任何会改变打分的项。"""
        return bool(self.positive or self.negative or self.test_penalty)

    def describe(self) -> str:
        if not self.archetypes:
            return "未识别到明确形态"
        return "、".join(ARCHETYPE_LABELS.get(t, t) for t in self.archetypes)


def score_profile(hits: list[ArchetypeHit] | None) -> ArchetypeScoreProfile:
    """把形态命中翻译成文件打分权重。

    同一关键词命中多个形态时取最大权重（而不是累加），避免多标签项目里
    一个 `consumer` 目录把权重堆到失真。
    """
    if not hits:
        return ArchetypeScoreProfile()

    types = tuple(hit.type for hit in hits)
    positive: dict[str, int] = {}
    for archetype in types:
        for kw, weight in _ARCHETYPE_PATH_WEIGHTS.get(archetype, {}).items():
            if weight > positive.get(kw, 0):
                positive[kw] = weight

    negative: dict[str, int] = {}
    for archetype, penalties in _ARCHETYPE_ABSENCE_PENALTIES.items():
        if archetype in types:
            continue
        for kw, weight in penalties.items():
            if weight > negative.get(kw, 0):
                negative[kw] = weight

    return ArchetypeScoreProfile(
        archetypes=types,
        positive=positive,
        negative=negative,
        test_penalty=_TEST_PATH_PENALTY if exclude_test_paths_enabled() else 0,
    )


def summarize(hits: list[ArchetypeHit]) -> list[dict]:
    """给审计日志 / 前端用的精简结构。"""
    return [hit.to_dict() for hit in hits]


# ---------------------------------------------------------------------------
# 识别主体
# ---------------------------------------------------------------------------


def _read_manifests(root: Path) -> dict[str, str]:
    """读根目录下的依赖清单（多模块项目里嵌套清单由代码遍历顺手补上）。"""
    manifests: dict[str, str] = {}
    for name in _MANIFEST_NAMES:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if text.strip():
            manifests[name] = text[:_MAX_MANIFEST_READ]
    return manifests


def _library_evidence(manifests: dict[str, str]) -> list[tuple[str, int]]:
    """发行/打包元数据 —— 说明这个项目是「给别人用的」，不是「自己跑的服务」。

    返回 `(证据描述, 权重)`。强证据（发行到仓库 / 导出 API）权重 3，
    弱证据（只是有模块声明）权重 1 —— 后者单独不足以入选形态。
    """
    out: list[tuple[str, int]] = []
    pyproject = manifests.get("pyproject.toml", "")
    if pyproject and "[project]" in pyproject:
        out.append(("pyproject.toml: [project] 发行元数据", 3))
    setup_py = manifests.get("setup.py", "")
    if setup_py and re.search(r"packages\s*=", setup_py):
        out.append(("setup.py: packages= 发行元数据", 3))
    # maven-source / gpg 插件是「发布到仓库」的强证据，子模块里出现也算
    for key, text in manifests.items():
        if key.endswith("pom.xml") and ("maven-source-plugin" in text or "maven-gpg-plugin" in text):
            out.append((f"{key}: maven-source/gpg 插件（发布到仓库）", 3))
            break
    else:
        # 根 pom 打成纯 jar（且没有 spring-boot 插件）→ 不是可执行服务
        root_pom = manifests.get("pom.xml", "")
        if re.search(r"<packaging>\s*(?:jar|aar)\s*</packaging>", root_pom) and "spring-boot-maven-plugin" not in root_pom:
            out.append(("pom.xml: 纯 jar 打包（无 spring-boot 插件）", 3))
    pkg = manifests.get("package.json", "")
    if pkg:
        has_entry = re.search(r'"(?:main|exports|types|module)"\s*:', pkg)
        has_start = re.search(r'"start"\s*:', pkg)
        if has_entry and not has_start:
            out.append(("package.json: main/exports 导出但无 start 脚本", 3))
    if manifests.get("go.mod"):
        # go.mod 只说明是 Go module，可执行程序也有 —— 弱证据
        out.append(("go.mod: 模块声明（Go module）", 1))
    if manifests.get("Cargo.toml"):
        out.append(("Cargo.toml: crate 定义", 1))
    return out


def _make_nested_repo_checker(root: Path):
    """返回一个判断「文件是否位于嵌套仓库内」的函数。

    判据：从文件所在目录逐级向上找，只要某一层（不含项目根）存在 `.git`，就认为该文件
    属于被扫项目夹带的另一个仓库，其注解 / 依赖不参与本项目形态判断。`.git` 既可能是
    目录（普通 clone），也可能是文件（submodule / worktree 的 gitfile），故用 exists()。

    探测结果按目录前缀缓存：同一个目录下的文件只 stat 一次，实测开销可忽略。
    """
    cache: dict[tuple[str, ...], bool] = {}

    def is_nested(rel: Path) -> bool:
        parts = rel.parts
        for depth in range(len(parts) - 1, 0, -1):
            prefix = parts[:depth]
            hit = cache.get(prefix)
            if hit is None:
                try:
                    hit = root.joinpath(*prefix, _GIT_ENTRY).exists()
                except OSError:  # pragma: no cover - 路径异常时按非嵌套处理
                    hit = False
                cache[prefix] = hit
            if hit:
                return True
        return False

    return is_nested


def detect_archetypes(
    project_path: Path,
    *,
    controller_count: int | None = None,
    max_files: int = _MAX_SCAN_FILES,
    max_total_bytes: int = _MAX_SCAN_BYTES,
) -> list[ArchetypeHit]:
    """识别项目形态，按可信度从高到低返回。

    Args:
        project_path: 项目根目录。
        controller_count: 已发现的 HTTP 端点/控制器数量。**传了就以它为准**
            （端点发现服务的结果比正则更可靠），为 0 时不再用正则兜底判断 HTTP 形态；
            传 None 则退化为纯正则判断。
    """
    root = Path(project_path)
    if not root.is_dir():
        return []

    try:
        cache_key = f"{root.resolve()}::{controller_count}::{max_files}::{max_total_bytes}"
    except OSError:  # pragma: no cover - 路径不可解析时退化为不缓存
        cache_key = f"{root}::{controller_count}"

    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    scores: dict[str, int] = defaultdict(int)
    evidence: dict[str, list[str]] = defaultdict(list)

    def add(archetype: str, weight: int, note: str) -> None:
        if not weight:
            return
        scores[archetype] += weight
        if weight > 0 and note and note not in evidence[archetype]:
            if len(evidence[archetype]) < _MAX_EVIDENCE:
                evidence[archetype].append(note)

    # --- 1) 依赖清单 ---------------------------------------------------
    manifests = _read_manifests(root)
    manifest_blobs = {name: text.lower() for name, text in manifests.items()}
    for name, blob in manifest_blobs.items():
        for sig in _DEP_SIGNALS:
            if sig.needle in blob:
                add(sig.archetype, sig.weight, f"{name}: {sig.label}")

    # --- 2) 源码特征 + 目录布局 ----------------------------------------
    has_entry_point = False
    layout_dirs: set[str] = set()
    scanned_files = 0
    scanned_bytes = 0
    skip_http_regex = controller_count is not None
    is_nested_repo = _make_nested_repo_checker(root)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue

        rel = path.relative_to(root)
        # 夹带的嵌套仓库整体剔除：它的注解、依赖、目录都不代表本项目是什么形态。
        if is_nested_repo(rel):
            continue

        # 目录布局（只看前 3 层，避免 `src/main/java/com/foo/...` 把包名当目录）
        for part in rel.parts[:-1][:3]:
            layout_dirs.add(part.lower())

        name = path.name
        if name in _MANIFEST_NAMES:
            # 嵌套清单（多模块 Maven / monorepo）按相对路径作 key，避免子模块 pom
            # 被根 pom「占位」后整批丢掉 —— 依赖其实常常声明在子模块里。
            key = rel.as_posix()
            if (
                key not in manifests
                and len(manifests) < _MAX_MANIFEST_FILES
                and len(rel.parts) <= _MAX_MANIFEST_DEPTH
            ):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                if text.strip():
                    manifests[key] = text[:_MAX_MANIFEST_READ]
                    blob = text[:_MAX_MANIFEST_READ].lower()
                    for sig in _DEP_SIGNALS:
                        if sig.needle in blob:
                            add(sig.archetype, sig.weight, f"{key}: {sig.label}")
            continue

        if path.suffix.lower() not in _SCAN_EXTENSIONS:
            continue
        if is_test_path(rel):
            continue
        if scanned_files >= max_files or scanned_bytes >= max_total_bytes:
            continue

        try:
            raw = path.read_text(encoding="utf-8", errors="replace")[:_MAX_FILE_READ]
        except OSError:
            continue
        scanned_files += 1
        scanned_bytes += len(raw)

        if not has_entry_point and _ENTRY_POINT_RE.search(raw):
            has_entry_point = True

        matched: list[_CodeSignal] = []
        raw_hits = 0
        for sig in _CODE_SIGNALS:
            if not sig.pattern.search(raw):
                continue
            # 「像不像规则表」要用**原始命中数**判断。HTTP 过滤是为了让端点发现结果说了算，
            # 跟规则表判定无关；若拿过滤后的数去比阈值，一个同时写了 HTTP 与 MQ 注解的
            # 小规则表就会正好卡在阈值上漏网（实测：原始命中 8、过滤后仅剩 5，5 > 5 为假）。
            raw_hits += 1
            if skip_http_regex and sig.archetype == HTTP_API:
                continue
            matched.append(sig)

        if raw_hits > _MAX_SIGNALS_PER_FILE:
            logger.debug("形态识别跳过疑似规则表文件: %s（命中 %d 个特征）", rel, raw_hits)
            continue

        for sig in matched:
            add(sig.archetype, sig.weight, f"{rel.as_posix()}: {sig.label}")

    for archetype, dirs in _STRONG_LAYOUT_DIRS.items():
        if skip_http_regex and archetype == HTTP_API:
            continue
        for d in dirs:
            if d in layout_dirs:
                add(archetype, 2, f"目录 {d}/")
                break

    for archetype, dirs in _WEAK_LAYOUT_DIRS.items():
        for d in dirs:
            if d in layout_dirs:
                add(archetype, 1, f"目录 {d}/")
                break

    # --- 3) 结构推断 ---------------------------------------------------
    if controller_count is not None:
        if controller_count > 0:
            add(HTTP_API, 3 + min(controller_count, 9), f"端点发现识别到 {controller_count} 个 HTTP 端点")
        else:
            scores[HTTP_API] = 0  # 明确否定，避免正则误报把库项目判成 HTTP 服务

    lib_evidence = _library_evidence(manifests)
    if lib_evidence:
        # 有可执行入口的项目通常是「应用」，库属性只是兼职：不再叠加下面的无入口加分，
        # 得分停在 3（置信度 0.5），与纯库项目（5 分 / 0.83）拉开差距。
        strongest = max(lib_evidence, key=lambda item: item[1])
        add(SDK_LIBRARY, strongest[1], strongest[0])
        for note, _weight in lib_evidence[1:2]:
            add(SDK_LIBRARY, 1, note)

        # 「没有入口」只有在确实有发行元数据时才算证据，否则任何前端项目都会因为
        # 有个 `src/lib/` 目录被误判成公共库。
        if not has_entry_point and not controller_count:
            add(SDK_LIBRARY, 2, "未发现可执行入口（main / __main__ / 服务启动）")

    # --- 4) 汇总 -------------------------------------------------------
    hits = [
        ArchetypeHit(
            type=archetype,
            score=score,
            confidence=min(_MAX_CONFIDENCE, score / _SATURATION),
            evidence=evidence.get(archetype, []),
        )
        for archetype, score in scores.items()
        if score >= _MIN_SCORE
    ]
    hits.sort(key=lambda h: (-h.score, h.type))

    logger.info(
        "项目形态识别完成 path=%s controller_count=%s hits=%s",
        root,
        controller_count,
        [(h.type, h.score) for h in hits],
    )
    return _cache_set(cache_key, hits)


def primary_archetype(hits: list[ArchetypeHit]) -> str | None:
    """得分最高的形态（并列时按 `detect_archetypes` 的稳定排序取第一个）。"""
    return hits[0].type if hits else None


def format_summary(hits: list[ArchetypeHit]) -> str:
    """一行中文摘要，用于审计日志。"""
    if not hits:
        return "未识别到明确项目形态"
    return "、".join(f"{h.label}({h.confidence:.0%})" for h in hits)
