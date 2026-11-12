"""形态专属审计视角（archetype lens）—— 给「没有 / 不只是 HTTP 端点」的项目一套场景思路。

**解决什么问题**

`project_archetype_service` 解决了「采样选对文件」，但**提示词还是 HTTP 味的**：
`BUSINESS_LOGIC_PROMPT` 的 JSON schema 里 `api_endpoint` 写着「HTTP 方法与路径
（如 GET /api/order/{id}）」，对一个 MQ 消费者来说是纯噪声，模型只能硬编一个
HTTP 路径，或者干脆不报。

更关键的是**入口面错位**：端点驱动审计从 Controller 出发，`member-service` 这类
「有 Controller、也有 RabbitMQ 消费者」的项目，MQ 消费逻辑根本不在 Controller 的
调用链上，所以那部分代码**永远不会被审到** —— 除非专门从 topic 出发去审。

本模块提供两样东西：
1. **每个形态一套风险清单**（`LensSpec.risk_focus`）→ 拼成该形态专属的审计提示词
2. **每个形态的入口面定位规则**（`path_keywords` + `code_patterns`）→
   直接从 topic / 任务名 / RPC 服务 / 公开 API / 子命令这些入口面找代码，
   不依赖 HTTP Controller

消费方是 `llm_audit_service.run_archetype_lens_audit()`。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from app.services.file_service import SKIP_DIRS
from app.services.path_filters import is_test_path
from app.services.project_archetype_service import (
    CLI_TOOL,
    MQ_CONSUMER,
    RPC_SERVICE,
    SCHEDULED_JOB,
    SDK_LIBRARY,
    ArchetypeHit,
    ARCHETYPE_LABELS,
)

logger = logging.getLogger(__name__)

# 有专属视角的形态。http_api 不走这里（它本来就有端点驱动审计）。
LENS_ARCHETYPES: tuple[str, ...] = (
    MQ_CONSUMER,
    SCHEDULED_JOB,
    RPC_SERVICE,
    SDK_LIBRARY,
    CLI_TOOL,
)

_LENS_EXTENSIONS = {
    ".py", ".java", ".go", ".js", ".ts", ".tsx", ".jsx",
    ".php", ".rb", ".cs", ".kt", ".rs", ".scala",
}

# 入口面定位的扫描预算
_LENS_SCAN_FILES = 600
_LENS_FILE_READ = 60_000
_LENS_MAX_FILE_BYTES = 200_000


@dataclass(frozen=True)
class LensSpec:
    """一个形态的审计视角：风险清单 + 入口面定位规则。"""

    archetype: str
    label: str
    risk_focus: tuple[str, ...]
    path_keywords: tuple[str, ...]
    code_patterns: tuple[re.Pattern[str], ...]


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


ARCHETYPE_LENSES: dict[str, LensSpec] = {
    MQ_CONSUMER: LensSpec(
        archetype=MQ_CONSUMER,
        label="消息队列消费者视角",
        risk_focus=(
            "消息体不可信：直接信任消息里的 userId / tenantId / role / amount 去做鉴权判断或写库",
            "消费端越权：用消息里的资源 ID 直接查改数据，不校验归属与租户",
            "缺少幂等：重复投递 / 重复消费导致重复扣款、重复发券、重复发货",
            "重放：消息无时间戳 / nonce / 签名校验，旧消息可被重放",
            "反序列化：对消息体做 pickle / yaml.load / ObjectInputStream / Hessian 反序列化",
            "消息驱动的任意操作：消息里的「操作类型」字符串直接映射到 service 方法，可调任意方法",
            "确认与事务顺序：先 ack 再处理、先提交再回滚、异常被吞导致消息丢失",
            "重试放大：失败无限重试、无退避、无死信上限",
            "凭据硬编码：连接串 / 密钥写死在代码里或被打进日志",
        ),
        path_keywords=(
            "consumer", "consumers", "listener", "listeners", "subscriber", "subscribers",
            "mq", "queue", "queues", "topic", "kafka", "rabbit", "rocketmq", "amqp",
            "event", "events", "dispatch", "worker",
        ),
        code_patterns=_rx(
            r"@KafkaListener\b", r"@RabbitListener\b", r"@RocketMQMessageListener\b",
            r"@JmsListener\b", r"@SqsListener\b", r"@StreamListener\b",
            r"@MessagePattern\s*\(", r"@EventPattern\s*\(",
            r"consumer\.subscribe\s*\(", r"basic_consume\s*\(", r"channel\.consume\s*\(",
            r"@(?:shared_task|app\.task|celery\.task)\b", r"\bCelery\s*\(",
            r"\bKafkaConsumer\s*\(", r"kafka\.NewReader\s*\(", r"sarama\.NewConsumer\w*\s*\(",
            r"implements\s+[\w.]*MessageListener\b",
        ),
    ),
    SCHEDULED_JOB: LensSpec(
        archetype=SCHEDULED_JOB,
        label="定时任务 / 批处理视角",
        risk_focus=(
            "分布式锁缺失：多实例 / 多副本同时执行，重复打款、重复发券、重复对账",
            "时间窗口竞态：跨天 / 跨月边界、时区不一致、夏令时导致重复执行或漏跑",
            "触发入口无鉴权：管理端 HTTP 触发 job 的接口没有权限校验，任何人都能触发跑批",
            "批量遍历越权：批处理按条件全量遍历，无租户 / 用户隔离，可越权处理他人数据",
            "补偿与对账可被操纵：构造业务数据让补偿逻辑多打款、多退款",
            "无上限批处理：一次拉全表 / 全量加载进内存 → OOM、拖垮数据库",
            "静默失败：异常被吞、无告警，业务长期不一致却无人发现",
            "运行身份权限过大：任务用高权限账号 / 连接串，或凭据硬编码",
        ),
        path_keywords=(
            "job", "jobs", "task", "tasks", "scheduler", "schedulers", "cron",
            "batch", "worker", "compensate", "reconcile", "settle", "sync", "statistic",
        ),
        code_patterns=_rx(
            r"@Scheduled\s*\(", r"@XxlJob\b", r"@Cron\s*\(", r"@EnableScheduling\b",
            r"extends\s+\w*QuartzJobBean\b", r"implements\s+\w*Job\b",
            r"\b(?:Background|Blocking)Scheduler\s*\(", r"\bschedule\.every\s*\(",
            r"\bcrontab\s*\(", r"@periodic_task\b",
            r"\bcron\.New\s*\(", r"new\s+CronJob\s*\(", r"cron\.schedule\s*\(",
            r"agenda\.define\s*\(",
        ),
    ),
    RPC_SERVICE: LensSpec(
        archetype=RPC_SERVICE,
        label="RPC 服务视角",
        risk_focus=(
            "内部接口默认信任：假设「只有内网会调」，服务端不做鉴权、不校验调用来源",
            "服务端参数校验缺失：把客户端校验当防护，服务端不校验必填 / 范围 / 类型",
            "反序列化协议：Hessian / Java 原生序列化 / 未限制类型的多态反序列化 → RCE",
            "泛化调用与动态方法名：invoke(service, method, args) 形式可由外部控制方法名",
            "上下文透传伪造：RpcContext / attachment / metadata 里的用户身份、租户 ID 被无条件信任",
            "超时与重试放大：接口非幂等却允许重试，导致重复扣款、重复创建",
            "RPC 客户端侧：目标地址可被配置或参数控制（SSRF）、关闭 TLS 校验、超时与重试无上限、异常回显内部拓扑",
            "注册与发现：注册中心无认证、可注册伪造服务；配置可被篡改",
            "信息泄露：异常堆栈、内部地址、内部标识原样回传给调用方",
            "资源无上限：无并发上限、无请求体大小限制、大对象反序列化",
        ),
        path_keywords=(
            # 刻意不放 service / impl：这两个目录名每个 Java 项目都有，
            # 会把任意 service/impl/XxxServiceImpl.java 都当 RPC 入口面。
            # 真正的 RPC 服务端靠 @DubboService / ImplBase / grpc.NewServer 这些注解特征定位。
            "rpc", "grpc", "dubbo", "thrift", "proto", "protos", "idl",
            "servicer", "stub", "provider", "interceptor",
        ),
        code_patterns=_rx(
            r"@DubboService\b", r"@DubboReference\b", r"@GrpcService\b", r"@FeignClient\b",
            r"extends\s+\w*ImplBase\b", r"add_\w+Servicer_to_server\s*\(",
            r"\bBindableService\b", r"@GrpcMethod\s*\(",
            r"\bgrpc\.server\s*\(", r"\bgrpc\.NewServer\s*\(", r"\bRegister\w*Server\s*\(",
            r"\bRpcContext\b", r"\bHessian2?Input\b", r"\bRpcInvocation\b",
        ),
    ),
    SDK_LIBRARY: LensSpec(
        archetype=SDK_LIBRARY,
        label="SDK / 公共库视角",
        risk_focus=(
            "不安全默认值：默认关闭校验、默认 allow-all、默认弱算法或弱密钥、默认无超时与上限",
            "危险 API 封装：把 eval / exec、动态导入、命令执行、任意反序列化包装成「便利方法」",
            "加解密误用：ECB 模式、固定或可预测 IV、无完整性校验（缺 MAC / AEAD）、自造算法、"
            "密钥硬编码、用 MD5/SHA1 存口令、用非 CSPRNG 生成随机数或令牌、签名比较非常量时间",
            "责任推卸：安全校验只写在文档与注释里，代码把校验义务推给调用方且没有 fail-safe 默认",
            "文档与实现不一致：文档承诺校验 / 转义 / 限制，实现里并没有",
            "并发与状态：共享可变状态、非线程安全缓存、单例里的可变全局配置",
            "序列化：对不可信数据做反序列化（pickle / yaml.load / ObjectInputStream / 原生序列化）",
            "路径与 URL：由调用方参数驱动的路径拼接（目录穿越）、URL 拼接（SSRF）、开放重定向",
            "供应链：从网络或可写目录动态加载代码与配置、依赖版本无约束",
        ),
        path_keywords=(
            "crypto", "cipher", "encrypt", "decrypt", "codec", "serializer", "serialization",
            "marshal", "sign", "signature", "hmac", "hash", "digest", "secret", "credential",
            "token", "auth", "acl", "policy", "session", "oauth", "jwt",
            "protocol", "transport", "client", "net", "socket", "url", "uri", "path",
            "file", "io", "stream", "archive", "zip", "tar", "xml", "yaml", "template",
            "sql", "query", "exec", "process", "random", "connection", "pool",
            "core", "util", "common", "config", "option",
        ),
        code_patterns=_rx(
            r"AES/ECB|Cipher\.getInstance\s*\(\s*[\"'][^\"']*ECB",
            r"IvParameterSpec\s*\(\s*new\s+byte",
            r"new\s+Random\s*\(|random\.random\s*\(|Math\.random\s*\(",
            r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']",
            r"yaml\.load\s*\(|pickle\.loads?\s*\(|ObjectInputStream|\.readObject\s*\(",
            r"\beval\s*\(|\bexec\s*\(", r"Runtime\.getRuntime\(\)\.exec|os\.system\s*\(",
            r"shell\s*=\s*True", r"verify\s*=\s*False|_create_unverified_context",
        ),
    ),
    CLI_TOOL: LensSpec(
        archetype=CLI_TOOL,
        label="命令行工具视角",
        risk_focus=(
            "命令注入：把用户参数拼进 shell、subprocess(shell=True)、os.system",
            "路径穿越：由参数驱动的文件读写路径未规范化，../ 逃出目标目录，任意文件读 / 写 / 删",
            "任意代码加载：--config / --plugin 指向任意文件即执行（yaml.load、pickle、动态 import）",
            "下载即执行：从网络拉脚本直接执行，无签名或哈希校验",
            "凭据处理：token / 口令作为命令行参数（进 shell history 与 ps）、写入日志或临时文件、权限过宽",
            "提权场景：以 root 运行、sudo 下保留环境变量、相对路径搜索导致 PATH 劫持",
            "危险默认：默认写入敏感路径、默认无覆盖保护、默认直接删除而非移到回收站",
            "符号链接逃逸：递归删除 / 复制时跟随符号链接逃出目标目录",
        ),
        path_keywords=(
            "cmd", "cli", "command", "commands", "console", "bin", "script", "scripts",
            "arg", "args", "option", "flag", "shell", "exec",
        ),
        code_patterns=_rx(
            r"\bArgumentParser\s*\(", r"@click\.(?:command|group)\b", r"\bTyper\s*\(",
            r"@CommandLine\.Command\b", r"cobra\.Command\s*\{", r"urfave/cli",
            r"os\.system\s*\(", r"subprocess\.(?:run|call|Popen|check_output|check_call)\b",
            r"shell\s*=\s*True", r"yaml\.load\s*\(|pickle\.loads?\s*\(",
            r"^#!.*\b(?:python|node)\b",
        ),
    ),
}

# 形态视角允许模型使用的风险标签。刻意在这里显式列出来（而不是只写在提示词字符串里），
# 这样测试可以断言「提示词里出现的标签一定在 RISK_TAG_LABELS 白名单内」——
# `_normalize_risk_tag` 会把白名单外的标签**静默丢掉**，写错一个词很难被发现。
LENS_RISK_TAGS: tuple[str, ...] = (
    "insecure_default",
    "crypto_misuse",
    "supply_chain",
    "message_trust",
    "idempotency",
    "internal_trust",
    "deserialization",
    "injection",
    "rce",
    "ssrf",
    "sensitive_data_exposure",
    "authz",
    "idor",
    "business_flow",
    "race_condition",
    "rate_limit",
)

# 给模型的 JSON schema：入口面字段不叫 api_endpoint，避免它硬编 HTTP 路径。
_LENS_SCHEMA = """{
  "category": "business_logic | authorization",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "title": "漏洞标题（中文）",
  "description": "漏洞描述与影响",
  "file": "相对路径",
  "line_start": 1,
  "line_end": 10,
  "evidence": "关键代码片段",
  "entry_surface": "风险所在的入口面：MQ 写 topic/queue 名，定时任务写任务名与触发表达式，RPC 写 服务.方法，SDK 写被调用的公开 API，CLI 写子命令；未知写 unknown",
  "entry_code_ref": "入口代码位置（相对路径:行号，如 mq/consumer/OrderConsumer.java:42；与漏洞 sink 行区分开，未知可省略）",
  "data_source": "数据来源（例如消息体 userId / RPC 请求参数 / 任务入参 / 调用方传入的 key）",
  "data_flow": "数据链路（抽象步骤用 -> 连接，如 消息体 -> 反序列化 -> Service.method -> 写库；某步有明确代码请加 相对路径:行号）",
  "trigger_point": "触发点（优先写 相对路径:行号 或 Class.method(...)）",
  "risk_tags": ["可选：从 __RISK_TAGS__ 中选择 1-3 个最贴切标签"],
  "attack_scenario": "攻击场景/复现思路（说明攻击者从哪里投递输入）",
  "recommendation": "修复建议",
  "confidence": 0.0-1.0
}""".replace("__RISK_TAGS__", "/".join(LENS_RISK_TAGS))


def lens_types(archetypes: list[ArchetypeHit] | None) -> list[str]:
    """从形态命中里挑出有专属视角的那些（保持原顺序，即按置信度降序）。"""
    if not archetypes:
        return []
    seen: list[str] = []
    for hit in archetypes:
        if hit.type in ARCHETYPE_LENSES and hit.type not in seen:
            seen.append(hit.type)
    return seen


def build_lens_prompt(types: list[str]) -> str:
    """把多个形态的风险清单合并成一段提示词。

    合并成一个 prompt（而不是每个形态各调一次模型）是刻意的成本控制：
    识别到 N 个形态时依然只多花 1 次调用。
    """
    active = [t for t in types if t in ARCHETYPE_LENSES]
    if not active:
        return ""

    names = "、".join(ARCHETYPE_LABELS.get(t, t) for t in active)
    sections: list[str] = []
    for archetype in active:
        spec = ARCHETYPE_LENSES[archetype]
        bullets = "\n".join(f"{i}) {item}" for i, item in enumerate(spec.risk_focus, 1))
        sections.append(f"【{spec.label}的重点风险】\n{bullets}")
    sections_block = "\n\n".join(sections)

    return f"""你是一名资深应用安全专家，正在审计一个**形态不是（或不只是）HTTP 服务**的项目。

识别到的项目形态：**{names}**。
这些入口面**不在 HTTP 路由上**，请从它们各自的入口出发思考，**不要**套用
「HTTP 接口 + 请求参数 + 越权」的套路，也不要臆造不存在的 HTTP 路径。

{sections_block}

【审计方法】
1. 先认清这个形态的**信任边界**：入口面的输入是谁给的？攻击者能不能影响它？
2. 再看**能力放大**：这条输入最终驱动了什么高危能力（写库、转账、发券、命令执行、网络请求）？
3. 然后看**约束缺失**：幂等、归属校验、来源校验、上限、签名校验有没有？
4. 只报告能在代码中定位、攻击路径说得清的问题。代码里已有防护的要说明防护点，不要报。

【输出要求】
- 每条结果的 category 从 business_logic / authorization 中选一个
- 入口面写进 entry_surface 字段（topic / 任务名 / RPC 方法 / 公开 API / 子命令），
  **不要**填 HTTP 方法与路径
- 输出 JSON 数组（无问题时返回 []），每项格式：
{_LENS_SCHEMA}
只输出 JSON 数组，不要其他文字。基于代码事实分析，不要臆造不存在的入口。"""


def _score_lens_file(rel: Path, text: str, specs: list[LensSpec]) -> int:
    name_lower = rel.name.lower()
    parts_lower = "/".join(rel.parts).lower()
    score = 0
    for spec in specs:
        for kw in spec.path_keywords:
            if kw in name_lower:
                score += 3
            elif kw in parts_lower:
                score += 2
        for pattern in spec.code_patterns:
            if pattern.search(text):
                score += 5
    return score


def collect_lens_files(
    root_path: Path,
    types: list[str],
    *,
    max_files: int,
) -> list[Path]:
    """按形态的入口面定位规则挑文件。

    和 `llm_audit_service.collect_audit_files` 的区别：那边是「业务域关键词」打分，
    这边是「入口面特征」打分 —— 一个 RabbitMQ 消费者文件既不含 `order` 也不含 `api`，
    但它命中 `@RabbitListener` 和 `consumer/` 目录，就一定会被选进来。

    测试目录直接跳过（测试代码不是生产入口面），不跟随 `exclude_test_paths` 设置。
    """
    root = Path(root_path)
    active = [t for t in types if t in ARCHETYPE_LENSES]
    if not root.is_dir() or not active or max_files <= 0:
        return []

    specs = [ARCHETYPE_LENSES[t] for t in active]
    candidates: list[tuple[int, Path]] = []
    scanned = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.suffix.lower() not in _LENS_EXTENSIONS:
            continue
        rel = path.relative_to(root)
        if is_test_path(rel):
            continue
        try:
            if path.stat().st_size > _LENS_MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if scanned >= _LENS_SCAN_FILES:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:_LENS_FILE_READ]
        except OSError:
            continue
        scanned += 1

        score = _score_lens_file(rel, text, specs)
        if score > 0:
            candidates.append((score, path))

    candidates.sort(key=lambda item: (-item[0], str(item[1])))
    selected = [path for _, path in candidates[:max_files]]
    if selected:
        logger.info(
            "形态视角入口面定位：形态=%s 扫描 %s 个文件，选中 %s 个",
            active,
            scanned,
            len(selected),
        )
    return selected
