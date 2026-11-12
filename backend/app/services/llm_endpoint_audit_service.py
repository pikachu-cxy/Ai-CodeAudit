"""Agentic endpoint-driven LLM audit — Origin → business understanding → Goal."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

from app.config import settings
from app.models import FindingCategory
from app.services.agent_tools import audit_tool_specs, execute_agent_tool, parse_agent_response
from app.services.endpoint_discovery_service import (
    DOMAIN_SIGNALS,
    ControllerUnit,
    EndpointInfo,
    cluster_endpoints_by_domain,
    collect_project_hints,
    discover_controller_units,
    find_related_service_files,
    list_endpoints_summary,
)
from app.services.llm_audit_journal import log_llm_audit_journal
from app.services.llm_audit_runtime import check_llm_audit_cancel, is_llm_audit_cancel_requested, LlmAuditCancelled
from app.services.llm_audit_service import (
    llm_items_to_findings,
    normalize_and_dedupe_llm_findings,
    parse_finding_metadata,
)
from app.services.llm_provider import (
    chat_completion,
    effective_llm_timeout,
    format_llm_exception,
    is_llm_configured,
    parse_llm_structured_response,
)

logger = logging.getLogger(__name__)


class NoHttpEndpointsDetected(RuntimeError):
    """Raised when endpoint-driven audit cannot locate any recognizable HTTP routes."""


@dataclass
class AuditProfileConfig:
    profile: str
    max_iterations: int
    max_domains: int
    max_controllers: int
    max_related_files: int
    agent_max_tool_rounds: int
    stronger_evidence: bool
    broader_hypotheses: bool
    finish_bias: str


def resolve_audit_profile_config() -> AuditProfileConfig:
    profile = str(getattr(settings, "llm_audit_profile", "balanced") or "balanced").strip().lower()
    if profile not in ("stable", "balanced", "broad"):
        profile = "balanced"

    max_iterations = int(settings.llm_endpoint_audit_max_iterations)
    max_domains = int(settings.llm_endpoint_audit_max_domains)
    max_controllers = int(settings.llm_endpoint_audit_max_controllers)
    max_related_files = int(settings.llm_endpoint_max_related_files)
    agent_max_tool_rounds = int(settings.llm_agent_max_tool_rounds)
    stronger = bool(getattr(settings, "llm_audit_require_stronger_evidence", False))
    broader = bool(getattr(settings, "llm_audit_enable_broader_hypotheses", False))
    finish_bias = "normal"

    if profile == "stable":
        max_iterations = max(12, min(max_iterations, 24))
        max_domains = max(1, min(max_domains, 2))
        max_controllers = max(10, min(max_controllers, 28))
        max_related_files = max(2, min(max_related_files, 4))
        agent_max_tool_rounds = max(6, min(agent_max_tool_rounds, 10))
        stronger = True
        finish_bias = "early"
    elif profile == "broad":
        max_iterations = max(max_iterations, 40)
        max_domains = max(max_domains, 4)
        max_controllers = max(max_controllers, 56)
        max_related_files = max(max_related_files, 6)
        agent_max_tool_rounds = max(agent_max_tool_rounds, 14)
        broader = True
        finish_bias = "late"
    else:
        max_iterations = max(20, min(max_iterations, 48))
        max_domains = max(2, min(max_domains, 5))
        max_controllers = max(20, min(max_controllers, 60))
        max_related_files = max(3, min(max_related_files, 6))
        agent_max_tool_rounds = max(8, min(agent_max_tool_rounds, 16))

    return AuditProfileConfig(
        profile=profile,
        max_iterations=max_iterations,
        max_domains=max_domains,
        max_controllers=max_controllers,
        max_related_files=max_related_files,
        agent_max_tool_rounds=agent_max_tool_rounds,
        stronger_evidence=stronger,
        broader_hypotheses=broader,
        finish_bias=finish_bias,
    )


LLM_AUDIT_FOCUS_ALLOWED = (
    "authz",
    "business_logic",
    "ai_prompt",
    "injection",
    "rce_command",
    "deserialization",
    "ssrf",
    "sensitive_data",
)

LLM_AUDIT_FOCUS_LABELS = {
    "authz": "越权 / 鉴权",
    "business_logic": "业务逻辑",
    "ai_prompt": "AI / Prompt 注入",
    "injection": "注入类（SQL/命令/表达式等）",
    "rce_command": "命令执行 / RCE（端点反推）",
    "deserialization": "不安全反序列化（端点反推）",
    "ssrf": "SSRF / 外联",
    "sensitive_data": "敏感数据泄露",
}

DEFAULT_LLM_AUDIT_FOCUS_AREAS = ["authz", "business_logic", "ai_prompt"]

HIGH_RISK_SINK_FOCUS = frozenset({"rce_command", "deserialization", "injection"})

FOCUS_SINK_QUERIES: dict[str, tuple[str, ...]] = {
    "rce_command": (
        "Runtime.exec",
        "ProcessBuilder",
        "subprocess",
        "os.system",
        "posix_spawn",
        "Runtime.getRuntime().exec",
    ),
    "deserialization": (
        "ObjectInputStream",
        "readObject",
        "enableDefaultTyping",
        "activateDefaultTyping",
        "pickle.loads",
        "yaml.load",
        "unserialize",
        "ObjectMapper.readValue",
        "JSON.parseObject",
        "JSON.parse(",
        "JSON.parseArray",
        "ParserConfig",
        "AutoType",
        "setAutoTypeSupport",
        "com.alibaba.fastjson",
    ),
    "injection": (
        "createQuery",
        "createNativeQuery",
        "Statement.execute",
        "SpelExpression",
        "Ognl",
        "ScriptEngine",
        "GroovyShell",
        "freemarker",
        "velocity",
        "jinja",
    ),
    "ssrf": (
        "requests.get",
        "requests.post",
        "httpx",
        "urlopen",
        "RestTemplate",
        "WebClient",
        "OkHttp",
        "callback_url",
        "webhook",
    ),
    "ai_prompt": (
        "system_prompt",
        "tool_call",
        "function_call",
        "messages",
        "ChatCompletion",
    ),
    "sensitive_data": (
        "password",
        "secret",
        "api_key",
        "Authorization",
        "logger.info",
    ),
}


def normalize_focus_areas(raw) -> list[str]:
    values = list(raw or [])
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in values:
        key = str(item or "").strip().lower()
        if key not in LLM_AUDIT_FOCUS_ALLOWED or key in seen:
            continue
        seen.add(key)
        cleaned.append(key)
    return cleaned


def resolve_focus_areas(categories: list[FindingCategory] | None = None) -> list[str]:
    areas = normalize_focus_areas(getattr(settings, "llm_audit_focus_areas", None))
    # Merge legacy category filter into focus areas when provided by API callers.
    for cat in categories or []:
        if cat == FindingCategory.AUTHORIZATION and "authz" not in areas:
            areas.append("authz")
        elif cat == FindingCategory.BUSINESS_LOGIC and "business_logic" not in areas:
            areas.append("business_logic")
    return areas


def sink_queries_for_focus(focus_areas: list[str], *, limit: int) -> list[str]:
    """Build sink search queries from user focus. Empty when no sink-related focus."""
    queries: list[str] = []
    seen: set[str] = set()
    for area in focus_areas:
        for q in FOCUS_SINK_QUERIES.get(area, ()):
            if q in seen:
                continue
            seen.add(q)
            queries.append(q)
            if len(queries) >= limit:
                return queries
    return queries[:limit]


def _has_stronger_evidence(finding: dict) -> bool:
    meta = parse_finding_metadata(finding.get("metadata_json"))
    source = str(meta.get("source") or meta.get("data_source") or "").strip()
    sink = str(meta.get("sink") or meta.get("trigger_point") or "").strip()
    guard = str(meta.get("missing_guard") or "").strip()
    impact = str(meta.get("impact") or meta.get("attack_scenario") or "").strip()
    score = sum(1 for x in (source, sink, guard, impact) if x)
    return score >= 3

AGENTIC_AUDIT_SYSTEM_PROMPT = """你是自主应用安全审计 Agent，像一名资深安全顾问接手新项目时的思考方式工作。

【思考顺序 — 从 Origin 到 Goal】
1. **读懂业务（Understand）**：端点清单合起来是什么产品？有哪些角色？核心流程是什么？要保护哪些资产？
2. **形成假设（Hypothesize）**：攻击者会盯什么？开发常犯什么错？哪些流程/模块最可疑？
3. **代码验证（Verify）**：用工具读源码、追调用链，把假设变成有证据的发现
4. **落地风险（Findings）**：只报告能在代码中定位、攻击路径说得清的问题

设计原则：少做限制，充分发挥安全专业与业务理解能力。不要跳过业务理解直接扫漏洞。

【Goal】
发现真实、可落地、值得修复的安全风险（含越权、业务逻辑、AI/Prompt 注入、注入、命令执行/RCE、反序列化、敏感数据泄露等）。
若用户消息给出「关注重点」，请提高对应方向的调查优先级与预算；未列出方向若证据极强仍可报告。
对每个 finding，尽量补充 1-3 个 risk_tags，优先从以下选择：
- prompt_injection
- agent_tool_abuse
- ssrf
- sensitive_data_exposure
- injection
- rce
- deserialization
- business_flow
- race_condition
- rate_limit
- session
- jwt
- authz
- idor
- privilege_escalation
- mass_assignment
- insecure_default
- crypto_misuse
- supply_chain
- message_trust
- idempotency
- internal_trust

【工作方式】
- 由你**自主决定**何时结束：各调查假设已验证、或继续调查收益很低时，输出 action=finish
- 调查过程中可 tool 读代码、findings 提交阶段性发现、understand 更新业务模型
- 系统仅有安全上限（防失控），**不应**被动耗满轮次；证据充分后主动 finish
- 从 HTTP 入口追到 Service / Agent / Prompt 组装逻辑，不停留在路由层

【Property-Driven 审计框架（默认）】
不要按漏洞名逐个专项堆叠。优先按以下“安全性质”调查，并将结果映射为具体漏洞：
1) 信任边界错误：不可信输入（用户参数/第三方回调/LLM 输出）被当作可信数据
2) 能力放大：可控输入驱动高危能力（网络请求、文件读写、命令执行、模板渲染、动态执行）
3) 约束缺失：缺少 allowlist、协议限制、目标限制、鉴权、速率限制、幂等保护
4) 状态/所有权破坏：审批流、金额、库存、资源归属等关键业务约束被破坏
5) 可落地影响：越权、数据泄露、内网探测、资金损失、持久化污染等

输出 findings 时必须补齐四元组：source(可控输入) → sink(危险能力) → missing_guard(缺失约束) → impact(实际后果)。
若是 AI/Agent 风险，还要优先说明：输入进入了哪段 prompt / 哪个工具 / 哪个外联目标，缺少什么约束。

【负向约束检查（默认必须覆盖）】
请主动证明“是否缺少以下约束”，不要只找显式危险函数：
- 频控/锁定：验证码、密码重置、登录、短信/邮箱发送是否可暴力尝试
- 服务端真值：价格、积分、优惠、库存、审批结果是否由服务端重算，而非信任客户端
- 会话并发/失效：JWT/session 是否支持单点登出、版本失效、jti/revocation、多端互斥
- 目标限制：URL/文件路径/回调地址/模板名/工具名是否受 allowlist/协议/私网限制
- 状态机/幂等：支付、退款、审批、充值是否能重复触发、乱序触发或并发破坏

【默认调查模板】
对每个高价值流程，优先回答这些问题：
1. 哪些输入是用户可控或第三方可控的？
2. 这些输入是否驱动了高危能力或关键业务决策？
3. 服务端是否有不可绕过的真值校验/约束/失效机制？
4. 如果约束缺失，攻击者能得到什么具体收益？

【重点流程提示】
- AI/Agent：用户输入是否直入 messages/system prompt；LLM 输出是否直接驱动工具/外联/文件操作；是否存在 tool allowlist、参数白名单、二次确认、权限隔离
- 密码重置/验证码：是否有 attempt counter、rate limit、cooldown、账号级锁定
- 支付/积分/充值：金额、价格、积分、折扣是否由服务端重算；状态流是否防重复/乱序
- JWT/Session：是否存在 jti、session version、revocation、logout 失效、并发登录策略
- 外联/回调：目标 URL 是否限制协议、域名、私网地址、metadata 地址
- 命令执行/RCE：从 HTTP 入口可控参数反推是否到达 Runtime.exec / ProcessBuilder / subprocess / os.system 等；区分“存在危险 API”与“用户可控到达”
- 反序列化：从入口反推 ObjectInputStream/readObject/多态反序列化/pickle/yaml.load 等，确认类型约束与来源可信性

若证据还差一步，不要沉默；请先用 action=candidates 提交“高风险候选 + 下一步验证建议”。

若用户给出「关注重点」，提高对应方向的调查优先级与检索力度，但仍不排斥其它明显高危。

{tool_specs}
"""

BUSINESS_COMPREHENSION_PROMPT = """你是资深安全顾问，刚拿到一个陌生项目的 API 端点清单。请先像人一样读懂业务，再谈漏洞。

根据【Origin】中的端点聚类、项目线索、高敏接口，推断：
- 这是什么系统、服务谁
- 有哪些业务域与关键流程
- 典型角色与信任边界
- 从业务视角，哪些模块最值得深入、可能存在什么类风险（hypothesis，待代码验证）
- 识别“可控输入是否驱动危险能力”的业务流，并标注优先验证项

只输出一个 JSON 对象（无 markdown），格式：
{
  "action": "understand",
  "app_summary": "一句话描述系统",
  "business_domains": [
    {"name": "用户与账号", "description": "...", "key_endpoints": ["POST /login"], "assets": ["凭证"], "typical_risks": ["越权改密"]}
  ],
  "user_roles": ["普通用户", "管理员"],
  "critical_flows": [
    {"name": "支付下单", "description": "...", "trust_assumptions": ["金额服务端计算"], "risk_if_broken": "资损"}
  ],
  "trust_boundaries": ["用户只能操作自己的资源"],
  "investigation_priorities": [
    {"target": "AI 对话模块", "reason": "含 agent/chat 路径", "hypothesis": "Prompt 注入或工具滥用", "suggested_tools": ["search_code: messages"]}
  ]
}

不要编造清单中不存在的模块；不确定的写入 hypothesis 并标明待验证。
"""


def _focus_hint(categories: list[FindingCategory] | None = None, focus_areas: list[str] | None = None) -> str:
    areas = focus_areas if focus_areas is not None else resolve_focus_areas(categories)
    labels = [LLM_AUDIT_FOCUS_LABELS.get(a, a) for a in areas]
    if not labels:
        return "用户未指定关注重点：完全自主调查，自行决定优先级。"
    parts = [
        f"用户关注重点（优先提高预算，但不局限）：{'、'.join(labels)}",
    ]
    if HIGH_RISK_SINK_FOCUS.intersection(areas):
        parts.append(
            "已开启高危 sink 反推：请按 端点可控输入 → 域内危险 sink 检索 → 桥接调用链 → "
            "source/sink/missing_guard/impact 四元组收束；无可达证据时用 candidates，勿把“仅存在危险 API”当 finding。"
        )
        if "rce_command" in areas:
            parts.append("重点验证命令执行可达性（Runtime.exec / ProcessBuilder / subprocess 等）。")
        if "deserialization" in areas:
            parts.append("重点验证反序列化可达性（ObjectInputStream / pickle / yaml.load / 多态反序列化等）。")
        if "injection" in areas:
            parts.append("重点验证注入类 sink（SQL/原生查询/表达式引擎/模板引擎等）是否由端点输入驱动。")
    return "\n".join(parts)


def _classify_endpoint_domain(ep: EndpointInfo, unit: ControllerUnit) -> str:
    hay = f"{ep.path} {ep.handler} {unit.class_name} {unit.file}".lower()
    for domain, keywords in DOMAIN_SIGNALS.items():
        if any(kw in hay for kw in keywords):
            return domain
    return "其它"


def _slim_endpoint_row(row: dict) -> dict:
    return {
        "method": row.get("method") or row.get("http_method"),
        "path": row.get("path"),
        "handler": row.get("handler"),
        "file": row.get("file"),
        "line": row.get("line"),
        "sensitivity": row.get("sensitivity", 0),
    }


def _slim_domain_clusters(
    domains: list[dict],
    *,
    sample_per_domain: int | None = None,
) -> list[dict]:
    n = sample_per_domain if sample_per_domain is not None else settings.llm_endpoint_origin_sample_per_domain
    n = max(1, min(int(n), 20))
    slim: list[dict] = []
    for d in domains:
        samples = [_slim_endpoint_row(r) for r in (d.get("sample_endpoints") or [])[:n]]
        slim.append(
            {
                "domain": d.get("domain"),
                "endpoint_count": d.get("endpoint_count", 0),
                "high_sensitivity_count": d.get("high_sensitivity_count", 0),
                "sample_endpoints": samples,
            }
        )
    return slim


def _unit_to_controller_payload(unit: ControllerUnit) -> dict:
    return {
        "file": unit.file,
        "class": unit.class_name,
        "base_path": unit.base_path,
        "sensitivity": unit.sensitivity,
        "endpoints": [
            {
                "method": ep.http_method,
                "path": ep.path,
                "handler": ep.handler,
                "line": ep.line,
                "sensitivity": ep.sensitivity,
            }
            for ep in unit.endpoints[:12]
        ],
    }


def build_origin_summary(project_path: Path, units: list[ControllerUnit] | None = None) -> dict:
    """Lightweight Origin for Understand — counts, domain samples, no full controllers[]."""
    units = units if units is not None else discover_controller_units(project_path)
    endpoints = list_endpoints_summary(project_path, limit=100)
    sensitive = [ep for ep in endpoints if ep.get("sensitivity", 0) >= 2][:20]
    domains = _slim_domain_clusters(cluster_endpoints_by_domain(units))
    return {
        "project_root": str(project_path),
        "project_hints": collect_project_hints(project_path),
        "controller_count": len(units),
        "endpoint_count": sum(len(u.endpoints) for u in units),
        "business_domains": domains,
        "top_sensitive_endpoints": [_slim_endpoint_row(ep) for ep in sensitive],
        "reading_guide": [
            "先看 business_domains 理解产品有哪些业务板块（本摘要仅含样例端点）",
            "结合 project_hints（README 等）确认系统定位",
            "在 investigation_priorities 中标出最值得深入的业务域与假设",
            "后续将按高风险业务域分批做代码级 Goal 验证",
        ],
    }


def _controllers_for_domain(
    units: list[ControllerUnit],
    domain_name: str,
    *,
    limit: int,
) -> list[ControllerUnit]:
    matched: list[ControllerUnit] = []
    for unit in units:
        if any(_classify_endpoint_domain(ep, unit) == domain_name for ep in unit.endpoints):
            matched.append(unit)
    matched.sort(key=lambda u: (-u.sensitivity, -len(u.endpoints), u.file))
    return matched[: max(1, limit)]


def build_domain_slice(
    project_path: Path,
    units: list[ControllerUnit],
    domain_name: str,
    *,
    max_controllers: int | None = None,
    sample_per_domain: int | None = None,
) -> dict:
    """Origin slice for one business domain — controllers + sensitive samples, volume-bounded."""
    limit = max_controllers if max_controllers is not None else settings.llm_endpoint_audit_max_controllers
    selected = _controllers_for_domain(units, domain_name, limit=limit)
    domain_eps: list[dict] = []
    for u in units:
        for ep in u.endpoints:
            if _classify_endpoint_domain(ep, u) == domain_name:
                domain_eps.append(
                    {
                        "method": ep.http_method,
                        "path": ep.path,
                        "handler": ep.handler,
                        "file": ep.file,
                        "line": ep.line,
                        "sensitivity": ep.sensitivity,
                    }
                )
    domain_eps.sort(key=lambda r: (-r["sensitivity"], r["path"]))
    high_sens = sum(1 for r in domain_eps if r.get("sensitivity", 0) >= 2)
    sensitive = [_slim_endpoint_row(r) for r in domain_eps if r.get("sensitivity", 0) >= 2][:15]
    if not sensitive:
        sensitive = [_slim_endpoint_row(r) for r in domain_eps[:10]]

    domain_info = {
        "domain": domain_name,
        "endpoint_count": len(domain_eps),
        "high_sensitivity_count": high_sens,
        "sample_endpoints": domain_eps[:10],
    }
    controllers = [_unit_to_controller_payload(u) for u in selected[:30]]

    return {
        "project_root": str(project_path),
        "audit_domain": domain_name,
        "project_hints": collect_project_hints(project_path),
        "controller_count": len(selected),
        "endpoint_count": len(domain_eps),
        # Global project size — domain slices must not under-count for "large project" gates.
        "project_controller_count": len(units),
        "project_endpoint_count": sum(len(u.endpoints) for u in units),
        "business_domains": _slim_domain_clusters(
            [domain_info],
            sample_per_domain=min(10, (sample_per_domain if sample_per_domain is not None else settings.llm_endpoint_origin_sample_per_domain) + 5),
        ),
        "top_sensitive_endpoints": sensitive,
        "controllers": controllers,
        "reading_guide": [
            f"本轮仅深度审计业务域：{domain_name}",
            "优先读本域 controllers 及关联 Service/Agent",
            "用 search_code 时优先结合本域路径/关键词，避免全仓无差别扫描",
            "从端点 handler 追到 Service/Agent/Prompt 构建函数",
            "同一条业务链优先 read_files_batch",
        ],
    }


def _select_audit_domains(
    clustered: list[dict],
    business_model: dict,
    *,
    max_domains: int,
) -> list[str]:
    """Pick Top-N domains by sensitivity + LLM investigation_priorities."""
    max_n = max(1, min(int(max_domains), 20))
    if not clustered:
        return ["其它"]

    scores: dict[str, float] = {}
    for d in clustered:
        name = str(d.get("domain") or "")
        if not name:
            continue
        scores[name] = float(d.get("high_sensitivity_count") or 0) * 10 + float(d.get("endpoint_count") or 0)

    priority_text = " ".join(
        f"{p.get('target', '')} {p.get('reason', '')} {p.get('hypothesis', '')}"
        for p in (business_model.get("investigation_priorities") or [])
        if isinstance(p, dict)
    ).lower()
    llm_domain_text = " ".join(
        f"{d.get('name', '')} {d.get('description', '')}"
        for d in (business_model.get("business_domains") or [])
        if isinstance(d, dict)
    ).lower()
    boost_hay = f"{priority_text} {llm_domain_text}"

    for name in list(scores.keys()):
        boost = 0.0
        if name in boost_hay or any(tok and tok in boost_hay for tok in name.replace("与", " ").split()):
            boost += 50
        # keyword overlap with DOMAIN_SIGNALS
        for kw in DOMAIN_SIGNALS.get(name, ()):
            if kw in boost_hay:
                boost += 8
                break
        scores[name] = scores.get(name, 0) + boost

    ranked = sorted(scores.keys(), key=lambda n: (-scores[n], n))
    return ranked[:max_n]


def _rank_audit_domains(clustered: list[dict], business_model: dict) -> list[dict]:
    """Structured ranking details for explainability logs/UI."""
    if not clustered:
        return [{"domain": "其它", "score": 0.0, "high_sensitivity_count": 0, "endpoint_count": 0, "boost": 0.0}]

    base_by_domain: dict[str, dict] = {}
    scores: dict[str, float] = {}
    for d in clustered:
        name = str(d.get("domain") or "")
        if not name:
            continue
        high = float(d.get("high_sensitivity_count") or 0)
        count = float(d.get("endpoint_count") or 0)
        base = high * 10 + count
        base_by_domain[name] = {
            "domain": name,
            "high_sensitivity_count": int(high),
            "endpoint_count": int(count),
            "base_score": base,
        }
        scores[name] = base

    priority_text = " ".join(
        f"{p.get('target', '')} {p.get('reason', '')} {p.get('hypothesis', '')}"
        for p in (business_model.get("investigation_priorities") or [])
        if isinstance(p, dict)
    ).lower()
    llm_domain_text = " ".join(
        f"{d.get('name', '')} {d.get('description', '')}"
        for d in (business_model.get("business_domains") or [])
        if isinstance(d, dict)
    ).lower()
    boost_hay = f"{priority_text} {llm_domain_text}"

    rows: list[dict] = []
    for name, base_meta in base_by_domain.items():
        boost = 0.0
        reasons: list[str] = []
        if name in boost_hay or any(tok and tok in boost_hay for tok in name.replace("与", " ").split()):
            boost += 50
            reasons.append("业务理解优先级命中")
        for kw in DOMAIN_SIGNALS.get(name, ()):
            if kw in boost_hay:
                boost += 8
                reasons.append(f"关键词命中:{kw}")
                break
        total = base_meta["base_score"] + boost
        rows.append(
            {
                **base_meta,
                "boost": boost,
                "score": total,
                "reasons": reasons,
            }
        )
        scores[name] = total

    rows.sort(key=lambda item: (-float(item["score"]), str(item["domain"])))
    return rows


def _domain_focused_business_model(business_model: dict, domain_name: str) -> dict:
    """Narrow priorities for a domain Goal round while keeping global app summary."""
    model = {
        "app_summary": business_model.get("app_summary", ""),
        "business_domains": [
            d
            for d in (business_model.get("business_domains") or [])
            if isinstance(d, dict) and domain_name in str(d.get("name") or "")
        ]
        or business_model.get("business_domains", [])[:2],
        "user_roles": business_model.get("user_roles", []),
        "critical_flows": [
            f
            for f in (business_model.get("critical_flows") or [])
            if isinstance(f, dict)
            and (
                domain_name in str(f.get("name") or "")
                or domain_name in str(f.get("description") or "")
                or any(kw in f"{f.get('name', '')} {f.get('description', '')}".lower() for kw in DOMAIN_SIGNALS.get(domain_name, ()))
            )
        ]
        or (business_model.get("critical_flows") or [])[:3],
        "trust_boundaries": business_model.get("trust_boundaries", []),
        "investigation_priorities": [],
        "focus_domain": domain_name,
    }
    priorities = []
    for p in business_model.get("investigation_priorities") or []:
        if not isinstance(p, dict):
            continue
        blob = f"{p.get('target', '')} {p.get('reason', '')} {p.get('hypothesis', '')}".lower()
        if domain_name in blob or any(kw in blob for kw in DOMAIN_SIGNALS.get(domain_name, ())):
            priorities.append(p)
    model["investigation_priorities"] = priorities or list(business_model.get("investigation_priorities") or [])[:4]
    return model


def _understand_payload(parsed: dict) -> dict:
    return {
        "app_summary": parsed.get("app_summary", ""),
        "business_domains": parsed.get("business_domains", []),
        "user_roles": parsed.get("user_roles", []),
        "critical_flows": parsed.get("critical_flows", []),
        "trust_boundaries": parsed.get("trust_boundaries", []),
        "investigation_priorities": parsed.get("investigation_priorities", []),
    }


def _candidate_payload(parsed: dict) -> dict:
    return {
        "note": parsed.get("note", ""),
        "candidates": parsed.get("candidates", []),
    }


async def _run_business_comprehension(
    origin: dict,
    *,
    scan_id: int | None,
    focus: str,
) -> dict:
    """Phase: Origin → business understanding (does not consume iteration budget)."""
    if scan_id:
        check_llm_audit_cancel(scan_id)

    user_content = (
        "【Origin — 端点与业务线索】\n"
        f"{json.dumps(origin, ensure_ascii=False, indent=2)}\n"
    )
    if focus:
        user_content += f"\n{focus}\n"

    text = await chat_completion(
        [
            {"role": "system", "content": BUSINESS_COMPREHENSION_PROMPT},
            {"role": "user", "content": user_content},
        ],
        task="deep",
        temperature=0.25,
        max_tokens=min(settings.llm_audit_max_tokens, 3072),
        timeout=effective_llm_timeout(4, task="deep"),
        json_mode=True,
    )
    if scan_id:
        check_llm_audit_cancel(scan_id)

    data = parse_llm_structured_response(text)
    if isinstance(data, dict):
        parsed = parse_agent_response(json.dumps(data, ensure_ascii=False))
        if parsed and parsed.get("action") == "understand":
            model = _understand_payload(parsed)
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "business_model",
                    {
                        "title": "业务理解",
                        "app_summary": model.get("app_summary", ""),
                        "business_domains": model.get("business_domains", []),
                        "user_roles": model.get("user_roles", []),
                        "critical_flows": model.get("critical_flows", []),
                        "trust_boundaries": model.get("trust_boundaries", []),
                        "investigation_priorities": model.get("investigation_priorities", []),
                    },
                )
            return model

    logger.warning("Business comprehension parse failed, using heuristic fallback")
    fallback = {
        "app_summary": "待调查的应用（业务理解阶段未返回结构化结果）",
        "business_domains": origin.get("business_domains", []),
        "user_roles": [],
        "critical_flows": [],
        "trust_boundaries": [],
        "investigation_priorities": [
            {
                "target": ep.get("path", ""),
                "reason": "高敏感度端点",
                "hypothesis": "鉴权或业务逻辑缺陷",
            }
            for ep in origin.get("top_sensitive_endpoints", [])[:5]
        ],
    }
    if scan_id:
        await log_llm_audit_journal(
            scan_id,
            "business_model",
            {"title": "业务理解（启发式回退）", **fallback},
            level="warning",
        )
    return fallback


def _raw_to_findings(raw: list, project_path: Path) -> list[dict]:
    if not raw:
        return []
    return llm_items_to_findings(
        raw,
        project_path,
        FindingCategory.BUSINESS_LOGIC,
        rule_prefix="endpoint",
        lock_category=False,
    )


def _goal_user_message(
    origin: dict,
    business_model: dict,
    focus: str,
    safety_max: int,
    *,
    focus_areas: list[str] | None = None,
) -> str:
    domain = str(origin.get("audit_domain") or business_model.get("focus_domain") or "")
    domain_line = f"\n【本轮审计域】{domain}\n请聚焦该域的 controllers / 敏感端点与相关假设，勿扩散到无关模块。\n" if domain else ""
    parts = [
        "【Origin】\n" + json.dumps(origin, ensure_ascii=False, indent=2),
        domain_line,
        "\n【业务理解 — 像人一样读懂后的结论】\n"
        + json.dumps(business_model, ensure_ascii=False, indent=2),
        "\n【Goal】\n"
        "请自主调查并**由你决定何时结束**（action=finish）。\n"
        "- 需要更多代码证据 → action=tool\n"
        "- 有充分证据的漏洞 → action=findings（可多次）\n"
        "- investigation_priorities 已验证且无更高价值方向 → action=finish\n"
        "- 需要串起 controller/service/util/agent/prompt 证据链时，优先用 read_files_batch 一次读取多文件，而不是逐个 read_file\n"
        f"系统安全上限 {safety_max} 轮（仅防失控，勿被动耗满）。\n"
        "每个 finding 需能回答：什么业务场景、谁攻击谁、什么后果、哪行代码支撑。",
        "\n证据不足也应在 finish 的 audit_summary 说明已调查范围与结论。",
    ]
    if focus:
        parts.append(f"\n{focus}")
    areas = normalize_focus_areas(focus_areas) if focus_areas is not None else []
    if HIGH_RISK_SINK_FOCUS.intersection(areas):
        parts.append(
            "\n【高危 sink 反推检查清单（用户已开启，finish 前尽量覆盖）】\n"
            "A. 端点侧：列出本域高价值接口的可控输入（path/query/body/header/file/回调）\n"
            "B. Sink 侧：结合预调查结果，定位命令执行/反序列化/注入/表达式等危险能力\n"
            "C. 桥接：验证可控输入是否到达 sink；读中间 Service/Util；证伪也写入 candidates\n"
            "D. 收束：仅当 source→sink→missing_guard→impact 齐备时 findings 入库；"
            "仅存在危险 API、无用户可达证据时不要报 finding\n"
            "禁止只完成越权/业务逻辑检查就 finish，除非已明确说明高危 sink 方向已验证或证伪。"
        )
    return "".join(parts)


def _soft_nudge_message(
    round_no: int,
    safety_max: int,
    consecutive_tools: int,
    *,
    finish_bias: str = "normal",
    high_risk_sink: bool = False,
) -> str | None:
    """Gentle hints only — LLM controls termination via finish."""
    remaining = safety_max - round_no
    if consecutive_tools >= 6:
        extra = (
            "若用户开启了高危 sink 反推，请确认命令执行/反序列化等是否已桥接或证伪。"
            if high_risk_sink
            else ""
        )
        return (
            "【提示】已连续多次 tool 调查。若主要假设已有结论，请 findings 或 finish；"
            "若仍有高价值模块未读，优先 read_files_batch 并读 controller + service + util/agent/prompt。"
            + extra
        )
    if consecutive_tools >= 3:
        return (
            "【提示】若你正在沿同一条调用链继续取证，优先改用 read_files_batch 一次读取多个相关文件，"
            "例如 controller + service + util/agent/prompt，避免单文件串行消耗轮次。"
        )
    finish_threshold = 2 if finish_bias != "early" else 4
    if remaining <= finish_threshold:
        sink_hint = (
            "finish 前请确认高危 sink（命令执行/反序列化等）已验证或证伪。"
            if high_risk_sink
            else ""
        )
        return (
            f"【安全上限提醒】距系统上限仅剩 {remaining} 轮。"
            "请尽快 finish；若有已确认漏洞，务必写入 findings，触顶后仅能通过收尾轮次补提。"
            + sink_hint
        )
    return None


def _tool_followup_hint(tool_name: str, tool_args: dict, consecutive_tools: int) -> str:
    if tool_name == "read_file":
        path = str(tool_args.get("path") or "")
        return (
            f"若 `{path}` 只是链路中的一环，下一步优先考虑 read_files_batch，把相关 controller/service/util/agent/prompt 一次并读。"
        )
    if tool_name == "search_code":
        query = str(tool_args.get("query") or "")
        return (
            f"若搜索 `{query}` 命中了多处可疑实现，不要逐个零散阅读；优先把最相关的 2-5 个文件用 read_files_batch 合并取证。"
        )
    if consecutive_tools >= 2:
        return "若当前仍在同一业务流上追证，优先 read_files_batch 合并读取下一批相关文件。"
    return ""


async def _salvage_findings_on_timeout(
    messages: list[dict],
    project_path: Path,
    *,
    scan_id: int | None,
    business_model: dict,
    max_rounds: int,
    already_collected: list[dict] | None = None,
) -> tuple[list[dict], str]:
    """Extra LLM call(s) when safety ceiling hit — flush all confirmed vulns into findings."""
    if scan_id:
        check_llm_audit_cancel(scan_id)

    preserved = already_collected or []
    preserved_titles = [str(it.get("message") or "") for it in preserved[:12] if it.get("message")]

    salvage_hints = [
        (
            f"【已达系统安全上限 {max_rounds} 轮】必须立即 action=finish，禁止 tool。\n"
            "把调查过程中**已确认、有代码证据**的漏洞全部写入 findings（无则 []）。\n"
            "遗漏已确认漏洞视为严重错误。audit_summary 说明调查范围与结论。\n"
            + (
                f"以下 {len(preserved)} 条已在过程中提交、会自动保留，finish 中只需写**尚未提交**的新发现：\n"
                + "\n".join(f"- {t}" for t in preserved_titles)
                if preserved_titles
                else "过程中尚未提交任何 findings，请把已确认漏洞全部写入 finish.findings。"
            )
            + f"\n业务背景：{business_model.get('app_summary', '')}"
        ),
        (
            "【收尾重试】上次未返回合法 finish。请仅输出 action=finish JSON。\n"
            "findings 必须包含你在前述 tool 结果中已确认的全部漏洞（file/line_start/title/description）。"
            "无漏洞则 findings=[]，但 audit_summary 必须说明已审查的模块。"
        ),
        (
            "【收尾最终尝试】输出极简 finish：\n"
            '{"action":"finish","audit_summary":"...","findings":[{"category":"business_logic",'
            '"severity":"HIGH","title":"...","description":"...","file":"path","line_start":1}]}'
        ),
    ]

    last_summary = ""
    last_raw: list = []

    for attempt, hint in enumerate(salvage_hints):
        attempt_messages = list(messages)
        attempt_messages.append({"role": "user", "content": hint})

        try:
            text = await chat_completion(
                attempt_messages,
                task="deep",
                temperature=0.1,
                max_tokens=min(settings.llm_audit_max_tokens, 4096),
                timeout=effective_llm_timeout(5, task="deep"),
                json_mode=True,
            )
        except Exception as exc:
            logger.warning("Salvage attempt %s failed: %s", attempt + 1, exc)
            if attempt == len(salvage_hints) - 1:
                return [], f"触顶收尾失败: {exc}"
            continue

        parsed = parse_agent_response(text)
        if not parsed:
            continue

        if parsed.get("action") == "finish":
            last_summary = str(parsed.get("audit_summary") or "")
            last_raw = parsed.get("findings") or []
            break
        if parsed.get("action") == "findings":
            last_summary = str(parsed.get("note") or "")
            last_raw = parsed.get("findings") or []
            break

    findings = _raw_to_findings(last_raw, project_path)
    if scan_id:
        await log_llm_audit_journal(
            scan_id,
            "salvage_finish",
            {
                "title": "触顶收尾汇总",
                "audit_summary": last_summary
                or (f"新提取 {len(findings)} 条" if findings else "未从对话中提取到新发现"),
                "findings_count": len(findings),
                "preserved_from_batches": len(preserved),
                "finding_titles": [it.get("message", "") for it in findings[:8]],
            },
            level="warning" if not findings and not preserved else "info",
        )
    return findings, last_summary or (
        f"触顶；保留过程中 {len(preserved)} 条，收尾新提取 {len(findings)} 条"
    )


def _keyword_from_priority(target: str, hypothesis: str) -> str | None:
    text = f"{target} {hypothesis}".lower()
    for kw in (
        "messages",
        "system_prompt",
        "prompt",
        "agent",
        "llm",
        "chat",
        "guide",
        "password",
        "modifypwd",
        "auth",
        "login",
        "user_id",
        "recordid",
        "order",
        "pay",
        "refund",
        "ssrf",
        "image_url",
        "callback_url",
        "webhook",
        "requests",
        "httpx",
        "aiohttp",
        "urlopen",
    ):
        if kw in text:
            return kw
    parts = [p for p in re.split(r"[/\s_\-]+", target) if len(p) > 2]
    return parts[-1] if parts else None


PROPERTY_SINK_QUERIES = (
    # outbound/network
    "requests.get", "requests.post", "httpx", "aiohttp", "urlopen", "webhook", "callback_url",
    # file/io
    "open(", "Path(", "read_text(", "write_text(", "download", "upload",
    # command/dynamic execution
    "subprocess", "os.system", "exec(", "eval(",
    # templating/serialization
    "jinja", "template", "pickle.loads", "yaml.load", "json.loads(",
    # AI/tooling glue
    "tool_call", "function_call", "agent", "messages", "system_prompt",
)

NEGATIVE_GUARD_QUERIES = (
    "verifyCode", "captcha", "rate_limit", "throttle", "attempt", "cooldown", "lock", "retry",
    "amount", "price", "points", "score", "coupon", "inventory", "recalculate", "server_price",
    "jwt", "jti", "revocation", "blacklist", "session_version", "logout", "single_login", "token_version",
    "allowlist", "whitelist", "private ip", "169.254.169.254", "127.0.0.1", "localhost", "scheme",
)


def _plan_bootstrap_tools(
    origin: dict,
    business_model: dict,
    *,
    profile_cfg: AuditProfileConfig | None = None,
    focus_areas: list[str] | None = None,
    cancel_check=None,
) -> list[tuple[str, dict]]:
    """Automatic tool calls before Goal loop — free, no LLM iteration cost."""
    planned: list[tuple[str, dict]] = []
    seen: set[str] = set()
    audit_domain = str(origin.get("audit_domain") or business_model.get("focus_domain") or "")
    areas = normalize_focus_areas(focus_areas)

    def add(tool: str, args: dict) -> None:
        key = f"{tool}:{json.dumps(args, sort_keys=True)}"
        if key in seen:
            return
        seen.add(key)
        planned.append((tool, args))

    budgets = {
        "overview": 1,
        "business_reads": 3,
        "property_sinks": 3,
        "negative_guards": 3,
        "priority_hypotheses": 3,
    }
    # Prefer whole-repo counts so domain slices (e.g. 40 controllers) don't re-enable
    # find_related_service_files and peg the machine for tens of minutes.
    controller_count = int(
        origin.get("project_controller_count") or origin.get("controller_count") or 0
    )
    endpoint_count = int(
        origin.get("project_endpoint_count") or origin.get("endpoint_count") or 0
    )
    large_project = controller_count >= 40 or endpoint_count >= 200
    if large_project:
        # Large projects: cap free bootstrap fan-out to preserve responsiveness.
        budgets["business_reads"] = min(budgets["business_reads"], 2)
        budgets["property_sinks"] = min(budgets["property_sinks"], 4)
        budgets["negative_guards"] = min(budgets["negative_guards"], 2)
        budgets["priority_hypotheses"] = min(budgets["priority_hypotheses"], 2)
    if profile_cfg and profile_cfg.broader_hypotheses:
        budgets["property_sinks"] += 2
        budgets["negative_guards"] += 2
        budgets["priority_hypotheses"] += 2
    if HIGH_RISK_SINK_FOCUS.intersection(areas):
        # User explicitly asked for high-risk sink reverse tracing.
        if profile_cfg and profile_cfg.profile == "stable":
            budgets["property_sinks"] = max(budgets["property_sinks"], 4)
        elif profile_cfg and profile_cfg.profile == "broad":
            budgets["property_sinks"] = max(budgets["property_sinks"], 8)
        else:
            budgets["property_sinks"] = max(budgets["property_sinks"], 6)

    if budgets["overview"] > 0:
        add("list_controllers", {"limit": 20})
        budgets["overview"] -= 1

    read_targets: list[dict] = []
    for c in (origin.get("controllers") or [])[:30]:
        rel = str(c.get("file") or "")
        name = f"{c.get('class', '')} {rel}".lower()
        if rel and (
            audit_domain
            or any(
                k in name
                for k in (
                    "guide", "content", "generator", "image", "chat", "agent", "admin",
                    "file", "callback", "payment", "auth", "reset", "jwt",
                )
            )
        ):
            read_targets.append({"path": rel, "start_line": 1, "end_line": 240})
            project_root = Path(str(origin.get("project_root") or "")) if origin.get("project_root") else None
            controller_abs = (project_root / rel) if project_root else None
            if not large_project and project_root and controller_abs and controller_abs.is_file():
                related_limit = 3
                if profile_cfg:
                    related_limit = max(2, min(profile_cfg.max_related_files, 8))
                for svc in find_related_service_files(
                    project_root,
                    controller_abs,
                    max_files=related_limit,
                    cancel_check=cancel_check,
                ):
                    try:
                        svc_rel = str(svc.relative_to(project_root))
                    except Exception:
                        continue
                    read_targets.append({"path": svc_rel, "start_line": 1, "end_line": 240})
    for ep in (origin.get("top_sensitive_endpoints") or [])[:6]:
        rel = str(ep.get("file") or "")
        if rel:
            line = int(ep.get("line") or 1)
            read_targets.append({"path": rel, "start_line": max(1, line - 25), "end_line": line + 120})
    batch_files: list[dict] = []
    batch_seen: set[str] = set()
    for args in read_targets:
        if budgets["business_reads"] <= 0:
            break
        rel = str(args.get("path") or "")
        if not rel or rel in batch_seen:
            continue
        batch_seen.add(rel)
        batch_files.append(args)
        budgets["business_reads"] -= 1
    if batch_files:
        add("read_files_batch", {"files": batch_files, "per_file_char_limit": 5000})

    domain_kw = DOMAIN_SIGNALS.get(audit_domain, ())[:2] if audit_domain else ()
    sink_queries = sink_queries_for_focus(areas, limit=budgets["property_sinks"])
    if domain_kw:
        sink_queries = [f"{q} {domain_kw[0]}" for q in sink_queries]
    for q in sink_queries:
        if budgets["property_sinks"] <= 0:
            break
        add("search_code", {"query": q, "limit": 12})
        budgets["property_sinks"] -= 1

    guard_queries = list(NEGATIVE_GUARD_QUERIES[: budgets["negative_guards"]])
    if domain_kw:
        guard_queries = [f"{q} {domain_kw[0]}" for q in guard_queries]
    for q in guard_queries:
        if budgets["negative_guards"] <= 0:
            break
        add("search_code", {"query": q, "limit": 12})
        budgets["negative_guards"] -= 1

    for prio in (business_model.get("investigation_priorities") or [])[:4]:
        if budgets["priority_hypotheses"] <= 0:
            break
        target = str(prio.get("target") or "")
        hypothesis = str(prio.get("hypothesis") or "")
        kw = _keyword_from_priority(target, hypothesis)
        if kw:
            add("search_code", {"query": kw, "limit": 12})
            budgets["priority_hypotheses"] -= 1
        if budgets["priority_hypotheses"] > 0 and ("/" in target or target.upper().startswith(("GET", "POST", "PUT", "DELETE"))):
            add("list_endpoints", {"filter": target.split()[-1] if " " in target else target, "limit": 15})
            budgets["priority_hypotheses"] -= 1

    return planned


async def _run_bootstrap_investigation(
    project_path: Path,
    origin: dict,
    business_model: dict,
    *,
    scan_id: int | None,
    profile_cfg: AuditProfileConfig | None = None,
    focus_areas: list[str] | None = None,
    progress_callback=None,
    progress_offset: int = 0,
    progress_total: int | None = None,
) -> str:
    areas = normalize_focus_areas(focus_areas)
    cancel_check = (lambda: check_llm_audit_cancel(scan_id)) if scan_id else None
    if progress_callback and progress_total is not None:
        try:
            await progress_callback(
                progress_offset,
                progress_total,
                ["端点预调查 · 规划中（本地扫描，不耗 token）"],
            )
        except Exception:
            pass
    planned = await asyncio.to_thread(
        _plan_bootstrap_tools,
        origin,
        business_model,
        profile_cfg=profile_cfg,
        focus_areas=areas,
        cancel_check=cancel_check,
    )
    if not planned:
        return ""

    blocks: list[dict] = []
    sink_queries_used: list[str] = []
    for tool, args in planned:
        if scan_id:
            check_llm_audit_cancel(scan_id)
        if tool == "search_code":
            q = str((args or {}).get("query") or "")
            if q:
                sink_queries_used.append(q)
        started = time.perf_counter()
        raw = await asyncio.to_thread(execute_agent_tool, project_path, tool, args, scan_id=scan_id)
        if scan_id:
            check_llm_audit_cancel(scan_id)
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        if progress_callback and progress_total is not None:
            try:
                # Keep bootstrap from consuming the whole progress budget.
                span = max(1, min(3, int(progress_total)))
                i = len(blocks)
                mapped = progress_offset + int(((i + 1) / max(1, len(planned))) * span)
                await progress_callback(mapped, progress_total, [f"端点预调查 · {tool} ({i + 1}/{len(planned)})"])
            except Exception:
                pass
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw[:2000]}
        blocks.append({"tool": tool, "arguments": args, "result": payload})
        if scan_id:
            await log_llm_audit_journal(
                scan_id,
                "bootstrap_tool",
                {
                    "title": f"预调查: {tool}",
                    "tool": tool,
                    "arguments": args,
                    "elapsed_ms": elapsed_ms,
                },
            )

    if scan_id:
        high_risk = sorted(HIGH_RISK_SINK_FOCUS.intersection(areas))
        await log_llm_audit_journal(
            scan_id,
            "bootstrap_done",
            {
                "title": "自动预调查完成",
                "tool_count": len(blocks),
                "tools": [b["tool"] for b in blocks],
                "focus_areas": areas,
                "detail": "不占 Goal 迭代轮次，结果已注入后续分析",
            },
        )
        if high_risk:
            await log_llm_audit_journal(
                scan_id,
                "high_risk_sink_pass",
                {
                    "title": "高危 sink 预检索",
                    "focus_areas": high_risk,
                    "queries": sink_queries_used[:20],
                    "query_count": len(sink_queries_used),
                    "detail": "已按用户关注重点对命令执行/反序列化/注入等 sink 做端点侧预检索",
                },
            )
    return json.dumps(blocks, ensure_ascii=False, indent=2)


async def _run_goal_loop(
    project_path: Path,
    origin: dict,
    business_model: dict,
    *,
    focus: str,
    safety_max: int,
    scan_id: int | None = None,
    progress_callback=None,
    progress_offset: int = 0,
    progress_total: int | None = None,
    domain_label: str = "",
    log_global_complete: bool = True,
    profile_cfg: AuditProfileConfig | None = None,
    focus_areas: list[str] | None = None,
) -> dict:
    """One Goal iteration loop over a (possibly domain-sliced) Origin."""
    tool_specs = audit_tool_specs()
    bootstrap_payload = await _run_bootstrap_investigation(
        project_path,
        origin,
        business_model,
        scan_id=scan_id,
        profile_cfg=profile_cfg,
        focus_areas=focus_areas,
        progress_callback=progress_callback,
        progress_offset=progress_offset,
        progress_total=progress_total,
    )
    goal_content = _goal_user_message(
        origin, business_model, focus, safety_max, focus_areas=focus_areas
    )
    if bootstrap_payload:
        goal_content += (
            "\n\n【系统自动预调查（不占迭代轮次，请直接分析以下结果）】\n"
            f"{bootstrap_payload}\n\n"
            "请基于预调查结果继续 tool 补盲，或已有足够证据时直接 findings/finish。"
        )

    all_findings: list[dict] = []
    all_candidates: list[dict] = []
    last_summary = ""
    last_text = ""
    finished_normally = False
    tool_rounds = 0
    consecutive_tools = 0
    round_no = 0
    total_for_progress = progress_total if progress_total is not None else safety_max
    model = dict(business_model)

    messages: list[dict] = [
        {
            "role": "system",
            "content": AGENTIC_AUDIT_SYSTEM_PROMPT.format(tool_specs=tool_specs),
        },
        {
            "role": "user",
            "content": goal_content,
        },
    ]

    while round_no < safety_max:
        round_no += 1
        if scan_id:
            check_llm_audit_cancel(scan_id)

        if progress_callback:
            try:
                label = f"验证第 {round_no} 轮"
                if domain_label:
                    label = f"{domain_label} · {label}"
                await progress_callback(progress_offset + round_no, total_for_progress, [label])
            except Exception:
                pass

        areas = normalize_focus_areas(focus_areas)
        nudge = _soft_nudge_message(
            round_no,
            safety_max,
            consecutive_tools,
            finish_bias=(profile_cfg.finish_bias if profile_cfg else "normal"),
            high_risk_sink=bool(HIGH_RISK_SINK_FOCUS.intersection(areas)),
        )
        if nudge:
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "investigation_trace",
                    {
                        "title": f"收束提示 · 第 {round_no} 轮" + (f" · {domain_label}" if domain_label else ""),
                        "domain": domain_label or None,
                        "round": round_no,
                        "detail": nudge[:500],
                    },
                )
            messages.append({"role": "user", "content": nudge})

        try:
            last_text = await chat_completion(
                messages,
                task="deep",
                temperature=0.2,
                max_tokens=min(settings.llm_audit_max_tokens, 4096),
                timeout=effective_llm_timeout(5, task="deep"),
            )
            if scan_id:
                check_llm_audit_cancel(scan_id)
        except Exception as exc:
            logger.exception("Agentic audit LLM call failed round %s: %s", round_no, exc)
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "round_error",
                    {
                        "title": f"迭代 {round_no} 调用失败" + (f"（{domain_label}）" if domain_label else ""),
                        "error": format_llm_exception(exc)[:500],
                        "domain": domain_label or None,
                    },
                    level="error",
                )
            if all_findings:
                break
            raise

        parsed = parse_agent_response(last_text)
        if not parsed:
            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": "请仅输出合法 JSON：action=understand / tool / findings / finish。",
                }
            )
            continue

        action = parsed.get("action")

        if action == "understand":
            model = _understand_payload(parsed)
            if domain_label:
                model["focus_domain"] = domain_label
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "business_model",
                    {
                        "title": "业务理解（更新）" + (f" · {domain_label}" if domain_label else ""),
                        "round": round_no,
                        **model,
                    },
                )
            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "已更新业务理解。请用 tool 验证假设；"
                        "调查充分时主动 finish，有证据时 findings。"
                    ),
                }
            )
            consecutive_tools = 0
            continue

        if action == "candidates":
            candidate_payload = _candidate_payload(parsed)
            candidates = candidate_payload.get("candidates") or []
            all_candidates.extend(candidates if isinstance(candidates, list) else [])
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "candidate_batch",
                    {
                        "title": str(candidate_payload.get("note") or f"提交 {len(candidates)} 条高风险候选"),
                        "round": round_no,
                        "domain": domain_label or None,
                        "candidate_count": len(candidates),
                        "candidate_titles": [
                            str(c.get("title") or c.get("hypothesis") or "候选风险")
                            for c in candidates[:8]
                            if isinstance(c, dict)
                        ],
                    },
                    level="warning",
                )
            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"已记录 {len(candidates)} 条高风险候选（累计 {len(all_candidates)} 条）。"
                        "请继续用 tool 验证，能坐实则转为 findings；调查充分时 finish。"
                    ),
                }
            )
            consecutive_tools = 0
            continue

        if action == "finish":
            last_summary = str(parsed.get("audit_summary") or "")
            batch = _raw_to_findings(parsed.get("findings") or [], project_path)
            weak_batch: list[dict] = []
            if profile_cfg and profile_cfg.stronger_evidence:
                strong_batch = [item for item in batch if _has_stronger_evidence(item)]
                weak_batch = [item for item in batch if not _has_stronger_evidence(item)]
                batch = strong_batch
                for weak in weak_batch:
                    all_candidates.append(
                        {
                            "title": weak.get("message") or "证据不足风险",
                            "hypothesis": weak.get("ai_reason") or "",
                            "reason": "证据不足：未满足 stronger evidence 阈值",
                        }
                    )
            all_findings.extend(batch)
            finished_normally = True
            if scan_id and weak_batch:
                await log_llm_audit_journal(
                    scan_id,
                    "suppressed_findings_summary",
                    {
                        "title": "弱证据发现未直接入库" + (f" · {domain_label}" if domain_label else ""),
                        "domain": domain_label or None,
                        "suppressed_count": len(weak_batch),
                        "suppressed_titles": [it.get("message", "") for it in weak_batch[:8]],
                        "detail": "当前启用“要求更强证据才入库”，弱证据项已转为候选/待确认。",
                    },
                    level="warning",
                )
            if scan_id and log_global_complete:
                await log_llm_audit_journal(
                    scan_id,
                    "complete",
                    {
                        "title": "审计完成（LLM 自主结束）",
                        "audit_summary": last_summary or f"共 {len(all_findings)} 条发现",
                        "round": round_no,
                        "rounds_used": round_no,
                        "findings_count": len(all_findings),
                        "candidate_count": len(all_candidates),
                        "app_summary": model.get("app_summary", ""),
                        "finish_reason": "llm_finish",
                    },
                )
                await log_llm_audit_journal(
                    scan_id,
                    "finish_reason",
                    {
                        "title": "LLM 主动结束" + (f" · {domain_label}" if domain_label else ""),
                        "domain": domain_label or None,
                        "round": round_no,
                        "detail": last_summary[:500] or "调查充分后主动 finish",
                    },
                )
            break

        if action == "findings":
            note = str(parsed.get("note") or "")
            batch = _raw_to_findings(parsed.get("findings") or [], project_path)
            weak_batch: list[dict] = []
            if profile_cfg and profile_cfg.stronger_evidence:
                strong_batch = [item for item in batch if _has_stronger_evidence(item)]
                weak_batch = [item for item in batch if not _has_stronger_evidence(item)]
                batch = strong_batch
                for weak in weak_batch:
                    all_candidates.append(
                        {
                            "title": weak.get("message") or "证据不足风险",
                            "hypothesis": weak.get("ai_reason") or "",
                            "reason": "证据不足：未满足 stronger evidence 阈值",
                        }
                    )
            all_findings.extend(batch)
            consecutive_tools = 0
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "findings_batch",
                    {
                        "title": note or f"提交 {len(batch)} 条发现",
                        "round": round_no,
                        "domain": domain_label or None,
                        "findings_count": len(batch),
                        "finding_titles": [it.get("message", "") for it in batch[:6]],
                    },
                )
                if weak_batch:
                    await log_llm_audit_journal(
                        scan_id,
                        "suppressed_findings_summary",
                        {
                            "title": "本轮弱证据发现已抑制" + (f" · {domain_label}" if domain_label else ""),
                            "domain": domain_label or None,
                            "round": round_no,
                            "suppressed_count": len(weak_batch),
                            "suppressed_titles": [it.get("message", "") for it in weak_batch[:8]],
                            "detail": "已转入候选，不直接写入 findings。",
                        },
                        level="warning",
                    )
            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"已记录 {len(batch)} 条发现（累计 {len(all_findings)} 条）。"
                        "请继续验证其它业务假设，或 action=finish 结束。"
                    ),
                }
            )
            continue

        if action == "tool":
            tool_name = str(parsed.get("tool") or "")
            tool_args = parsed.get("arguments") or {}
            started = time.perf_counter()
            tool_result = await asyncio.to_thread(
                execute_agent_tool,
                project_path,
                tool_name,
                tool_args,
                scan_id=scan_id,
            )
            if scan_id:
                check_llm_audit_cancel(scan_id)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            tool_rounds += 1
            consecutive_tools += 1
            followup_hint = _tool_followup_hint(tool_name, tool_args, consecutive_tools)
            logger.info("Agentic audit round %s tool %s %s", round_no, tool_name, tool_args)

            if scan_id:
                trace_files: list[str] = []
                if tool_name == "read_file":
                    rel = str(tool_args.get("path") or "")
                    if rel:
                        trace_files.append(rel)
                elif tool_name == "read_files_batch":
                    for item in tool_args.get("files") or []:
                        if isinstance(item, dict) and item.get("path"):
                            trace_files.append(str(item.get("path")))
                elif tool_name == "search_code" and tool_args.get("file_hint"):
                    trace_files.append(str(tool_args.get("file_hint")))
                await log_llm_audit_journal(
                    scan_id,
                    "tool_round",
                    {
                        "title": f"验证 {round_no}: {tool_name}" + (f" · {domain_label}" if domain_label else ""),
                        "tool": tool_name,
                        "arguments": tool_args,
                        "domain": domain_label or None,
                        "trace_files": trace_files[:8],
                        "elapsed_ms": elapsed_ms,
                    },
                )
                if trace_files:
                    await log_llm_audit_journal(
                        scan_id,
                        "investigation_trace",
                        {
                            "title": f"读取/定位代码 · {tool_name}" + (f" · {domain_label}" if domain_label else ""),
                            "domain": domain_label or None,
                            "round": round_no,
                            "files": trace_files[:12],
                        },
                    )

            messages.append({"role": "assistant", "content": last_text})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"工具 `{tool_name}` 返回:\n{tool_result}\n\n"
                        "结合业务上下文分析：该结果是否支持或推翻某条假设？"
                        + (f"\n{followup_hint}" if followup_hint else "")
                        + "\n继续 tool 调查、更新 understand、提交 findings 或 finish。"
                    ),
                }
            )
            continue

        if action == "answer":
            last_summary = str(parsed.get("content") or "")
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "round_note",
                    {"title": f"迭代 {round_no} 备注", "content": last_summary[:500], "domain": domain_label or None},
                )
            break

    if not finished_normally:
        preserved_count = len(all_findings)
        salvage, salvage_summary = await _salvage_findings_on_timeout(
            messages,
            project_path,
            scan_id=scan_id,
            business_model=model,
            max_rounds=safety_max,
            already_collected=all_findings,
        )
        if profile_cfg and profile_cfg.stronger_evidence and salvage:
            strong_salvage = [item for item in salvage if _has_stronger_evidence(item)]
            weak_salvage = [item for item in salvage if not _has_stronger_evidence(item)]
            salvage = strong_salvage
            for weak in weak_salvage:
                all_candidates.append(
                    {
                        "title": weak.get("message") or "证据不足风险",
                        "hypothesis": weak.get("ai_reason") or "",
                        "reason": "证据不足：未满足 stronger evidence 阈值",
                    }
                )
            if scan_id and weak_salvage:
                await log_llm_audit_journal(
                    scan_id,
                    "suppressed_findings_summary",
                    {
                        "title": "收尾阶段弱证据发现已抑制" + (f" · {domain_label}" if domain_label else ""),
                        "domain": domain_label or None,
                        "suppressed_count": len(weak_salvage),
                        "suppressed_titles": [it.get("message", "") for it in weak_salvage[:8]],
                        "detail": "当前启用更强证据阈值，弱证据项已转候选。",
                    },
                    level="warning",
                )
        all_findings.extend(salvage)
        last_summary = salvage_summary

        if scan_id:
            detail_parts = [
                f"LLM 未主动 finish，已达安全上限 {safety_max} 轮（使用 {round_no} 轮，tool {tool_rounds} 次）",
                f"过程中已提交并保留 {preserved_count} 条",
                f"触顶收尾新提取 {len(salvage)} 条，合计 {len(all_findings)} 条",
            ]
            if domain_label:
                detail_parts.insert(0, f"业务域 {domain_label}")
            if not all_findings:
                detail_parts.append("未能提取漏洞；请提高安全上限或检查模型 finish 输出")
            elif preserved_count > 0 and len(salvage) == 0:
                detail_parts.append("过程中提交的漏洞已全部保留")

            await log_llm_audit_journal(
                scan_id,
                "iteration_limit",
                {
                    "title": "已达安全上限" + (f" · {domain_label}" if domain_label else ""),
                    "max_rounds": safety_max,
                    "rounds_used": round_no,
                    "tool_rounds": tool_rounds,
                    "domain": domain_label or None,
                    "preserved_from_batches": preserved_count,
                    "salvaged_count": len(salvage),
                    "findings_total": len(all_findings),
                    "candidate_count": len(all_candidates),
                    "detail": "；".join(detail_parts),
                    "audit_summary": last_summary[:500] if last_summary else "",
                    "finish_reason": "iteration_limit",
                },
                level="warning" if not all_findings else "info",
            )
            await log_llm_audit_journal(
                scan_id,
                "finish_reason",
                {
                    "title": "达到安全上限" + (f" · {domain_label}" if domain_label else ""),
                    "domain": domain_label or None,
                    "detail": "未主动 finish，已使用收尾 salvage 汇总发现。",
                    "rounds_used": round_no,
                    "tool_rounds": tool_rounds,
                },
                level="warning",
            )

    return {
        "findings": all_findings,
        "candidates": all_candidates,
        "finished_normally": finished_normally,
        "round_no": round_no,
        "tool_rounds": tool_rounds,
        "last_summary": last_summary,
        "business_model": model,
    }


async def run_agentic_endpoint_audit(
    project_path: Path,
    categories: list[FindingCategory] | None = None,
    *,
    scan_id: int | None = None,
    progress_callback=None,
) -> list[dict]:
    """Origin summary → Understand → Top-N domain Goal batches → merge findings."""
    if not is_llm_configured():
        return []

    units = await asyncio.to_thread(discover_controller_units, project_path)
    origin_summary = await asyncio.to_thread(build_origin_summary, project_path, units)
    if origin_summary["controller_count"] == 0 and not origin_summary["top_sensitive_endpoints"]:
        if scan_id:
            await log_llm_audit_journal(
                scan_id,
                "error",
                {"title": "未发现 HTTP 端点", "detail": "项目中未识别到 Spring/Flask/Express/NestJS/Koa 等 HTTP 路由"},
                level="warning",
            )
        raise NoHttpEndpointsDetected("项目中未识别到 Spring/Flask/Express/NestJS/Koa 等 HTTP 路由")

    safety_max = settings.llm_endpoint_audit_max_iterations
    max_domains = settings.llm_endpoint_audit_max_domains
    focus_areas = resolve_focus_areas(categories)
    focus = _focus_hint(categories, focus_areas)
    clustered = cluster_endpoints_by_domain(units)
    profile_cfg = resolve_audit_profile_config()
    safety_max = profile_cfg.max_iterations
    max_domains = profile_cfg.max_domains

    if scan_id:
        await log_llm_audit_journal(
            scan_id,
            "settings_snapshot",
            {
                "title": "审计策略快照",
                "profile": profile_cfg.profile,
                "stronger_evidence": profile_cfg.stronger_evidence,
                "broader_hypotheses": profile_cfg.broader_hypotheses,
                "focus_areas": focus_areas,
                "focus_labels": [LLM_AUDIT_FOCUS_LABELS.get(a, a) for a in focus_areas],
                "config": {
                    "max_iterations": profile_cfg.max_iterations,
                    "max_domains": profile_cfg.max_domains,
                    "max_controllers": profile_cfg.max_controllers,
                    "max_related_files": profile_cfg.max_related_files,
                    "agent_max_tool_rounds": profile_cfg.agent_max_tool_rounds,
                    "finish_bias": profile_cfg.finish_bias,
                },
            },
        )
        await log_llm_audit_journal(
            scan_id,
            "plan",
            {
                "title": "审计方案",
                "methodology": [
                    "Origin — 轻量摘要（域样例 + 高敏端点，不含完整 controllers）",
                    "Understand — LLM 读懂业务、角色、流程与信任边界",
                    f"Domain batches — 按风险选出最多 {max_domains} 个业务域分批 Goal",
                    "Bootstrap — 域内预调查（按关注重点裁剪 sink 词表，不占轮次）",
                    "Goal — LLM 自主 tool/findings，自行决定何时 finish",
                    f"安全上限合计 {safety_max} 轮，按域均分",
                ],
                "architecture": {
                    "overview": "轻量 Origin → 业务理解 → 分域 Goal → 合并去重",
                    "pipeline": [
                        "1. Origin 摘要 — 全量统计 + 域样例",
                        "2. Understand — 推断系统与调查优先级",
                        "3. 选出 Top-N 高风险业务域",
                        "4. 每域 Bootstrap + Goal 验证",
                        "5. Findings 合并去重",
                    ],
                },
                "config": {
                    "safety_max_rounds": safety_max,
                    "max_domains": max_domains,
                    "sample_per_domain": settings.llm_endpoint_origin_sample_per_domain,
                    "max_controllers_per_domain": profile_cfg.max_controllers,
                    "max_related_files": profile_cfg.max_related_files,
                    "profile": profile_cfg.profile,
                    "focus_areas": focus_areas,
                    "iteration_mode": "llm_controlled_domain_batches",
                    "focus": focus or "无（完全自主）",
                },
            },
        )
        await log_llm_audit_journal(
            scan_id,
            "inventory",
            {
                "title": "端点清单（Origin 摘要）",
                "controller_count": origin_summary["controller_count"],
                "endpoint_count": origin_summary["endpoint_count"],
                "business_domains": origin_summary.get("business_domains", []),
                "top_sensitive_endpoints": origin_summary["top_sensitive_endpoints"][:15],
            },
        )

    if progress_callback:
        try:
            await progress_callback(0, safety_max, ["业务理解中…"])
        except Exception:
            pass

    business_model = await _run_business_comprehension(origin_summary, scan_id=scan_id, focus=focus)
    ranked_domains = _rank_audit_domains(clustered, business_model)
    selected_domains = [str(item["domain"]) for item in ranked_domains[:max_domains]]
    domain_count = max(1, len(selected_domains))
    rounds_per_domain = max(8, safety_max // domain_count)
    if rounds_per_domain * domain_count > safety_max + domain_count:
        rounds_per_domain = max(5, safety_max // domain_count)
    progress_total = rounds_per_domain * domain_count

    if scan_id:
        await log_llm_audit_journal(
            scan_id,
            "domain_selection",
            {
                "title": "业务域选择结果",
                "selected_domains": selected_domains,
                "ranked_domains": ranked_domains[:10],
                "detail": f"从 {len(ranked_domains)} 个业务域中选出 {len(selected_domains)} 个进入 Goal 深挖",
            },
        )
        await log_llm_audit_journal(
            scan_id,
            "plan",
            {
                "title": "分域深度审计计划",
                "selected_domains": selected_domains,
                "rounds_per_domain": rounds_per_domain,
                "max_domains": max_domains,
                "detail": f"将依次审计 {len(selected_domains)} 个业务域，每域约 {rounds_per_domain} 轮",
            },
        )

    all_findings: list[dict] = []
    all_candidates: list[dict] = []
    summaries: list[str] = []
    total_rounds = 0
    total_tools = 0

    for idx, domain_name in enumerate(selected_domains):
        if scan_id:
            check_llm_audit_cancel(scan_id)
            await log_llm_audit_journal(
                scan_id,
                "domain_batch_start",
                {
                    "title": f"正在审计：{domain_name} ({idx + 1}/{len(selected_domains)})",
                    "domain": domain_name,
                    "index": idx + 1,
                    "total": len(selected_domains),
                    "rounds_budget": rounds_per_domain,
                },
            )

        if progress_callback:
            try:
                await progress_callback(
                    idx * rounds_per_domain,
                    progress_total,
                    [f"正在审计：{domain_name} ({idx + 1}/{len(selected_domains)})"],
                )
            except Exception:
                pass

        domain_origin = await asyncio.to_thread(
            build_domain_slice,
            project_path,
            units,
            domain_name,
            max_controllers=profile_cfg.max_controllers,
        )
        if not domain_origin.get("controllers") and not domain_origin.get("top_sensitive_endpoints"):
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "domain_batch_done",
                    {
                        "title": f"跳过空域：{domain_name}",
                        "domain": domain_name,
                        "findings_count": 0,
                        "detail": "该域未匹配到 Controller/端点",
                    },
                    level="warning",
                )
            continue

        domain_model = _domain_focused_business_model(business_model, domain_name)
        result = await _run_goal_loop(
            project_path,
            domain_origin,
            domain_model,
            focus=focus,
            safety_max=rounds_per_domain,
            scan_id=scan_id,
            progress_callback=progress_callback,
            progress_offset=idx * rounds_per_domain,
            progress_total=progress_total,
            domain_label=domain_name,
            log_global_complete=False,
            profile_cfg=profile_cfg,
            focus_areas=focus_areas,
        )
        batch_findings = result.get("findings") or []
        all_findings.extend(batch_findings)
        all_candidates.extend(result.get("candidates") or [])
        total_rounds += int(result.get("round_no") or 0)
        total_tools += int(result.get("tool_rounds") or 0)
        if result.get("last_summary"):
            summaries.append(f"[{domain_name}] {result['last_summary']}")

        if scan_id:
            await log_llm_audit_journal(
                scan_id,
                "domain_batch_done",
                {
                    "title": f"完成审计：{domain_name} ({idx + 1}/{len(selected_domains)})",
                    "domain": domain_name,
                    "index": idx + 1,
                    "total": len(selected_domains),
                    "findings_count": len(batch_findings),
                    "rounds_used": result.get("round_no"),
                    "finished_normally": result.get("finished_normally"),
                    "audit_summary": (result.get("last_summary") or "")[:500],
                },
            )

    merged = normalize_and_dedupe_llm_findings(all_findings)
    if scan_id:
        await log_llm_audit_journal(
            scan_id,
            "coverage_summary",
            {
                "title": "覆盖摘要",
                "domains_selected": selected_domains,
                "domains_audited": selected_domains,
                "rounds_used": total_rounds,
                "tool_rounds": total_tools,
                "findings_before_dedupe": len(all_findings),
                "findings_after_dedupe": len(merged),
                "candidate_count": len(all_candidates),
                "detail": f"共审计 {len(selected_domains)} 个业务域，累计 {total_tools} 次工具调查。",
            },
        )
        await log_llm_audit_journal(
            scan_id,
            "complete",
            {
                "title": "分域审计全部完成",
                "audit_summary": "；".join(summaries)[:800] or f"共 {len(merged)} 条发现（已去重）",
                "domains_audited": selected_domains,
                "rounds_used": total_rounds,
                "tool_rounds": total_tools,
                "findings_count": len(merged),
                "candidate_count": len(all_candidates),
                "app_summary": business_model.get("app_summary", ""),
            },
        )
        if is_llm_audit_cancel_requested(scan_id):
            await log_llm_audit_journal(
                scan_id,
                "cancelled",
                {"title": "审计已暂停", "findings_so_far": len(merged)},
                level="warning",
            )

    return merged


async def run_endpoint_driven_audit(
    project_path: Path,
    categories: list[FindingCategory] | None = None,
    *,
    scan_id: int | None = None,
    progress_callback=None,
) -> list[dict]:
    """Run agentic endpoint audit (primary entry)."""
    try:
        return await run_agentic_endpoint_audit(
            project_path,
            categories,
            scan_id=scan_id,
            progress_callback=progress_callback,
        )
    except LlmAuditCancelled:
        raise
