"""LLM deep code audit: business logic flaws and authorization vulnerabilities."""

import asyncio
import json
import logging
from pathlib import Path

from app.config import settings
from app.models import AiVerdict, FindingCategory, Severity
from app.services.file_service import read_file_with_context
from app.services.path_filters import is_test_path
from app.services.project_archetype_service import (
    ARCHETYPE_LABELS,
    ArchetypeHit,
    ArchetypeScoreProfile,
    clear_archetype_cache,
    detect_archetypes,
    format_summary,
    score_profile,
    summarize as summarize_archetypes,
)
from app.services.scanners.common import to_repo_relative_path
from app.services.scan_diff_service import _normalize_path
from app.services.llm_provider import (
    chat_completion,
    effective_llm_timeout,
    extract_json_from_llm_text,
    is_llm_configured,
    llm_not_configured_message,
    parse_llm_structured_response,
)
from app.services.llm_audit_runtime import LlmAuditCancelled
from app.services.llm_archetype_lens import (
    build_lens_prompt,
    collect_lens_files,
    lens_types,
)
from app.services.llm_service import normalize_fp_results, verdict_from_str

logger = logging.getLogger(__name__)

CODE_EXTENSIONS = {
    ".py", ".java", ".go", ".js", ".ts", ".tsx", ".jsx",
    ".php", ".rb", ".cs", ".kt", ".rs", ".vue",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build",
    "vendor", "target", ".idea", ".vscode", "coverage", ".next",
}

RELEVANCE_KEYWORDS = [
    "auth", "login", "logout", "permission", "role", "admin", "access",
    "token", "jwt", "oauth", "session", "user", "account", "password",
    "api", "route", "router", "controller", "handler", "middleware",
    "guard", "policy", "acl", "rbac", "privilege", "order", "payment",
    "transfer", "withdraw", "approve", "verify", "coupon", "discount",
]

BUSINESS_LOGIC_PROMPT = """你是一名资深应用安全专家，专注审计**业务逻辑漏洞**。

重点检测（但不限于）：
- 业务流程绕过（跳过校验步骤、状态机跳转）
- 竞态条件（并发下单、重复领取、余额双花）
- 支付/转账/积分等业务数值篡改
- 优惠券/折扣叠加滥用、限购绕过
- 审批流绕过、工单状态非法变更
- 时间窗口/重放类业务缺陷
- 资源耗尽或未限制频率的敏感操作

**请勿在本类报告中输出以下内容（应留给越权/访问控制审计）：**
- 水平越权、垂直越权、IDOR、未鉴权/未授权访问
- 缺失登录校验、缺失角色/资源归属校验、权限提升
- Mass Assignment、JWT/Session 角色篡改、API 权限绕过
- 任何以「越权」「访问控制」「鉴权」为核心的问题

分析提供的源代码，输出 JSON 数组（无问题时返回 []）。每条结果的 category 必须为 business_logic：
{
  "category": "business_logic",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "title": "漏洞标题（中文）",
  "description": "漏洞描述与影响",
  "file": "相对路径",
  "line_start": 1,
  "line_end": 10,
  "evidence": "关键代码片段",
  "api_endpoint": "HTTP 方法与路径（如 GET /api/order/{id}，未知写 unknown），勿混入文件行号",
  "endpoint_code_ref": "接口入口代码位置（相对路径:行号，如 controllers/OrderController.java:42；与漏洞 sink 行区分开，未知可省略）",
  "data_source": "数据来源（例如请求参数 userId / body.amount / token.claims.uid）",
  "data_flow": "数据链路（抽象步骤用 -> 连接，如 请求参数 -> 校验 -> Service.method -> 写库；某步有明确代码请加 相对路径:行号）",
  "trigger_point": "触发点（优先写 相对路径:行号 或 Class.method(...)）",
  "risk_tags": ["可选：从 ssrf/prompt_injection/agent_tool_abuse/sensitive_data_exposure/injection/business_flow/race_condition/rate_limit/session/authz/idor/mass_assignment 中选择 1-3 个最贴切标签"],
  "attack_scenario": "攻击场景/复现思路",
  "recommendation": "修复建议",
  "confidence": 0.0-1.0
}
只输出 JSON 数组，不要其他文字。基于代码事实分析，不要臆造不存在的接口。"""

AUTHORIZATION_PROMPT = """你是一名资深应用安全专家，专注审计**越权与访问控制漏洞**。

重点检测（但不限于）：
- 水平越权（IDOR）：访问/修改他人数据（用户ID、订单ID等可控参数）
- 垂直越权：普通用户调用管理员接口或高权限功能
- 缺失鉴权：敏感接口未校验登录态
- 缺失授权：已登录但未校验资源归属或角色权限
- 前端/客户端信任：仅在前端隐藏按钮，后端未校验
- 批量赋值导致权限提升（mass assignment）
- API 路径/方法绕过（如 /admin 与 /api/admin 不一致防护）
- JWT/Session 中角色字段可被篡改或缺少校验

**请勿在本类报告中输出纯业务逻辑问题**（如竞态双花、优惠券叠加、支付金额篡改等）。

分析提供的源代码，输出 JSON 数组（无问题时返回 []）。每条结果的 category 必须为 authorization：
{
  "category": "authorization",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "title": "漏洞标题（中文）",
  "description": "漏洞描述与影响",
  "file": "相对路径",
  "line_start": 1,
  "line_end": 10,
  "evidence": "关键代码片段",
  "api_endpoint": "HTTP 方法与路径（如 GET /api/user/{id}，未知写 unknown），勿混入文件行号",
  "endpoint_code_ref": "接口入口代码位置（相对路径:行号，如 controllers/UserController.java:42；与漏洞 sink 行区分开，未知可省略）",
  "data_source": "数据来源（例如 path.id / query.userId / token.role）",
  "data_flow": "数据链路（抽象步骤用 -> 连接，如 路径参数 -> 鉴权 -> 授权校验 -> 敏感操作；某步有明确代码请加 相对路径:行号）",
  "trigger_point": "触发点（优先写 相对路径:行号 或 Class.method(...)）",
  "risk_tags": ["可选：从 authz/idor/privilege_escalation/mass_assignment/session/jwt/access_control 中选择 1-3 个最贴切标签"],
  "attack_scenario": "攻击场景/复现思路",
  "recommendation": "修复建议",
  "confidence": 0.0-1.0
}
只输出 JSON 数组，不要其他文字。基于代码事实分析，不要臆造不存在的接口。"""

# 用于将误标为 business_logic 的越权类发现归到 authorization
AUTHZ_SIGNAL_KEYWORDS = [
    "越权", "idor", "未鉴权", "未授权", "缺鉴权", "缺失鉴权", "缺少鉴权", "缺乏鉴权",
    "无鉴权", "可无权限", "访问控制", "水平越权", "垂直越权", "权限提升",
    "privilege", "unauthorized", "access control", "mass assignment", "批量赋值",
    "数据隔离", "匿名端点", "任意用户", "未校验权限", "缺乏权限校验", "缺失授权",
    "未校验角色", "鉴权缺失", "权限校验缺失", "role escalation",
]

DEDUP_LINE_TOLERANCE = 30

NON_VULN_POSITIVE_HINTS = [
    "实现正确", "验证合理", "校验通过", "校验有效", "权限正确", "逻辑正确",
    "未发现风险", "未发现漏洞", "无安全风险", "无风险", "安全实现", "符合预期",
    "签名验证合理", "审批权限实现正确", "鉴权完整", "验证通过", "安全",
]
NON_VULN_RISK_HINTS = [
    "存在", "缺失", "可绕过", "可伪造", "可被", "未校验", "未授权", "越权",
    "漏洞", "风险", "攻击", "绕过", "注入", "伪造", "泄露", "高危", "中危", "低危",
    "缺陷", "失效", "错误", "未限制",
]
NON_VULN_NEGATING_PHRASES = [
    "未发现风险", "未发现漏洞", "无风险", "不存在风险", "没有风险",
    "风险可控", "未见风险", "未见漏洞", "未发现明显风险",
]

RISK_TAG_LABELS = {
    "ssrf": "SSRF",
    "prompt_injection": "Prompt 注入",
    "agent_tool_abuse": "Agent 工具滥用",
    "sensitive_data_exposure": "敏感数据泄露",
    "injection": "注入",
    "rce": "命令执行/RCE",
    "deserialization": "不安全反序列化",
    "business_flow": "业务流程绕过",
    "race_condition": "竞态条件",
    "rate_limit": "频控缺失",
    "session": "会话失效",
    "jwt": "JWT 风险",
    "authz": "访问控制",
    "idor": "IDOR",
    "privilege_escalation": "权限提升",
    "mass_assignment": "批量赋值",
    "access_control": "访问控制",
    # 形态专属视角（MQ / 定时任务 / RPC / SDK / CLI）会用到的标签
    "insecure_default": "不安全默认值",
    "crypto_misuse": "加解密误用",
    "supply_chain": "依赖/供应链",
    "message_trust": "消息来源不可信",
    "idempotency": "幂等缺失",
    "internal_trust": "内部接口默认信任",
}

RISK_TAG_RULES = [
    ("prompt_injection", ("prompt injection", "prompt注入", "prompt 注入", "system prompt", "messages", "提示词")),
    ("agent_tool_abuse", ("tool call", "工具调用", "function call", "agent", "工具滥用", "外部工具")),
    ("ssrf", ("ssrf", "metadata地址", "metadata 地址", "169.254.169.254", "内网探测", "url.openconnection", "resttemplate", "webclient", "okhttp")),
    ("sensitive_data_exposure", ("敏感数据", "数据泄露", "secret", "token泄露", "token 泄露", "credential", "密钥")),
    ("rce", ("命令执行", "remote code", "rce", "runtime.exec", "processbuilder", "os.system", "subprocess")),
    ("deserialization", ("反序列化", "deserialization", "objectinputstream", "readobject", "pickle.loads", "yaml.load", "unserialize")),
    ("injection", ("sql注入", "sql 注入", "命令注入", "template injection", "ssti", "注入", "spel", "ognl")),
    ("race_condition", ("竞态", "并发", "双花", "重复领取", "重复触发")),
    ("rate_limit", ("频率限制", "rate limit", "cooldown", "验证码", "暴力尝试", "短信轰炸")),
    ("session", ("session", "单点登出", "会话失效", "revocation", "jti")),
    ("jwt", ("jwt", "token role", "role claim", "token.claims")),
    ("idor", ("idor", "水平越权", "任意用户", "资源归属")),
    ("privilege_escalation", ("垂直越权", "管理员接口", "权限提升", "高权限功能")),
    ("mass_assignment", ("mass assignment", "批量赋值")),
    # 形态专属标签：放在最后，让通用标签优先占满 tags[:3] 的名额
    ("insecure_default", ("默认值", "默认开启", "默认关闭", "默认配置", "默认密钥", "默认口令", "insecure default", "default value")),
    ("crypto_misuse", ("ecb", "固定 iv", "iv 固定", "弱算法", "md5", "sha1", "密钥硬编码", "加解密", "加密模式", "非 csp", "csprng", "hmac", "签名校验")),
    ("supply_chain", ("供应链", "依赖版本", "动态加载", "远程加载", "从网络下载", "supply chain", "第三方组件")),
    ("message_trust", ("消息体", "消息内容", "消息队列", "消费端", "重复投递", "kafka", "rabbitmq", "rocketmq", "topic", "queue")),
    ("idempotency", ("幂等", "重复消费", "重复执行", "重复扣款", "重复发券", "重复发货", "idempot")),
    ("internal_trust", ("信任内网", "内部接口", "内部调用", "来源校验", "调用来源", "rpc 上下文", "rpccontext", "attachment", "泛化调用")),
]


def _score_file(path: Path, profile: ArchetypeScoreProfile | None = None) -> int:
    """给候选源文件打分。

    `profile` 为 None 时是**原来的纯关键词打分**（HTTP 服务视角）。
    传入形态 profile 后：
    - 命中形态关键词加分（`crypto/cipher.go` 这类基础能力文件被抬上来）
    - 项目不是 HTTP 服务时，`api/routes/controllers` 这类目录被降权
    - `exclude_test_paths` 打开时，测试文件降权（避免 `tests/test_auth.py`
      靠文件名里的 `auth` 白吃采样配额）
    """
    score = 0
    name_lower = path.name.lower()
    parts_lower = "/".join(path.parts).lower()

    for kw in RELEVANCE_KEYWORDS:
        if kw in name_lower:
            score += 3
        if kw in parts_lower:
            score += 1

    if any(x in name_lower for x in ("main", "app", "server", "index")):
        score += 2
    if any(x in parts_lower for x in ("api", "routes", "controllers", "handlers", "views", "middleware")):
        score += 3

    if profile is not None and profile.active:
        for kw, weight in profile.positive.items():
            if kw in name_lower:
                score += weight
            elif kw in parts_lower:
                # 目录里出现只是弱证据，权重折半（向上取整）
                score += max(1, weight // 2)
        for kw, weight in profile.negative.items():
            if kw in name_lower:
                score -= weight
            elif kw in parts_lower:
                score -= max(1, weight // 2)
        if profile.test_penalty and is_test_path(path):
            score -= profile.test_penalty

    return score


def collect_audit_files(
    project_path: Path,
    max_files: int | None = None,
    *,
    archetypes: list[ArchetypeHit] | None = None,
) -> list[Path]:
    """Collect high-value source files for LLM audit.

    `archetypes` 为 None 时自动识别项目形态并据此加权；传空列表可显式关闭加权
    （回到旧的纯 HTTP 关键词打分）。
    """
    limit = max_files or settings.llm_audit_max_files
    profile = None
    if archetypes is None:
        archetypes = detect_archetypes(project_path)
    if archetypes:
        profile = score_profile(archetypes)
    candidates: list[tuple[int, Path]] = []

    for path in project_path.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.stat().st_size > 200_000:
            continue

        rel = path.relative_to(project_path)
        score = _score_file(rel, profile)
        candidates.append((score, path))

    candidates.sort(key=lambda x: (-x[0], str(x[1])))
    selected = [p for _, p in candidates[:limit]]

    if not selected:
        for path in project_path.rglob("*"):
            if path.is_file() and path.suffix.lower() in CODE_EXTENSIONS:
                if not any(skip in path.parts for skip in SKIP_DIRS):
                    selected.append(path)
                    if len(selected) >= limit:
                        break

    return selected


def _read_file_chunk(path: Path, project_path: Path) -> dict:
    rel = str(path.relative_to(project_path))
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        content = ""
    max_chars = settings.llm_audit_file_max_chars
    if len(content) > max_chars:
        content = content[:max_chars] + "\n... [truncated]"
    return {"file": rel, "content": content}


def _parse_llm_json(text: str) -> list[dict]:
    data = parse_llm_structured_response(text)
    if data is None:
        raise ValueError(f"LLM 返回为空或非 JSON: {(text or '')[:200]}")
    if isinstance(data, dict):
        findings = data.get("findings", data.get("issues", [data]))
        return findings if isinstance(findings, list) else [data]
    return data if isinstance(data, list) else []


def _safe_confidence(val: object, default: float = 0.7) -> float:
    try:
        return float(val)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _severity_from_str(raw: str) -> Severity:
    upper = (raw or "MEDIUM").upper()
    return Severity(upper) if upper in Severity.__members__ else Severity.MEDIUM


def _category_from_str(raw: str, default: FindingCategory) -> FindingCategory:
    mapping = {
        "business_logic": FindingCategory.BUSINESS_LOGIC,
        "business": FindingCategory.BUSINESS_LOGIC,
        "authorization": FindingCategory.AUTHORIZATION,
        "authz": FindingCategory.AUTHORIZATION,
        "access_control": FindingCategory.AUTHORIZATION,
        "llm": FindingCategory.BUSINESS_LOGIC,
        "llm_security": FindingCategory.BUSINESS_LOGIC,
        "prompt_injection": FindingCategory.BUSINESS_LOGIC,
        "ai": FindingCategory.BUSINESS_LOGIC,
        "ai_security": FindingCategory.BUSINESS_LOGIC,
    }
    return mapping.get((raw or "").lower().replace("-", "_"), default)


def _finding_text_blob(finding: dict) -> str:
    parts = [
        finding.get("message", ""),
        finding.get("ai_reason", ""),
        finding.get("metadata_json", ""),
    ]
    return " ".join(str(p) for p in parts).lower()


def _normalize_risk_tag(tag: object) -> str | None:
    raw = str(tag or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "prompt": "prompt_injection",
        "ai_prompt_injection": "prompt_injection",
        "tool_abuse": "agent_tool_abuse",
        "agent_abuse": "agent_tool_abuse",
        "data_exposure": "sensitive_data_exposure",
        "sensitive_data_leak": "sensitive_data_exposure",
        "business_logic": "business_flow",
        "logic_bypass": "business_flow",
        "race": "race_condition",
        "rate_limit_missing": "rate_limit",
        "authorization": "authz",
        "access_control": "access_control",
        "horizontal_authz": "idor",
        "vertical_authz": "privilege_escalation",
    }
    norm = aliases.get(raw, raw)
    return norm if norm in RISK_TAG_LABELS else None


def infer_risk_tags(item: dict, category: FindingCategory) -> list[str]:
    tags: list[str] = []
    explicit = item.get("risk_tags")
    if isinstance(explicit, list):
        for tag in explicit:
            norm = _normalize_risk_tag(tag)
            if norm and norm not in tags:
                tags.append(norm)

    text = " ".join(
        str(item.get(k) or "")
        for k in (
            "title",
            "message",
            "description",
            "evidence",
            "attack_scenario",
            "recommendation",
            "data_source",
            "data_flow",
            "trigger_point",
            "source",
            "sink",
            "missing_guard",
            "impact",
            "api_endpoint",
        )
    ).lower()
    for tag, keywords in RISK_TAG_RULES:
        if tag in tags:
            continue
        if any(kw in text for kw in keywords):
            tags.append(tag)

    if category == FindingCategory.AUTHORIZATION:
        if any(k in text for k in ("idor", "水平越权", "归属", "他人数据")) and "idor" not in tags:
            tags.append("idor")
        elif any(k in text for k in ("垂直越权", "管理员", "高权限")) and "privilege_escalation" not in tags:
            tags.append("privilege_escalation")
        elif "authz" not in tags:
            tags.append("authz")
    elif category == FindingCategory.BUSINESS_LOGIC and not tags:
        tags.append("business_flow")

    return tags[:3]


def is_non_vuln_confirmation_text(*texts: object) -> bool:
    merged = " ".join(str(t or "") for t in texts).strip().lower()
    if not merged:
        return False
    has_positive = any(k in merged for k in NON_VULN_POSITIVE_HINTS)
    has_negating = any(k in merged for k in NON_VULN_NEGATING_PHRASES)
    has_risk = any(k in merged for k in NON_VULN_RISK_HINTS) and not has_negating
    return has_positive and not has_risk


def _looks_like_authorization(finding: dict) -> bool:
    text = _finding_text_blob(finding)
    return any(kw in text for kw in AUTHZ_SIGNAL_KEYWORDS)


def _reclassify_to_authorization(finding: dict) -> dict:
    title = finding.get("message", "潜在越权问题")
    return {
        **finding,
        "category": FindingCategory.AUTHORIZATION,
        "rule_id": f"llm.authorization.{title[:80]}",
    }


def _lines_overlap(f1: dict, f2: dict, tolerance: int = DEDUP_LINE_TOLERANCE) -> bool:
    a_start = int(f1.get("line_start") or 0)
    a_end = int(f1.get("line_end") or a_start)
    b_start = int(f2.get("line_start") or 0)
    b_end = int(f2.get("line_end") or b_start)
    a_lo, a_hi = min(a_start, a_end), max(a_start, a_end)
    b_lo, b_hi = min(b_start, b_end), max(b_start, b_end)
    if a_lo == 0 and b_lo == 0:
        return True
    if a_hi == 0 or b_hi == 0:
        return abs(a_lo - b_lo) <= tolerance
    return not (a_hi + tolerance < b_lo or b_hi + tolerance < a_lo)


def _same_file(f1: dict, f2: dict) -> bool:
    """同一文件判定：比较归一化后的仓库内相对路径。

    原来只比 basename，于是 `a/config.py` 和 `b/config.py` 会被当成同一个文件，
    同一行区间上的两条 finding 被错并成一条，真漏洞就这么没了。改成比归一化
    路径后，盘符 / `data/repos/<hash>/` / `data/uploads/<run>/<ver>/` 前缀的
    差异仍然会被抹平，跨目录同名文件则正确区分开。

    保留一个退化分支：LLM 有时只回一个光秃秃的文件名（没有目录），这时仍按
    文件名比较，否则这类 finding 永远合不进带目录的同一文件。
    """
    p1 = _normalize_path(str(f1.get("file_path") or ""))
    p2 = _normalize_path(str(f2.get("file_path") or ""))
    if not p1 or not p2:
        return False
    if p1 == p2:
        return True
    if "/" not in p1 or "/" not in p2:
        return p1.rsplit("/", 1)[-1] == p2.rsplit("/", 1)[-1]
    return False


def _findings_duplicate(a: dict, b: dict) -> bool:
    return _same_file(a, b) and _lines_overlap(a, b)


def _severity_rank_for_priority(severity) -> int:
    """严重级别 → 排序位，越小越严重（``Severity`` 的声明顺序即严重度顺序）。

    枚举和字符串两种形态都要认。``Severity`` 是 str 枚举，`list.index` 对
    `"HIGH"` 这类字符串同样成立，只是大小写敏感，所以先归一化再比。
    """
    if isinstance(severity, Severity):
        return list(Severity).index(severity)
    text = str(severity or "").strip().upper()
    try:
        return list(Severity).index(Severity(text))
    except ValueError:
        return len(Severity)


def _finding_priority_key(finding: dict) -> tuple:
    """Lower tuple = higher priority to keep."""
    cat_rank = 0 if finding.get("category") == FindingCategory.AUTHORIZATION else 1
    confidence = float(finding.get("ai_confidence") or 0)
    # 这里原来写的是 `-list(Severity).index(...)`，取负之后排序意图正好反过来：
    # 严重级别越低排序位越小，于是同一漏洞的两条 finding 在类别和置信度都相同时
    # （很常见——它们本来就是同一个漏洞的两条描述），被留下的反而是 MEDIUM 而不是
    # CRITICAL。去掉负号即为「越小越严重」。
    sev_rank = _severity_rank_for_priority(finding.get("severity"))
    return (cat_rank, -confidence, sev_rank)


def normalize_and_dedupe_llm_findings(findings: list[dict]) -> list[dict]:
    """Reclassify authz issues out of business_logic, then merge by overlap."""
    if not findings:
        return []

    normalized: list[dict] = []
    for item in findings:
        if item.get("category") == FindingCategory.BUSINESS_LOGIC and _looks_like_authorization(item):
            normalized.append(_reclassify_to_authorization(item))
        else:
            normalized.append(item)

    groups: list[list[dict]] = []
    for item in normalized:
        matched = False
        for group in groups:
            if _findings_duplicate(group[0], item):
                group.append(item)
                matched = True
                break
        if not matched:
            groups.append([item])

    deduped = [min(group, key=_finding_priority_key) for group in groups]
    if len(deduped) < len(findings):
        logger.info(
            "LLM findings normalized/deduped: %s -> %s",
            len(findings),
            len(deduped),
        )
    return deduped


def finding_to_dedupe_ref(finding) -> dict:
    """Normalize ORM Finding or dict into a comparable dedupe reference."""
    if hasattr(finding, "file_path"):
        return {
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "category": finding.category,
            "message": finding.message,
            "tool": getattr(finding, "tool", None) or "llm",
            "rule_id": getattr(finding, "rule_id", None) or "",
            "message_zh": getattr(finding, "message_zh", None),
            "owasp_id": getattr(finding, "owasp_id", None) or "",
            "vuln_subtype": getattr(finding, "vuln_subtype", None) or "",
        }
    return {
        "file_path": finding.get("file_path", ""),
        "line_start": finding.get("line_start", 0),
        "line_end": finding.get("line_end", 0),
        "category": finding.get("category"),
        "message": finding.get("message", ""),
        "tool": finding.get("tool") or "llm",
        "rule_id": finding.get("rule_id", ""),
        "message_zh": finding.get("message_zh"),
        "owasp_id": finding.get("owasp_id", ""),
        "vuln_subtype": finding.get("vuln_subtype", ""),
    }


def filter_new_llm_findings(new_items: list[dict], existing) -> tuple[list[dict], int]:
    """Drop items that duplicate findings already stored for this scan (by overlap)."""
    pool = [finding_to_dedupe_ref(item) for item in existing]
    accepted: list[dict] = []
    skipped = 0
    for item in new_items:
        ref = finding_to_dedupe_ref(item)
        if any(_findings_duplicate(ref, prior) for prior in pool):
            skipped += 1
            continue
        accepted.append(item)
        pool.append(ref)
    if skipped:
        logger.info("LLM audit skipped %s duplicate findings vs existing scan data", skipped)
    return accepted, skipped


def llm_items_to_findings(
    raw_findings: list,
    root_path: Path,
    default_category: FindingCategory,
    *,
    rule_prefix: str = "llm",
    lock_category: bool = False,
) -> list[dict]:
    """Convert LLM JSON items to normalized finding dicts."""
    results: list[dict] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        category = _category_from_str(item.get("category", ""), default_category)
        if lock_category:
            if default_category == FindingCategory.BUSINESS_LOGIC:
                category = FindingCategory.BUSINESS_LOGIC
            elif default_category == FindingCategory.AUTHORIZATION:
                category = FindingCategory.AUTHORIZATION
        severity = _severity_from_str(item.get("severity", "MEDIUM"))
        confidence = _safe_confidence(item.get("confidence", 0.7))
        title = item.get("title") or item.get("message") or "潜在安全问题"
        description = item.get("description") or title
        attack = item.get("attack_scenario", "")
        recommendation = item.get("recommendation", "")
        # 形态专属视角（MQ / 定时任务 / RPC / SDK / CLI）的 schema 用 entry_surface，
        # 因为它本来就没有 HTTP 路径可写；这里落到同一个存储字段，下游无需改动。
        entry_surface = item.get("entry_surface") or ""
        api_endpoint = item.get("api_endpoint") or entry_surface
        endpoint_code_ref = item.get("endpoint_code_ref") or item.get("entry_code_ref") or ""
        data_source = item.get("data_source", "")
        data_flow = item.get("data_flow", "")
        trigger_point = item.get("trigger_point", "")
        prop_source = item.get("source") or data_source
        prop_sink = item.get("sink") or trigger_point or api_endpoint
        prop_guard = item.get("missing_guard") or item.get("guard") or item.get("constraint_missing") or ""
        prop_impact = item.get("impact") or item.get("risk_impact") or description
        risk_tags = infer_risk_tags(item, category)
        risk_label = " / ".join(RISK_TAG_LABELS.get(tag, tag) for tag in risk_tags)
        surface_label = "入口面" if entry_surface and not item.get("api_endpoint") else "接口"
        reason_parts = [description]
        if api_endpoint:
            reason_parts.append(f"{surface_label}: {api_endpoint}")
        if endpoint_code_ref:
            reason_parts.append(f"接口入口: {endpoint_code_ref}")
        if data_source:
            reason_parts.append(f"来源: {data_source}")
        if data_flow:
            reason_parts.append(f"链路: {data_flow}")
        if trigger_point:
            reason_parts.append(f"触发: {trigger_point}")
        if attack:
            reason_parts.append(f"攻击场景: {attack}")
        if recommendation:
            reason_parts.append(f"修复建议: {recommendation}")
        if prop_source:
            reason_parts.append(f"source: {prop_source}")
        if prop_sink:
            reason_parts.append(f"sink: {prop_sink}")
        if prop_guard:
            reason_parts.append(f"missing_guard: {prop_guard}")
        if prop_impact:
            reason_parts.append(f"impact: {prop_impact}")
        if risk_label:
            reason_parts.append(f"风险标签: {risk_label}")

        if is_non_vuln_confirmation_text(
            title,
            description,
            attack,
            recommendation,
            item.get("verdict"),
            item.get("summary"),
        ):
            logger.info("Skip non-vuln confirmation finding from LLM: %s", title)
            continue

        rel_file = item.get("file", "")
        abs_path = str(root_path / rel_file) if rel_file else ""
        if rel_file and not Path(abs_path).is_file():
            matches = list(root_path.rglob(Path(rel_file).name))
            if matches:
                abs_path = str(matches[0])

        meta = {
            "attack_scenario": attack,
            "recommendation": recommendation,
            "description": description,
            "api_endpoint": api_endpoint,
            "endpoint_code_ref": endpoint_code_ref,
            "data_source": data_source,
            "data_flow": data_flow,
            "trigger_point": trigger_point,
            "source": prop_source,
            "sink": prop_sink,
            "missing_guard": prop_guard,
            "impact": prop_impact,
            "risk_tags": risk_tags,
            "risk_label": risk_label,
        }
        if rule_prefix == "endpoint":
            meta["audit_mode"] = "endpoint_driven"

        results.append({
            "category": category,
            "rule_id": f"{rule_prefix}.{category.value}.{title[:60]}",
            "severity": severity,
            "message": title,
            "file_path": to_repo_relative_path(abs_path or rel_file or "", root_path) or rel_file,
            "line_start": int(item.get("line_start") or 0),
            "line_end": int(item.get("line_end") or item.get("line_start") or 0),
            "code_snippet": item.get("evidence") or item.get("code_snippet"),
            "tool": "llm",
            "ai_verdict": AiVerdict.REAL_VULN if confidence >= 0.6 else AiVerdict.UNCERTAIN,
            "ai_reason": "\n".join(reason_parts),
            "ai_confidence": confidence,
            "metadata_json": json.dumps(meta, ensure_ascii=False),
        })
    return results


async def _audit_batch(
    system_prompt: str,
    files_payload: list[dict],
    default_category: FindingCategory,
    audit_label: str,
    root_path: Path,
    *,
    lock_category: bool = True,
    rule_prefix: str = "llm",
) -> list[dict]:
    user_content = json.dumps(files_payload, ensure_ascii=False, indent=2)
    text = await chat_completion(
        [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"请审计以下 {len(files_payload)} 个源文件的{audit_label}风险：\n\n{user_content}",
            },
        ],
        task="deep",
        temperature=0.15,
        max_tokens=settings.llm_audit_max_tokens,
        timeout=effective_llm_timeout(3, task="deep"),
    )
    raw_findings = _parse_llm_json(text)
    return llm_items_to_findings(
        raw_findings,
        root_path,
        default_category,
        rule_prefix=rule_prefix,
        lock_category=lock_category,
    )


async def _detect_project_archetypes(root_path: Path) -> list[ArchetypeHit]:
    """识别项目形态，供「降级采样加权」与「形态专属审计」共用。

    `controller_count` 传真实端点数而不是 0：此时我们还不知道端点审计会不会成功，
    传 0 会强行否定 HTTP 形态。端点发现本身失败时退化为纯正则判断（传 None）。
    `discover_controller_units` 有 90s 缓存，端点审计随后会复用同一份结果。
    """
    controller_count: int | None = None
    try:
        from app.services.endpoint_discovery_service import discover_controller_units

        units = await asyncio.to_thread(discover_controller_units, root_path)
        controller_count = len(units)
    except Exception as exc:  # 端点发现失败不该拖垮形态识别
        logger.warning("端点发现失败，形态识别退化为纯正则判断: %s", exc)
    return detect_archetypes(root_path, controller_count=controller_count)


async def run_llm_code_audit(
    root_path: Path,
    categories: list[FindingCategory] | None = None,
    progress_callback=None,
    *,
    scan_id: int | None = None,
) -> list[dict]:
    """Run LLM deep audit — endpoint-driven (primary) + archetype lens (supplementary)."""
    if not is_llm_configured():
        return []

    # 复测可能复用同一个工作目录，形态识别的 TTL 缓存必须作废
    clear_archetype_cache()

    from app.services.llm_endpoint_audit_service import NoHttpEndpointsDetected, run_endpoint_driven_audit
    from app.services.llm_audit_journal import log_llm_audit_journal
    from app.services.llm_provider import format_llm_exception

    all_findings: list[dict] = []
    batch_errors: list[str] = []

    # 先认清项目形态：它同时决定「降级时怎么挑文件」和「要不要补一轮形态专属审计」
    archetypes = await _detect_project_archetypes(root_path)

    try:
        endpoint_items = await run_endpoint_driven_audit(
            root_path,
            categories,
            scan_id=scan_id,
            progress_callback=progress_callback,
        )
        all_findings.extend(endpoint_items)
    except NoHttpEndpointsDetected as exc:
        logger.info("Endpoint-driven LLM audit found no HTTP routes, falling back to file sampling: %s", exc)
        # 没有 HTTP 端点 ≠ 没有风险面：形态识别已经算好，据此给候选文件加权，
        # 否则采样出来的是一堆 tests/test_auth.py。
        if scan_id:
            await log_llm_audit_journal(
                scan_id,
                "fallback",
                {
                    "title": "自动切换文件采样审计",
                    "detail": (
                        "端点审计未识别到 HTTP 路由，已自动切换到文件采样审计继续补盲。"
                        f"项目形态：{format_summary(archetypes)}"
                    ),
                    "archetypes": summarize_archetypes(archetypes),
                },
                level="warning",
            )
        sample_items = await run_llm_file_sampling_audit(
            root_path, categories, progress_callback, archetypes=archetypes
        )
        all_findings.extend(sample_items)
        if scan_id:
            await log_llm_audit_journal(
                scan_id,
                "fallback_complete",
                {
                    "title": "文件采样审计完成",
                    "detail": f"自动降级文件采样审计已完成，产出 {len(sample_items)} 条候选发现。",
                },
            )
    except LlmAuditCancelled:
        raise
    except Exception as exc:
        logger.exception("Endpoint-driven LLM audit failed: %s", exc)
        batch_errors.append(f"端点驱动审计: {format_llm_exception(exc)}")

    # 【形态专属补充审计】端点审计是从 Controller 出发的：MQ 消费逻辑、定时任务、
    # RPC 服务端实现这些入口面根本不在 Controller 的调用链上，不补这一轮就永远审不到。
    # 只在识别到对应形态时才跑，最多多花 2 次 LLM 调用（16 个文件 / 8 个一批）。
    lens_types_found = lens_types(archetypes)
    if lens_types_found:
        lens_label = "、".join(ARCHETYPE_LABELS.get(t, t) for t in lens_types_found)
        if scan_id:
            await log_llm_audit_journal(
                scan_id,
                "archetype_lens_start",
                {
                    "title": "形态专属视角审计",
                    "detail": (
                        f"识别到 {lens_label}，将从入口面（topic / 任务名 / RPC 服务 / "
                        "公开 API / 子命令）补充审计，覆盖 HTTP 端点照不到的代码。"
                    ),
                    "archetypes": summarize_archetypes(archetypes),
                },
            )
        try:
            lens_items = await run_archetype_lens_audit(root_path, archetypes, progress_callback)
            all_findings.extend(lens_items)
            if scan_id:
                await log_llm_audit_journal(
                    scan_id,
                    "archetype_lens_complete",
                    {
                        "title": "形态专属视角审计完成",
                        "detail": f"{lens_label}视角补充审计完成，产出 {len(lens_items)} 条候选发现。",
                    },
                )
        except LlmAuditCancelled:
            raise
        except Exception as exc:
            logger.exception("Archetype lens audit failed: %s", exc)
            batch_errors.append(f"形态视角审计: {format_llm_exception(exc)}")

    if batch_errors and not all_findings:
        hint = ""
        joined = "；".join(batch_errors)
        if "Free plans can only use Auto" in joined or "Named models unavailable" in joined:
            hint = "（提示：请将深度审计模型改为 auto 或升级订阅）"
        if "timeout" in joined.lower() or "Timeout" in joined:
            hint = (hint or "") + "（提示：可在设置中增大 LLM 超时，或降低端点/Controller 上限）"
        raise RuntimeError(f"LLM 深度审计调用失败: {joined}{hint}")

    if batch_errors:
        logger.warning("LLM endpoint audit completed with errors: %s", batch_errors)

    return normalize_and_dedupe_llm_findings(all_findings)


async def run_llm_file_sampling_audit(
    root_path: Path,
    categories: list[FindingCategory] | None = None,
    progress_callback=None,
    *,
    archetypes: list[ArchetypeHit] | None = None,
) -> list[dict]:
    """Legacy file-sampling LLM audit (optional fallback)."""
    if not is_llm_configured():
        return []

    if categories is None:
        categories = [FindingCategory.BUSINESS_LOGIC, FindingCategory.AUTHORIZATION]

    if archetypes is None:
        archetypes = detect_archetypes(root_path)
    files = collect_audit_files(root_path, archetypes=archetypes)
    if not files:
        logger.warning("No source files found for LLM audit in %s", root_path)
        return []
    logger.info(
        "文件采样审计选中 %s 个文件（项目形态：%s）",
        len(files),
        format_summary(archetypes) if archetypes else "未识别",
    )

    files_payload = [_read_file_chunk(f, root_path) for f in files]
    all_findings: list[dict] = []
    batch_errors: list[str] = []

    batch_size = 8
    for i in range(0, len(files_payload), batch_size):
        batch = files_payload[i : i + batch_size]
        if progress_callback:
            try:
                batch_files = [b.get("file", "") for b in batch]
                await progress_callback(i // batch_size + 1, (len(files_payload) + batch_size - 1) // batch_size, batch_files)
            except Exception:
                pass

        if FindingCategory.BUSINESS_LOGIC in categories:
            try:
                biz = await _audit_batch(
                    BUSINESS_LOGIC_PROMPT, batch,
                    FindingCategory.BUSINESS_LOGIC, "业务逻辑", root_path,
                )
                all_findings.extend(biz)
            except Exception as exc:
                logger.exception("Business logic audit failed: %s", exc)
                batch_errors.append(f"业务逻辑审计: {exc}")

        if FindingCategory.AUTHORIZATION in categories:
            try:
                authz = await _audit_batch(
                    AUTHORIZATION_PROMPT, batch,
                    FindingCategory.AUTHORIZATION, "越权/访问控制", root_path,
                )
                all_findings.extend(authz)
            except Exception as exc:
                logger.exception("Authorization audit failed: %s", exc)
                batch_errors.append(f"越权审计: {exc}")

    if batch_errors and not all_findings:
        raise RuntimeError(f"LLM 文件抽检审计失败: {'；'.join(batch_errors)}")

    return normalize_and_dedupe_llm_findings(all_findings)


# 形态视角是**补充**审计，预算刻意压小：最多 16 个文件 / 2 批 → 最多多花 2 次 LLM 调用
LENS_MAX_FILES = 16
LENS_BATCH_SIZE = 8


async def run_archetype_lens_audit(
    root_path: Path,
    archetypes: list[ArchetypeHit],
    progress_callback=None,
    *,
    max_files: int | None = None,
) -> list[dict]:
    """按项目形态从**入口面**出发做补充审计。

    与 `run_llm_file_sampling_audit` 的分工：
    - 文件采样：按业务域关键词挑文件，用通用视角（业务逻辑 + 越权）
    - 形态视角：按 topic / 任务名 / RPC 服务 / 公开 API / 子命令定位代码，
      用该形态专属的风险清单审计，入口面字段是 `entry_surface` 而不是 HTTP 路径

    典型场景：一个既有 Controller 又有 RabbitMQ 消费者的服务 —— 端点驱动审计从
    Controller 出发，消费逻辑不在 Controller 的调用链上，只有这里才会被审到。
    """
    if not is_llm_configured():
        return []

    types = lens_types(archetypes)
    if not types:
        return []

    files = collect_lens_files(root_path, types, max_files=max_files or LENS_MAX_FILES)
    label = "、".join(ARCHETYPE_LABELS.get(t, t) for t in types)
    if not files:
        logger.info("形态视角未定位到入口面文件：形态=%s", types)
        return []

    prompt = build_lens_prompt(types)
    files_payload = [_read_file_chunk(f, root_path) for f in files]
    all_findings: list[dict] = []
    batch_errors: list[str] = []
    total_batches = (len(files_payload) + LENS_BATCH_SIZE - 1) // LENS_BATCH_SIZE

    for i in range(0, len(files_payload), LENS_BATCH_SIZE):
        batch = files_payload[i : i + LENS_BATCH_SIZE]
        if progress_callback:
            try:
                batch_files = [b.get("file", "") for b in batch]
                await progress_callback(i // LENS_BATCH_SIZE + 1, total_batches, batch_files)
            except Exception:
                pass

        try:
            items = await _audit_batch(
                prompt,
                batch,
                # 形态视角要能同时报业务逻辑与越权，所以不能锁死分类
                FindingCategory.BUSINESS_LOGIC,
                label,
                root_path,
                lock_category=False,
                rule_prefix="archetype",
            )
            all_findings.extend(items)
        except Exception as exc:
            logger.exception("Archetype lens audit failed: %s", exc)
            batch_errors.append(f"{label}: {exc}")

    if batch_errors and not all_findings:
        raise RuntimeError(f"形态视角审计失败: {'；'.join(batch_errors)}")

    return normalize_and_dedupe_llm_findings(all_findings)


LLM_REVIEW_PROMPT = """你是一名资深应用安全专家，负责对「LLM 深度审计」产出的业务逻辑/越权类发现进行**独立复审**（第二意见）。

深度审计可能过度报警。请结合代码片段与上下文，审慎判断每条发现是否成立：
- REAL_VULN：有明确攻击路径或设计缺陷，应修复
- FALSE_POSITIVE：误判、已有防护、不可利用或证据不足
- UNCERTAIN：需更多业务上下文或人工验证

输出严格 JSON 数组，每项格式：
{
  "finding_id": <number>,
  "verdict": "real_vuln" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reason": "中文复审结论，120字以内，说明判定依据",
  "missing_guard": "若 real_vuln，写缺失的关键约束（如资源归属校验/allowlist/频控）；否则可空",
  "blocked_by": "若 false_positive，写阻断点（哪条校验/鉴权/白名单导致不可利用）；否则可空",
  "evidence_ref": "优先写 相对路径:行号 或 方法名",
  "risk_tags": ["可选：1-2个标签，如 prompt_injection/ssrf/authz/idor/rate_limit"]
}
要求：
- verdict=real_vuln：必须填写 missing_guard，blocked_by 置空
- verdict=false_positive：必须填写 blocked_by，missing_guard 置空
- verdict=uncertain：至少说明缺少哪类上下文才能定性
只输出 JSON，不要其他文字。"""


def parse_finding_metadata(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def is_llm_pending_review(finding) -> bool:
    """True when an LLM finding has not yet received AI re-review."""
    return not parse_finding_metadata(finding.metadata_json).get("ai_re_reviewed")


def apply_llm_review_results(findings_db, results: list[dict]) -> int:
    """Apply AI re-review verdicts; preserve initial discovery notes in metadata."""
    by_id = normalize_fp_results(results)
    updated = 0
    for f in findings_db:
        r = by_id.get(f.id)
        if not r:
            continue
        meta = parse_finding_metadata(f.metadata_json)
        if f.ai_reason and not meta.get("discovery_reason"):
            meta["discovery_reason"] = f.ai_reason
        if f.ai_verdict and not meta.get("discovery_verdict"):
            meta["discovery_verdict"] = (
                f.ai_verdict.value if hasattr(f.ai_verdict, "value") else str(f.ai_verdict)
            )
        if f.ai_confidence is not None and "discovery_confidence" not in meta:
            meta["discovery_confidence"] = f.ai_confidence

        f.ai_verdict = verdict_from_str(r.get("verdict", ""))
        f.ai_reason = r.get("reason") or f.ai_reason
        f.ai_confidence = r.get("confidence")
        missing_guard = str(r.get("missing_guard") or "").strip()
        blocked_by = str(r.get("blocked_by") or "").strip()
        evidence_ref = str(r.get("evidence_ref") or "").strip()
        if missing_guard:
            meta["review_missing_guard"] = missing_guard
        if blocked_by:
            meta["review_blocked_by"] = blocked_by
        if evidence_ref:
            meta["review_evidence_ref"] = evidence_ref
        review_tags = r.get("risk_tags")
        if isinstance(review_tags, list):
            normalized_tags = []
            for tag in review_tags:
                norm = _normalize_risk_tag(tag)
                if norm and norm not in normalized_tags:
                    normalized_tags.append(norm)
            if normalized_tags:
                merged = list(meta.get("risk_tags") or [])
                for tag in normalized_tags:
                    if tag not in merged:
                        merged.append(tag)
                meta["risk_tags"] = merged[:4]
                meta["risk_label"] = " / ".join(RISK_TAG_LABELS.get(tag, tag) for tag in meta["risk_tags"])
        meta["ai_re_reviewed"] = True
        f.metadata_json = json.dumps(meta, ensure_ascii=False)
        updated += 1
    return updated


def _source_context_for_review(project_path: Path, finding: dict) -> str:
    file_path = finding.get("file_path", "")
    line = int(finding.get("line_start") or 0)
    if not file_path:
        return ""
    try:
        ctx = read_file_with_context(
            project_path,
            file_path,
            line,
            int(finding.get("line_end") or line),
            context_lines=35,
        )
        return ctx.get("content", "")[:4000]
    except Exception:
        return (finding.get("code_snippet") or "")[:2000]


async def review_llm_findings(findings: list[dict], project_path: Path) -> list[dict]:
    """Second-opinion AI review for LLM deep-audit findings."""
    if not is_llm_configured():
        return [
            {
                "finding_id": f["id"],
                "verdict": AiVerdict.SKIPPED.value,
                "confidence": 0.0,
                "reason": llm_not_configured_message(),
            }
            for f in findings
        ]

    all_results: list[dict] = []
    batch_size = 8
    for i in range(0, len(findings), batch_size):
        batch = findings[i : i + batch_size]
        payload = []
        for f in batch:
            rel_path = f.get("file_path", "")
            try:
                rel_path = str(Path(rel_path).relative_to(project_path))
            except ValueError:
                pass
            payload.append(
                {
                    "finding_id": f["id"],
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "title": f.get("message"),
                    "initial_analysis": f.get("ai_reason"),
                    "initial_confidence": f.get("ai_confidence"),
                    "file": rel_path,
                    "line": f.get("line_start"),
                    "code_snippet": (f.get("code_snippet") or "")[:1500],
                    "source_context": _source_context_for_review(project_path, f),
                }
            )

        user_content = json.dumps(payload, ensure_ascii=False, indent=2)
        try:
            text = await chat_completion(
                [
                    {"role": "system", "content": LLM_REVIEW_PROMPT},
                    {
                        "role": "user",
                        "content": f"请复审以下 {len(payload)} 条 LLM 深度审计发现：\n\n{user_content}",
                    },
                ],
                task="deep",
                temperature=0.1,
                max_tokens=4096,
                timeout=effective_llm_timeout(2, task="deep"),
            )
            text = extract_json_from_llm_text(text)
            results = json.loads(text)
            if isinstance(results, dict):
                results = results.get("findings", [results])
            if isinstance(results, list):
                all_results.extend(results)
        except Exception as exc:
            logger.exception("LLM re-review batch failed")
            all_results.extend(
                {
                    "finding_id": f["id"],
                    "verdict": AiVerdict.UNCERTAIN.value,
                    "confidence": 0.0,
                    "reason": f"AI 复审失败: {exc}",
                }
                for f in batch
            )
    return all_results
