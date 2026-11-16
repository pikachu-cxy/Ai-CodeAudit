"""Minimal deterministic Planner for Deep Audit V1.

The Planner is a PURE data transformation. It receives a snapshot that the
scheduler has already assembled (project info, SAST results, extracted
endpoints, blackboard facts, user-selected scope). It never receives a project
path, never touches the filesystem, never spawns a shell and never performs an
HTTP request -- including LLM calls. That keeps planning reproducible and
testable, and makes "Planner has no code access" a structural guarantee rather
than a prompt instruction.

Supported focus areas (V1):
    authz            鉴权与水平越权
    injection        注入及危险数据流
    business_logic   业务逻辑风险
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.blackboard_service import compute_task_fingerprint
from app.services.deep_audit_guards import path_in_scope

FOCUS_KEYS = ("authz", "injection", "business_logic")
FOCUS_LABELS = {
    "authz": "鉴权与水平越权",
    "injection": "注入及危险数据流",
    "business_logic": "业务逻辑风险",
}

FOCUS_SPECS: dict[str, dict[str, Any]] = {
    "authz": {
        "sast_keywords": ("auth", "permission", "idor", "access", "越权", "鉴权", "csrf"),
        "endpoint_keywords": ("user", "account", "admin", "profile", "order", "password", "token", "role", "detail"),
        "search_queries": ("user_id", "current_user", "check_owner"),
        "checks": (
            "接口是否校验登录态与对象归属（owner / tenant / role）",
            "资源标识是否直接来自请求参数而未与当前用户比对",
            "从 Controller 追到 Service/DAO，确认校验没有被绕过",
        ),
    },
    "injection": {
        "sast_keywords": ("sql", "inject", "command", "taint", "sink", "xss", "rce", "注入"),
        "endpoint_keywords": ("search", "query", "filter", "export", "import", "upload", "exec", "run"),
        "search_queries": ("execute", "cursor.execute", "request.args"),
        "checks": (
            "外部输入是否进入 SQL/命令/模板等危险汇聚点",
            "是否使用参数化查询或白名单，而不是字符串拼接",
            "追踪跨文件调用链，确认污染数据在到达 sink 前没有被净化",
        ),
    },
    "business_logic": {
        "sast_keywords": ("amount", "price", "balance", "logic", "race", "业务", "金额"),
        "endpoint_keywords": ("pay", "order", "transfer", "refund", "withdraw", "coupon", "wallet", "recharge"),
        "search_queries": ("create_order", "amount", "balance"),
        "checks": (
            "金额/数量/积分是否由服务端重算而非信任客户端传值",
            "状态机与幂等性、并发扣减是否有约束",
            "关键业务分支是否缺少频控、冷却或二次校验",
        ),
    },
}


@dataclass(frozen=True)
class AuditScope:
    focus: tuple[str, ...] = FOCUS_KEYS
    path_prefixes: tuple[str, ...] = ()
    max_tasks: int = 6

    def normalised(self, hard_max: int) -> "AuditScope":
        focus: list[str] = []
        for key in self.focus:
            key = str(key or "").strip().lower()
            if key in FOCUS_KEYS and key not in focus:
                focus.append(key)
        if not focus:
            focus = list(FOCUS_KEYS)
        prefixes = tuple(
            str(p).strip().replace("\\", "/").lstrip("/")
            for p in self.path_prefixes if str(p).strip()
        )
        return AuditScope(tuple(focus), prefixes, max(1, min(int(self.max_tasks or 0) or hard_max, hard_max)))

    def to_dict(self) -> dict:
        return {
            "focus": list(self.focus),
            "path_prefixes": list(self.path_prefixes),
            "max_tasks": self.max_tasks,
            "labels": {key: FOCUS_LABELS[key] for key in self.focus},
        }


@dataclass
class PlannerInput:
    project_info: dict = field(default_factory=dict)
    sast_findings: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    existing_facts: list[dict] = field(default_factory=list)
    previous_task_fingerprints: set[str] = field(default_factory=set)
    scope: AuditScope = field(default_factory=AuditScope)
    revision: str = ""

    @property
    def fact_covered_targets(self) -> set[str]:
        out: set[str] = set()
        for fact in self.existing_facts:
            metadata = fact.get("metadata") or {}
            for key in ("target", "file"):
                value = metadata.get(key) or fact.get(key)
                if value:
                    out.add(str(value).strip().lower())
        return out


def _matches(text: str, keywords: tuple[str, ...]) -> bool:
    hay = str(text or "").lower()
    return any(word in hay for word in keywords)


def _targets_for_focus(data: PlannerInput, focus: str) -> list[tuple[str, int, str]]:
    """Return (target, priority, reason) triples, highest priority first."""
    spec = FOCUS_SPECS[focus]
    out: list[tuple[str, int, str]] = []
    seen: set[str] = set()

    def add(target: str, priority: int, reason: str) -> None:
        key = target.strip().lower()
        if not key or key in seen:
            return
        if not path_in_scope(target.split(":", 1)[0].replace("\\", "/"), data.scope.path_prefixes):
            return
        seen.add(key)
        out.append((target, priority, reason))

    for finding in data.sast_findings[:60]:
        rule = f"{finding.get('rule_id','')} {finding.get('message','')}"
        if not _matches(rule, spec["sast_keywords"]):
            continue
        path = str(finding.get("file_path") or "").strip()
        if not path:
            continue
        severity = str(finding.get("severity") or "").upper()
        boost = 3 if severity in ("CRITICAL", "HIGH") else 1
        add(path, 10 + boost, f"SAST 命中 {finding.get('tool','sast')}/{finding.get('rule_id','')}")

    for endpoint in data.endpoints[:80]:
        hay = f"{endpoint.get('path','')} {endpoint.get('handler','')} {endpoint.get('file','')}"
        if not _matches(hay, spec["endpoint_keywords"]):
            continue
        path = str(endpoint.get("file") or "").strip()
        route = str(endpoint.get("path") or endpoint.get("handler") or "").strip()
        target = f"{path}:{route}" if path and route else (path or route)
        sensitivity = int(endpoint.get("sensitivity") or 0)
        add(target, 5 + min(3, max(0, sensitivity)), f"敏感接口 {route}")

    for prefix in data.scope.path_prefixes:
        add(prefix, 2, "用户选定的审计范围")

    if not out:
        # No hints at all: still produce a meaningful, explicitly scoped task.
        add("<repository>", 1, "无 SAST/接口线索，按选定范围做通用检查")
    return out


def plan_tasks(data: PlannerInput, *, hard_max_tasks: int = 6) -> list[dict]:
    """Produce de-duplicated, explicitly-scoped AuditTask specs.

    Completed tasks are deduplicated by task type, target and source revision.
    """
    scope = data.scope.normalised(hard_max_tasks)
    data = PlannerInput(
        project_info=data.project_info,
        sast_findings=data.sast_findings,
        endpoints=data.endpoints,
        existing_facts=data.existing_facts,
        previous_task_fingerprints=data.previous_task_fingerprints,
        scope=scope,
        revision=data.revision,
    )
    covered = data.fact_covered_targets
    specs: list[dict] = []
    for focus in scope.focus:
        spec = FOCUS_SPECS[focus]
        for target, priority, reason in _targets_for_focus(data, focus):
            fp = compute_task_fingerprint(focus, target, data.revision, focus)
            already_done = fp in data.previous_task_fingerprints
            if target.split(":", 1)[0].lower() in covered:
                priority += 1
            goal = (
                f"【{FOCUS_LABELS[focus]}】目标：{target}\n"
                f"线索：{reason}；代码版本：{data.revision or 'content-digest'}\n"
                "检查清单：\n"
                + "\n".join(f"  {i}. {item}" for i, item in enumerate(spec["checks"], 1))
                + "\n必须使用只读工具取得真实代码证据后再提交候选结论；无证据只能提交假设。"
            )
            specs.append(
                {
                    "task_type": focus,
                    "goal": goal,
                    "priority": priority,
                    "fingerprint": fp,
                    "status": "skipped" if already_done else "pending",
                    "result_summary": "黑板已有该目标事实，跳过重复调查" if already_done else "",
                    "scope": {
                        "focus": focus,
                        "target": target,
                        "revision": data.revision,
                        "path_prefixes": list(scope.path_prefixes),
                        "search_queries": list(spec["search_queries"]),
                        "reason": reason,
                    },
                }
            )

    # De-duplicate by fingerprint, keep the highest priority, then cap.
    by_fp: dict[str, dict] = {}
    for item in specs:
        current = by_fp.get(item["fingerprint"])
        if current is None or item["priority"] > current["priority"]:
            by_fp[item["fingerprint"]] = item
    ordered = sorted(
        by_fp.values(),
        key=lambda item: (item["status"] == "skipped", -item["priority"],
                          scope.focus.index(item["task_type"]), item["scope"]["target"]),
    )
    primary = []
    for focus in scope.focus:
        first = next((item for item in ordered if item["task_type"] == focus), None)
        if first is not None:
            primary.append(first)
    chosen = (primary + [item for item in ordered if item not in primary])[:scope.max_tasks]
    return sorted(chosen, key=lambda item: (item["status"] == "skipped", -item["priority"]))
