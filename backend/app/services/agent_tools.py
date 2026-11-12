"""Agent tools for codebase exploration during chat."""

from __future__ import annotations

from collections.abc import Callable
import logging
import json
import time
from pathlib import Path

from app.config import settings
from app.services.llm_audit_runtime import check_llm_audit_cancel
from app.services.endpoint_discovery_service import (
    discover_controller_units,
    find_related_service_files,
    list_endpoints_summary,
)
from app.services.file_service import locate_text_in_project, resolve_project_file

logger = logging.getLogger(__name__)

TOOL_SPECS = """
可用工具（通过 JSON 调用，一次一个）：

1. list_endpoints — 列出项目 HTTP 接口
   arguments: { "filter": "可选关键词如 modifyPwd", "limit": 30 }

2. read_file — 读取项目内源码
   arguments: { "path": "相对路径", "start_line": 1, "end_line": 200 }

3. read_files_batch — 批量读取多个关键文件
   arguments: { "files": [{"path":"src/a.py","start_line":1,"end_line":120},{"path":"src/b.py","start_line":20,"end_line":180}], "per_file_char_limit": 4000 }

4. search_code — 在项目中搜索符号/字符串
   arguments: { "query": "resetAuthInfo", "file_hint": "可选文件", "limit": 15 }
   返回: hits，以及 related_batch_candidates / suggested_next_tool（便于下一步 read_files_batch）

5. list_controllers — 按 Controller/路由文件分组列出端点（含 Java/Python/Express/NestJS/Koa，敏感度排序）
   arguments: { "limit": 20 }

响应格式（二选一，只输出 JSON，不要 markdown）：
调用工具: {"action":"tool","tool":"read_file","arguments":{...}}
最终回答: {"action":"answer","content":"你的中文结论..."}
"""

AUDIT_RESPONSE_SPECS = """
端点审计专用响应（自主迭代，JSON，无 markdown）：

1. 继续调查 — 调用工具:
   {"action":"tool","tool":"read_file","arguments":{"path":"src/foo.py","start_line":1,"end_line":120}}

2. 提交阶段性发现（可多次，有证据再提交）:
   {"action":"findings","note":"已确认 Prompt 注入风险","findings":[{"category":"business_logic","severity":"HIGH","title":"用户输入直入 LLM messages","description":"...","file":"相对路径","line_start":42,"api_endpoint":"POST /chat"}]}

3. 完成审计（**由你判断调查已充分时**主动结束，不必耗满上限）:
   {"action":"finish","audit_summary":"调查结论与范围说明","findings":[...]}

4. 更新/深化业务理解（调查过程中可再次输出）:
   {"action":"understand","app_summary":"...","business_domains":[...],"critical_flows":[...],"investigation_priorities":[...]}

5. 提交高风险候选（证据还差一步，不入库为漏洞）:
   {"action":"candidates","note":"发现 2 个高风险候选","candidates":[{"title":"积分充值价格可能信任客户端金额","hypothesis":"服务端未重算价格","evidence":["PaymentController.createOrder","body.amount"],"next_checks":["search_code: amount","read_file: payment service"]}]}

findings 字段说明：
- category: business_logic（含 AI/LLM 应用风险）或 authorization（越权/鉴权）
- 必须包含 file、line_start、title、description；有 HTTP 入口时填 api_endpoint
"""


def audit_tool_specs() -> str:
    return TOOL_SPECS + "\n" + AUDIT_RESPONSE_SPECS


def _search_related_batch_candidates(
    project_path: Path,
    hits: list[dict],
    limit: int = 5,
    cancel_check: Callable[[], None] | None = None,
) -> list[dict]:
    root = project_path.resolve()
    candidates: list[dict] = []
    seen: set[str] = set()

    def add(path: Path, reason: str) -> None:
        try:
            rel = str(path.resolve().relative_to(root))
        except Exception:
            return
        if rel in seen:
            return
        seen.add(rel)
        candidates.append(
            {
                "path": rel,
                "start_line": 1,
                "end_line": 240,
                "reason": reason,
            }
        )

    for hit in hits[:6]:
        raw_path = str(hit.get("file_path") or "").strip()
        if not raw_path:
            continue
        try:
            resolved = resolve_project_file(root, raw_path)
        except (FileNotFoundError, ValueError):
            continue
        add(resolved, "search_hit")

        name = resolved.name.lower()
        parent_blob = " ".join(part.lower() for part in resolved.parts)
        if "controller" in name or "controller" in parent_blob:
            for svc in find_related_service_files(root, resolved, max_files=3, cancel_check=cancel_check):
                add(svc, "related_service")

        if len(candidates) >= limit:
            break

    return candidates[:limit]


def execute_agent_tool(
    project_path: Path,
    tool: str,
    arguments: dict | None,
    *,
    scan_id: int | None = None,
) -> str:
    """Run a tool and return JSON string result."""
    args = arguments or {}
    root = project_path.resolve()
    started = time.perf_counter()
    ok = False
    out: str | None = None
    cancel_check = (lambda: check_llm_audit_cancel(scan_id)) if scan_id is not None else None

    def _arg_preview() -> dict:
        preview: dict = {}
        for k, v in args.items():
            ks = str(k)
            if ks in {"query", "file_hint", "path"}:
                preview[ks] = (str(v)[:120] + "...") if v else ""
            elif ks in {"limit", "start_line", "end_line", "max_files", "max_related_files"}:
                try:
                    preview[ks] = int(v)
                except Exception:
                    preview[ks] = v
            elif ks == "files" and isinstance(v, list):
                preview[ks] = f"{len(v)} items"
            else:
                preview[ks] = v if isinstance(v, (str, int, float, bool)) else type(v).__name__
        return preview

    tool_preview = str(tool or "").strip() or "unknown"

    try:
        if tool == "list_endpoints":
            rows = list_endpoints_summary(
                root,
                filter_text=str(args.get("filter") or ""),
                limit=int(args.get("limit") or 40),
                cancel_check=cancel_check,
            )
            out = json.dumps({"ok": True, "count": len(rows), "endpoints": rows}, ensure_ascii=False)
            ok = True
            return out

        if tool == "list_controllers":
            limit = int(args.get("limit") or 20)
            units = discover_controller_units(root, cancel_check=cancel_check)[:limit]
            payload = [
                {
                    "file": u.file,
                    "class": u.class_name,
                    "base_path": u.base_path,
                    "sensitivity": u.sensitivity,
                    "endpoint_count": len(u.endpoints),
                    "handlers": [e.handler for e in u.endpoints[:12]],
                }
                for u in units
            ]
            out = json.dumps({"ok": True, "controllers": payload}, ensure_ascii=False)
            ok = True
            return out

        if tool == "read_file":
            rel = str(args.get("path") or "").strip()
            if not rel:
                out = json.dumps({"ok": False, "error": "缺少 path"}, ensure_ascii=False)
                return out
            resolved = resolve_project_file(root, rel)
            text = resolved.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            total = len(lines)
            start = max(1, int(args.get("start_line") or 1))
            end = min(total, int(args.get("end_line") or min(total, start + 180)))
            chunk = "\n".join(f"{i:4d}| {lines[i-1]}" for i in range(start, end + 1))
            max_chars = settings.llm_audit_file_max_chars
            if len(chunk) > max_chars:
                chunk = chunk[:max_chars] + "\n... [truncated]"
            out = json.dumps(
                {
                    "ok": True,
                    "path": str(resolved.relative_to(root)),
                    "start_line": start,
                    "end_line": end,
                    "total_lines": total,
                    "content": chunk,
                },
                ensure_ascii=False,
            )
            ok = True
            return out

        if tool == "read_files_batch":
            files = args.get("files")
            if not isinstance(files, list) or not files:
                out = json.dumps({"ok": False, "error": "缺少 files"}, ensure_ascii=False)
                return out
            per_file_limit = max(1000, min(int(args.get("per_file_char_limit") or 4000), 12000))
            payload = []
            for item in files[:8]:
                if not isinstance(item, dict):
                    continue
                rel = str(item.get("path") or "").strip()
                if not rel:
                    continue
                resolved = resolve_project_file(root, rel)
                text = resolved.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()
                total = len(lines)
                start = max(1, int(item.get("start_line") or 1))
                end = min(total, int(item.get("end_line") or min(total, start + 180)))
                chunk = "\n".join(f"{i:4d}| {lines[i-1]}" for i in range(start, end + 1))
                if len(chunk) > per_file_limit:
                    chunk = chunk[:per_file_limit] + "\n... [truncated]"
                payload.append(
                    {
                        "path": str(resolved.relative_to(root)),
                        "start_line": start,
                        "end_line": end,
                        "total_lines": total,
                        "content": chunk,
                    }
                )
            out = json.dumps({"ok": True, "count": len(payload), "files": payload}, ensure_ascii=False)
            ok = True
            return out

        if tool == "search_code":
            query = str(args.get("query") or "").strip()
            if not query:
                out = json.dumps({"ok": False, "error": "缺少 query"}, ensure_ascii=False)
                return out
            raw_file_hint = str(args.get("file_hint") or "") or None
            file_hint = raw_file_hint if raw_file_hint and raw_file_hint.strip() else None

            # Cap all searches on large repos. Broad hints (".java", "agent") used to
            # scan for 5+ minutes and peg CPU until the API stopped responding.
            max_scan_seconds = 8.0
            max_files_scanned = 1600
            max_file_bytes = 2 * 1024 * 1024  # 2MB
            if file_hint:
                hint = file_hint.strip().lower()
                looks_like_path = ("/" in hint) or ("\\" in hint) or ("." in hint and not hint.startswith("."))
                # Extension-only / short keyword hints are effectively full-repo scans.
                if hint in {".java", ".py", ".js", ".ts", ".tsx", ".kt", ".go", "java", "py"} or (
                    not looks_like_path and len(hint) <= 8
                ):
                    max_scan_seconds = 6.0
                    max_files_scanned = 1200
                else:
                    max_scan_seconds = 12.0
                    max_files_scanned = 2500

            hits = locate_text_in_project(
                root,
                query,
                file_hint=file_hint,
                limit=int(args.get("limit") or 15),
                max_scan_seconds=max_scan_seconds,
                max_files_scanned=max_files_scanned,
                cancel_check=cancel_check,
                max_file_bytes=max_file_bytes,
            )
            related_batch_candidates = _search_related_batch_candidates(root, hits, cancel_check=cancel_check)
            out = json.dumps(
                {
                    "ok": True,
                    "query": query,
                    "hits": hits,
                    "related_batch_candidates": related_batch_candidates,
                    "suggested_next_tool": (
                        {
                            "tool": "read_files_batch",
                            "arguments": {
                                "files": [
                                    {
                                        "path": item["path"],
                                        "start_line": item["start_line"],
                                        "end_line": item["end_line"],
                                    }
                                    for item in related_batch_candidates
                                ],
                                "per_file_char_limit": 5000,
                            },
                        }
                        if related_batch_candidates
                        else None
                    ),
                },
                ensure_ascii=False,
            )
            ok = True
            return out

        out = json.dumps({"ok": False, "error": f"未知工具: {tool}"}, ensure_ascii=False)
        return out
    except FileNotFoundError as exc:
        out = json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
        return out
    except ValueError as exc:
        out = json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
        return out
    except Exception as exc:
        out = json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False)
        return out
    finally:
        duration_ms = int((time.perf_counter() - started) * 1000)
        # 日志量控制：只对慢调用或失败调用报 info/warn
        if duration_ms >= 3000 or not ok:
            try:
                logger.warning(
                    "agent_tool duration=%dms ok=%s tool=%s args=%s",
                    duration_ms,
                    ok,
                    tool_preview,
                    _arg_preview(),
                )
            except Exception:
                pass


def parse_agent_response(text: str) -> dict | None:
    """Parse LLM tool/answer JSON from response text."""
    from app.services.llm_provider import extract_json_from_llm_text

    raw = extract_json_from_llm_text(text)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    action = str(data.get("action") or "").lower()
    if action == "answer":
        return {"action": "answer", "content": str(data.get("content") or "")}
    if action == "findings":
        findings = data.get("findings")
        return {
            "action": "findings",
            "findings": findings if isinstance(findings, list) else [],
            "note": str(data.get("note") or data.get("audit_summary") or ""),
        }
    if action == "finish":
        findings = data.get("findings")
        return {
            "action": "finish",
            "audit_summary": str(data.get("audit_summary") or data.get("summary") or ""),
            "findings": findings if isinstance(findings, list) else [],
        }
    if action == "understand":
        return {
            "action": "understand",
            "app_summary": str(data.get("app_summary") or data.get("summary") or ""),
            "business_domains": data.get("business_domains") if isinstance(data.get("business_domains"), list) else [],
            "user_roles": data.get("user_roles") if isinstance(data.get("user_roles"), list) else [],
            "critical_flows": data.get("critical_flows") if isinstance(data.get("critical_flows"), list) else [],
            "investigation_priorities": (
                data.get("investigation_priorities")
                if isinstance(data.get("investigation_priorities"), list)
                else data.get("priorities")
                if isinstance(data.get("priorities"), list)
                else []
            ),
            "trust_boundaries": data.get("trust_boundaries") if isinstance(data.get("trust_boundaries"), list) else [],
        }
    if action == "candidates":
        candidates = data.get("candidates")
        return {
            "action": "candidates",
            "note": str(data.get("note") or data.get("audit_summary") or ""),
            "candidates": candidates if isinstance(candidates, list) else [],
        }
    if action == "tool":
        return {
            "action": "tool",
            "tool": str(data.get("tool") or ""),
            "arguments": data.get("arguments") if isinstance(data.get("arguments"), dict) else {},
        }
    if action == "flow_verdict":
        return data
    return None
