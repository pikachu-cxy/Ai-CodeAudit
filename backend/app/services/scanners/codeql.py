import asyncio
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from app.config import settings
from app.services.scanners.base import BaseScanner, ScannerRunResult
from app.services.scanners.common import finding, parse_json_output, read_code_snippet, resolve_file_path

logger = logging.getLogger(__name__)


def _read_json_file(path: Path) -> dict | list:
    return parse_json_output(path.read_text(encoding="utf-8", errors="replace"), "codeql")


def _is_windows_path(text: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", text.strip()))


def _is_local_query_suite(text: str) -> bool:
    """True only for filesystem paths to .ql/.qls — not CodeQL pack refs.

    Pack examples (NOT local):
      codeql/java-queries
      codeql/java-queries:codeql-suites/java-security-and-quality.qls
    Local examples:
      /opt/queries/java.qls
      ./suites/security.qls
    """
    t = text.strip()
    if not t:
        return False
    # pack:subpath — colon after a pack name (not Windows drive letter)
    if ":" in t and not _is_windows_path(t):
        pack = t.split(":", 1)[0].strip()
        if "/" in pack and not pack.startswith(".") and not pack.startswith("/"):
            return False
    if t.endswith((".qls", ".ql")):
        return True
    try:
        return Path(t).is_file()
    except OSError:
        return False


def _normalize_query_candidates(raw: str) -> list[str]:
    text = (raw or "").strip()
    if not text:
        text = "codeql/java-queries"
    if _is_local_query_suite(text):
        path = Path(text)
        return [str(path.resolve())] if path.is_file() else [text]

    candidates: list[str] = [text]
    # pack:subpath form (not Windows drive letters like C:\...)
    if ":" in text and not _is_windows_path(text):
        pack = text.split(":", 1)[0].strip()
        if pack and pack not in candidates:
            candidates.append(pack)
    if "codeql/java-queries" not in candidates:
        candidates.append("codeql/java-queries")
    uniq: list[str] = []
    for c in candidates:
        if c and c not in uniq:
            uniq.append(c)
    return uniq


def _pack_from_candidate(candidate: str) -> str | None:
    text = candidate.strip()
    if not text or _is_windows_path(text):
        return None
    # Local filesystem suite/query path — not a pack
    if _is_local_query_suite(text):
        return None
    if ":" in text:
        text = text.split(":", 1)[0].strip()
    # ql pack refs are typically owner/name
    if "/" in text and not text.endswith(".qls") and not text.endswith(".ql"):
        return text
    return None


def _coerce_line(loc: dict | None) -> int:
    if not isinstance(loc, dict):
        return 0
    region = loc.get("region") if isinstance(loc.get("region"), dict) else {}
    try:
        return int(region.get("startLine") or region.get("line") or 0)
    except (TypeError, ValueError):
        return 0


def _coerce_end_line(loc: dict | None, start_line: int) -> int:
    if not isinstance(loc, dict):
        return start_line
    region = loc.get("region") if isinstance(loc.get("region"), dict) else {}
    try:
        return int(region.get("endLine") or start_line or 0)
    except (TypeError, ValueError):
        return start_line


def _artifact_uri(loc: dict | None) -> str:
    if not isinstance(loc, dict):
        return ""
    artifact = loc.get("artifactLocation") if isinstance(loc.get("artifactLocation"), dict) else {}
    return str(artifact.get("uri") or "")


def _message_text(node: dict | None) -> str:
    if not isinstance(node, dict):
        return ""
    msg = node.get("message")
    if isinstance(msg, dict):
        return str(msg.get("text") or msg.get("markdown") or "")
    return str(msg or "")


def _parse_security_severity(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _sarif_severity(result: dict, rule: dict) -> str:
    props = {}
    if isinstance(rule.get("properties"), dict):
        props.update(rule["properties"])
    if isinstance(result.get("properties"), dict):
        props.update(result["properties"])

    sec = _parse_security_severity(props.get("security-severity"))
    if sec is not None:
        if sec >= 9.0:
            return "CRITICAL"
        if sec >= 7.0:
            return "HIGH"
        if sec >= 4.0:
            return "MEDIUM"
        if sec > 0:
            return "LOW"

    level = str(
        result.get("level")
        or (rule.get("defaultConfiguration") or {}).get("level")
        or props.get("problem.severity")
        or "warning"
    ).upper()
    if level == "ERROR":
        return "HIGH"
    if level in ("WARNING", "WARN"):
        return "MEDIUM"
    if level in ("NOTE", "RECOMMENDATION"):
        return "LOW"
    return level


def _collect_tags(rule: dict, result: dict) -> list[str]:
    tags: list[str] = []
    for source in (rule.get("properties"), result.get("properties")):
        if not isinstance(source, dict):
            continue
        raw_tags = source.get("tags")
        if isinstance(raw_tags, list):
            tags.extend(str(tag) for tag in raw_tags if tag)
    return tags


def _extract_taxonomy(tags: list[str]) -> tuple[list[str], list[str]]:
    cwe: list[str] = []
    owasp: list[str] = []
    for tag in tags:
        low = tag.lower()
        if "cwe-" in low:
            idx = low.find("cwe-")
            cwe.append(tag[idx:].upper())
        if "owasp" in low:
            owasp.append(tag)
    return cwe, owasp


def _build_flow_compat(project_path: Path, result: dict) -> dict:
    code_flows = result.get("codeFlows")
    if not isinstance(code_flows, list) or not code_flows:
        return {}
    first_flow = code_flows[0] if isinstance(code_flows[0], dict) else {}
    thread_flows = first_flow.get("threadFlows")
    if not isinstance(thread_flows, list) or not thread_flows:
        return {}

    raw_thread_flows: list[dict] = []
    compat_trace: dict = {}
    summaries: list[str] = []

    for tf in thread_flows:
        if not isinstance(tf, dict):
            continue
        locations = tf.get("locations")
        if not isinstance(locations, list) or not locations:
            continue
        flow_steps: list[dict] = []
        compat_nodes: list[dict] = []
        for item in locations:
            if not isinstance(item, dict):
                continue
            location = item.get("location") if isinstance(item.get("location"), dict) else {}
            physical = location.get("physicalLocation") if isinstance(location.get("physicalLocation"), dict) else {}
            uri = _artifact_uri(physical)
            abs_path = resolve_file_path(project_path, uri) if uri else Path("")
            line = _coerce_line(physical)
            label = _message_text(location) or _message_text(item)
            step = {
                "file": str(abs_path) if uri else "",
                "line": line,
                "label": label[:200],
            }
            flow_steps.append(step)
            compat_nodes.append(
                {
                    "location": {
                        "path": str(abs_path) if uri else "",
                        "start": {"line": line},
                    },
                    "abstract_content": label[:200],
                }
            )
        if not flow_steps:
            continue
        raw_thread_flows.append({"locations": flow_steps})
        summaries.append(
            " → ".join(
                f"{Path(step['file']).name or '?'}:{step['line'] or '?'}"
                + (f" ({step['label'][:40]})" if step.get("label") else "")
                for step in flow_steps
            )
        )
        if not compat_trace and compat_nodes:
            compat_trace = {
                "taint_source": compat_nodes[0],
                "intermediate_vars": compat_nodes[1:-1],
                "taint_sink": compat_nodes[-1],
            }

    if not raw_thread_flows:
        return {}

    return {
        "codeql_thread_flows": raw_thread_flows,
        "dataflow_trace": compat_trace if compat_trace else None,
        "data_flow_chain": summaries[0] if summaries else "",
        "data_flow_summary": summaries[0] if summaries else "",
    }


def _lookup_rules(sarif: dict) -> dict[str, dict]:
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return {}
    mapping: dict[str, dict] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        rules = driver.get("rules")
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id") or "")
            if rule_id:
                mapping[rule_id] = rule
    return mapping


def _extract_build_failure_hint(stdout: str = "", stderr: str = "") -> str:
    """Pull a short, actionable Maven/Gradle reason from CodeQL create output."""
    text = f"{stderr or ''}\n{stdout or ''}"
    if not text.strip():
        return "构建命令退出码非 0（无详细输出）"

    patterns = (
        r"Non-resolvable parent POM[^\n]*",
        r"Could not find artifact [^\n]+",
        r"\[FATAL\][^\n]+",
        r"Could not resolve dependencies[^\n]*",
        r"Failed to execute goal [^\n]+",
        r"BUILD FAILURE",
        r"A fatal error occurred:[^\n]*",
    )
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            line = re.sub(r"\s+", " ", m.group(0)).strip()
            return line[:400]

    # Fallback: last ERROR line
    for line in reversed(text.splitlines()):
        s = line.strip()
        if s.upper().startswith("[ERROR]") or "error:" in s.lower():
            return re.sub(r"\s+", " ", s)[:400]
    return re.sub(r"\s+", " ", text.strip())[:300]


class CodeqlScanner(BaseScanner):
    id = "codeql"
    name = "CodeQL"
    description = "Java 专用语义级 SAST，支持更深的数据流与规则查询"
    category = "sast"
    install_hint = "安装 CodeQL CLI 并确保 `codeql` 在 PATH 中"
    supported_languages = ["java"]
    setup_hint = (
        "需本机安装 CodeQL CLI、JDK，以及可用于编译项目的 Maven/Gradle；"
        "autobuild/manual 失败时会自动降级为 none（无编译）模式。"
    )
    requires_build = True

    async def is_available(self) -> bool:
        return shutil.which("codeql") is not None

    async def availability_reason(self) -> str | None:
        if await self.is_available():
            return None
        return (
            "未检测到 codeql CLI。官方镜像默认不安装 CodeQL（CLI 约 400 MB，且仅用于 Java 深度分析）；"
            "需要时以 INSTALL_CODEQL=1 重新构建镜像，或自行安装 CodeQL CLI 并加入 PATH。"
        )

    async def timeout_seconds(self, project_path: Path) -> int:
        # Must cover DB create (+ optional none fallback) + pack download + analyze.
        create_budget = settings.codeql_db_timeout
        mode = (settings.codeql_build_mode or "autobuild").strip().lower()
        if mode != "none":
            create_budget *= 2
        return create_budget + settings.codeql_timeout + 300

    def _java_files(self, project_path: Path) -> list[Path]:
        skip = {
            "node_modules", ".git", "target", "build", "dist", "vendor",
            ".gradle", ".m2", "out", "bin", "obj", ".idea", ".vscode",
        }
        out: list[Path] = []
        stack = [project_path]
        while stack:
            current = stack.pop()
            try:
                for entry in current.iterdir():
                    try:
                        if entry.is_dir() and not entry.is_symlink():
                            if entry.name in skip:
                                continue
                            stack.append(entry)
                        elif entry.is_file() and entry.suffix.lower() == ".java":
                            out.append(entry)
                    except OSError:
                        continue
            except OSError:
                continue
        return out

    def _version(self) -> str | None:
        try:
            proc = subprocess.run(
                ["codeql", "version", "--format=json"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = parse_json_output(proc.stdout, self.id)
                if isinstance(data, dict):
                    return str(data.get("version") or data.get("codeqlVersion") or "").strip() or None
        except Exception:
            pass
        try:
            proc = subprocess.run(
                ["codeql", "version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            if proc.returncode == 0:
                return (proc.stdout or proc.stderr).strip().splitlines()[0][:120]
        except Exception:
            return None
        return None

    def _database_create_cmd(
        self,
        project_path: Path,
        db_dir: Path,
        *,
        build_mode: str,
        build_cmd: str = "",
    ) -> list[str]:
        cmd = [
            "codeql",
            "database",
            "create",
            str(db_dir),
            "--language=java",
            "--source-root",
            str(project_path),
            "--overwrite",
        ]
        mode = (build_mode or "autobuild").strip().lower()
        if mode == "manual":
            command = (build_cmd or "").strip()
            if command:
                cmd.extend(["--command", command])
            else:
                cmd.extend(["--build-mode", "autobuild"])
        elif mode == "none":
            cmd.extend(["--build-mode", "none"])
        else:
            cmd.extend(["--build-mode", "autobuild"])
        return cmd

    def _database_analyze_cmd(self, db_dir: Path, sarif_path: Path, query_suite: str) -> list[str]:
        return [
            "codeql",
            "database",
            "analyze",
            str(db_dir),
            query_suite,
            "--format=sarif-latest",
            "--output",
            str(sarif_path),
            "--threads=0",
            "--rerun",
        ]

    async def scan(self, project_path: Path) -> ScannerRunResult:
        java_files = await asyncio.to_thread(self._java_files, project_path)
        if not java_files:
            return ScannerRunResult(
                scanner_id=self.id,
                skipped=True,
                skip_reason="项目中无 Java 文件",
                detail={"supported_languages": self.supported_languages},
            )

        build_mode = (settings.codeql_build_mode or "autobuild").strip().lower()
        build_cmd = settings.codeql_java_build_command.strip()
        query_suite_raw = (settings.codeql_query_suite or "").strip()
        if _is_local_query_suite(query_suite_raw):
            qls_path = Path(query_suite_raw)
            if not qls_path.is_file():
                return ScannerRunResult(
                    scanner_id=self.id,
                    skipped=True,
                    skip_reason=f"CodeQL 查询套件文件不存在: {query_suite_raw}",
                    detail={"query_suite": query_suite_raw},
                )
        if build_mode == "manual" and not build_cmd:
            return ScannerRunResult(
                scanner_id=self.id,
                skipped=True,
                skip_reason="CodeQL manual 模式需要先配置 Java 构建命令",
                detail={
                    "build_mode": build_mode,
                    "query_suite": settings.codeql_query_suite,
                },
            )

        version = self._version()
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="codeql-scan-") as tmp:
            tmp_path = Path(tmp)
            db_dir = tmp_path / "db"
            sarif_path = tmp_path / "results.sarif"
            query_candidates = _normalize_query_candidates(settings.codeql_query_suite)
            requested_mode = build_mode if build_mode in ("autobuild", "manual", "none") else "autobuild"

            def _create_once(mode: str) -> subprocess.CompletedProcess:
                create_cmd = self._database_create_cmd(
                    project_path,
                    db_dir,
                    build_mode=mode,
                    build_cmd=build_cmd,
                )
                return subprocess.run(
                    create_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=settings.codeql_db_timeout,
                )

            def _run():
                create_meta: dict = {
                    "requested_mode": requested_mode,
                    "effective_mode": requested_mode,
                    "degraded": False,
                    "build_failure_hint": "",
                    "primary_create_ok": False,
                }
                create_proc: subprocess.CompletedProcess | None = None
                primary_timeout_msg = ""

                try:
                    create_proc = _create_once(requested_mode)
                except subprocess.TimeoutExpired as exc:
                    if requested_mode == "none":
                        raise
                    primary_timeout_msg = (
                        f"主构建建库超时（>{settings.codeql_db_timeout}s）: "
                        + " ".join(str(x) for x in (exc.cmd or []))[:300]
                    )
                    create_meta["build_failure_hint"] = primary_timeout_msg

                if create_proc is not None and create_proc.returncode == 0:
                    create_meta["primary_create_ok"] = True
                elif requested_mode != "none":
                    # Generic fallback: incomplete repos / missing parent POM / private deps.
                    hint = create_meta.get("build_failure_hint") or ""
                    if create_proc is not None:
                        hint = _extract_build_failure_hint(create_proc.stdout or "", create_proc.stderr or "")
                    create_meta["build_failure_hint"] = hint
                    create_meta["primary_stderr_tail"] = (
                        ((create_proc.stderr if create_proc else "") or "")[-1500:]
                        or primary_timeout_msg
                    )
                    logger.warning(
                        "CodeQL %s create failed (%s); falling back to build-mode=none",
                        requested_mode,
                        hint[:200],
                    )
                    try:
                        create_proc = _create_once("none")
                    except subprocess.TimeoutExpired:
                        # Re-raise so outer handler reports timeout for the fallback attempt.
                        raise
                    create_meta["effective_mode"] = "none"
                    create_meta["degraded"] = True
                    if create_proc.returncode != 0:
                        return ("create", create_proc, query_candidates[0], [], create_meta)
                else:
                    # requested_mode == none and create failed (non-timeout)
                    return ("create", create_proc, query_candidates[0], [], create_meta)

                assert create_proc is not None
                if create_proc.returncode != 0:
                    return ("create", create_proc, query_candidates[0], [], create_meta)

                last_proc = None
                attempts: list[dict] = []
                for query_suite in query_candidates:
                    pack = _pack_from_candidate(query_suite)
                    if pack:
                        download_proc = subprocess.run(
                            ["codeql", "pack", "download", pack],
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=min(settings.codeql_timeout, 180),
                        )
                        attempts.append(
                            {
                                "suite": query_suite,
                                "pack": pack,
                                "download_ok": download_proc.returncode == 0,
                                "download_stderr": (download_proc.stderr or "")[-400:],
                            }
                        )
                    analyze_cmd = self._database_analyze_cmd(db_dir, sarif_path, query_suite)
                    analyze_proc = subprocess.run(
                        analyze_cmd,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=settings.codeql_timeout,
                    )
                    attempts.append(
                        {
                            "suite": query_suite,
                            "analyze_ok": analyze_proc.returncode == 0,
                            "stderr_tail": (analyze_proc.stderr or "")[-400:],
                        }
                    )
                    if analyze_proc.returncode == 0:
                        return ("analyze", analyze_proc, query_suite, attempts, create_meta)
                    last_proc = analyze_proc
                    err_text = (analyze_proc.stderr or analyze_proc.stdout or "").lower()
                    # Retry next candidate only for missing query pack / suite resolution issues.
                    if "query pack" not in err_text and "cannot be found" not in err_text:
                        break
                return ("analyze", last_proc, query_candidates[0], attempts, create_meta)

            try:
                stage, proc, used_query_suite, attempts, create_meta = await asyncio.to_thread(_run)
            except subprocess.TimeoutExpired as exc:
                elapsed = round(time.monotonic() - started, 1)
                cmd_text = " ".join(str(x) for x in (exc.cmd or []))
                if "database create" in cmd_text or " create " in f" {cmd_text} ":
                    phase = "建库"
                    limit = settings.codeql_db_timeout
                elif "pack download" in cmd_text:
                    phase = "下载查询包"
                    limit = min(settings.codeql_timeout, 180)
                else:
                    phase = "分析"
                    limit = settings.codeql_timeout
                return ScannerRunResult(
                    scanner_id=self.id,
                    version=version,
                    detail={
                        "build_mode": requested_mode,
                        "query_suite": settings.codeql_query_suite,
                        "elapsed_seconds": elapsed,
                        "database_timeout": settings.codeql_db_timeout,
                        "analyze_timeout": settings.codeql_timeout,
                        "phase": phase,
                        "phase_timeout": limit,
                    },
                    error=(
                        f"CodeQL {phase}超时（已运行 {elapsed}s，该阶段上限 {limit}s）。"
                        f"可在设置中增大建库/分析超时，或改用较轻的 java-code-scanning.qls。"
                    ),
                )

            effective_mode = str(create_meta.get("effective_mode") or requested_mode)
            degraded = bool(create_meta.get("degraded"))
            build_hint = str(create_meta.get("build_failure_hint") or "")
            elapsed = round(time.monotonic() - started, 1)
            if not proc or proc.returncode != 0:
                hint = build_hint or _extract_build_failure_hint(
                    (proc.stdout if proc else "") or "",
                    (proc.stderr if proc else "") or "",
                )
                if stage == "create":
                    err_msg = f"CodeQL 建库失败: {hint}"
                    if degraded:
                        err_msg = f"CodeQL 建库失败（已尝试 none 降级仍失败）: {hint}"
                elif proc and "query pack" in (proc.stderr or proc.stdout or "").lower():
                    err_msg = (
                        "CodeQL analyze失败: 无法解析查询套件。"
                        "请在设置里将 Query Suite 改为 `codeql/java-queries`。"
                    )
                else:
                    err_msg = (
                        f"CodeQL {stage}失败: "
                        f"{((proc.stderr if proc else '') or (proc.stdout if proc else '') or 'unknown error')[:2000]}"
                    )
                return ScannerRunResult(
                    scanner_id=self.id,
                    version=version,
                    detail={
                        "phase": stage,
                        "build_mode": effective_mode,
                        "build_mode_requested": requested_mode,
                        "degraded": degraded,
                        "build_failure_hint": hint,
                        "query_suite": settings.codeql_query_suite,
                        "query_suite_used": used_query_suite,
                        "query_candidates": query_candidates,
                        "query_attempts": attempts,
                        "elapsed_seconds": elapsed,
                        "stdout_tail": ((proc.stdout if proc else "") or "")[-2000:],
                        "stderr_tail": ((proc.stderr if proc else "") or "")[-2000:],
                    },
                    error=err_msg,
                )

            if not sarif_path.is_file():
                return ScannerRunResult(
                    scanner_id=self.id,
                    version=version,
                    detail={
                        "build_mode": effective_mode,
                        "build_mode_requested": requested_mode,
                        "degraded": degraded,
                        "query_suite": settings.codeql_query_suite,
                        "elapsed_seconds": elapsed,
                    },
                    error="CodeQL 未生成 SARIF 输出",
                )

            sarif = _read_json_file(sarif_path)
            if not isinstance(sarif, dict):
                sarif = {}
            rules = _lookup_rules(sarif)
            findings: list[dict] = []
            runs = sarif.get("runs")
            if not isinstance(runs, list):
                runs = []
            for run in runs:
                if not isinstance(run, dict):
                    continue
                for result in run.get("results", []) or []:
                    if not isinstance(result, dict):
                        continue
                    rule_id = str(result.get("ruleId") or "codeql.unknown")
                    rule = rules.get(rule_id, {})
                    locations = result.get("locations")
                    if not isinstance(locations, list) or not locations:
                        continue
                    primary = locations[0] if isinstance(locations[0], dict) else {}
                    location = primary.get("physicalLocation") if isinstance(primary.get("physicalLocation"), dict) else {}
                    uri = _artifact_uri(location)
                    abs_path = resolve_file_path(project_path, uri) if uri else project_path
                    line_start = _coerce_line(location)
                    line_end = _coerce_end_line(location, line_start)
                    tags = _collect_tags(rule, result)
                    cwe, owasp = _extract_taxonomy(tags)
                    rule_name = rule.get("name") or rule_id
                    flow_meta = _build_flow_compat(project_path, result)
                    metadata = {
                        "rule_name": rule_name,
                        "rule_description": _message_text(rule.get("shortDescription") if isinstance(rule, dict) else {}),
                        "help_markdown": _message_text(rule.get("fullDescription") if isinstance(rule, dict) else {})
                        or _message_text(rule.get("help") if isinstance(rule, dict) else {}),
                        "precision": (
                            (result.get("properties") or {}).get("precision")
                            if isinstance(result.get("properties"), dict)
                            else None
                        ),
                        "security_severity": (
                            (result.get("properties") or {}).get("security-severity")
                            if isinstance(result.get("properties"), dict)
                            else (rule.get("properties") or {}).get("security-severity")
                            if isinstance(rule.get("properties"), dict)
                            else None
                        ),
                        "cwe": cwe,
                        "owasp": owasp,
                        "tags": tags,
                        "query_suite": used_query_suite,
                        "build_mode": effective_mode,
                        "build_mode_requested": requested_mode,
                        "degraded": degraded,
                        **flow_meta,
                    }
                    findings.append(
                        finding(
                            tool=self.id,
                            rule_id=rule_id,
                            check_id=rule_id,
                            severity=_sarif_severity(result, rule),
                            message=_message_text(result) or str(rule_name),
                            file_path=str(abs_path),
                            line_start=line_start,
                            line_end=line_end,
                            code_snippet=read_code_snippet(abs_path, line_start),
                            metadata=metadata,
                            project_path=project_path,
                        )
                    )

            warning = ""
            if degraded:
                warning = (
                    f"已降级为无编译模式（none）。主构建失败原因: {build_hint or '未知'}。"
                    "数据流精度可能低于完整编译扫描。"
                )

            return ScannerRunResult(
                scanner_id=self.id,
                version=version,
                findings=findings,
                detail={
                    "build_mode": effective_mode,
                    "build_mode_requested": requested_mode,
                    "degraded": degraded,
                    "build_failure_hint": build_hint,
                    "warning": warning,
                    "query_suite": used_query_suite,
                    "query_candidates": query_candidates,
                    "query_attempts": attempts,
                    "java_file_count": len(java_files),
                    "elapsed_seconds": elapsed,
                    "database_timeout": settings.codeql_db_timeout,
                    "analyze_timeout": settings.codeql_timeout,
                    "result_count": len(findings),
                },
            )
