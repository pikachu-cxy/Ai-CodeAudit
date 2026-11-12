"""Resolve Semgrep registry rule packs into a concrete rule inventory (实锤)."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from app.config import settings
from app.services.owasp_classifier import classify_finding

logger = logging.getLogger(__name__)

REGISTRY_BASE = "https://semgrep.dev/c"
CACHE_TTL_SEC = 7 * 24 * 3600
SAMPLE_PER_SUBTYPE = 20
SAMPLE_PER_OWASP = 10

# Semgrep language-pack id → rule `languages` values (lowercase).
CONFIG_TO_LANGUAGES: dict[str, frozenset[str]] = {
    "p/python": frozenset({"python"}),
    "p/javascript": frozenset({"javascript", "typescript"}),
    "p/typescript": frozenset({"typescript", "javascript"}),
    "p/golang": frozenset({"go"}),
    "p/java": frozenset({"java", "kotlin"}),
    "p/kotlin": frozenset({"kotlin", "java"}),
    "p/php": frozenset({"php"}),
    "p/ruby": frozenset({"ruby"}),
    "p/csharp": frozenset({"csharp", "c#"}),
    "p/rust": frozenset({"rust"}),
}

# Language-agnostic Semgrep language tags kept when filtering.
_UNIVERSAL_LANG_TAGS = frozenset({"generic", "regex"})


def languages_from_source_counts(source_counts: dict[str, Any] | None) -> set[str]:
    """Derive project languages from Semgrep plan source_counts keys (e.g. p/java)."""
    langs: set[str] = set()
    for pack, count in (source_counts or {}).items():
        try:
            n = int(count)
        except (TypeError, ValueError):
            n = 0
        if n <= 0:
            continue
        mapped = CONFIG_TO_LANGUAGES.get(str(pack).strip())
        if mapped:
            langs |= set(mapped)
    return langs


def languages_from_configs(configs: list[str] | None) -> set[str]:
    """Infer languages only from language-specific packs (not security-audit / owasp)."""
    langs: set[str] = set()
    for cfg in configs or []:
        mapped = CONFIG_TO_LANGUAGES.get(str(cfg).strip())
        if mapped:
            langs |= set(mapped)
    return langs


def _normalize_lang_set(langs: set[str] | list[str] | None) -> set[str]:
    out: set[str] = set()
    for item in langs or []:
        text = str(item or "").strip().lower()
        if not text:
            continue
        out.add(text)
        if text == "c#":
            out.add("csharp")
        elif text == "csharp":
            out.add("c#")
    return out


def rule_matches_project_languages(
    rule: dict[str, Any],
    project_languages: set[str],
) -> bool:
    """Keep rules that target project languages, or universal/empty language tags."""
    if not project_languages:
        return True
    rule_langs = _normalize_lang_set(rule.get("languages") or [])
    if not rule_langs:
        return True
    if rule_langs & _UNIVERSAL_LANG_TAGS:
        return True
    return bool(rule_langs & project_languages)


def _cache_dir() -> Path:
    d = settings.data_dir / "cache" / "semgrep_rules"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x is not None and str(x).strip()]
    text = str(value).strip()
    return [text] if text else []


def _normalize_cwe(value: Any) -> list[str]:
    out: list[str] = []
    for item in _normalize_list(value):
        text = item.upper().replace(" ", "")
        if text.startswith("CWE-"):
            out.append(text.split(":")[0] if ":" in text else text)
        elif text.isdigit():
            out.append(f"CWE-{text}")
        else:
            # e.g. "CWE-89: SQL Injection"
            import re

            m = re.search(r"CWE-(\d+)", text, re.I)
            if m:
                out.append(f"CWE-{m.group(1)}")
    return out


def _normalize_owasp(value: Any) -> list[str]:
    import re

    out: list[str] = []
    for item in _normalize_list(value):
        m = re.search(r"A(\d{2})", str(item), re.I)
        if m:
            out.append(f"A{m.group(1)}")
    return out


def parse_rules_yaml(raw: str, *, config: str = "") -> list[dict[str, Any]]:
    """Parse Semgrep rules YAML into classified rule dicts (no network)."""
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        return []
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        return []

    parsed: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            continue
        metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        cwe = _normalize_cwe(metadata.get("cwe") or metadata.get("CWE"))
        owasp_meta = _normalize_owasp(metadata.get("owasp") or metadata.get("OWASP"))
        message = str(rule.get("message") or "")[:300]
        severity = str(rule.get("severity") or metadata.get("severity") or "WARNING").upper()
        languages = _normalize_list(rule.get("languages") or rule.get("language"))

        md_for_cls = {
            "cwe": cwe,
            "owasp": owasp_meta,
            "category": metadata.get("category"),
        }
        cls = classify_finding(
            rule_id=rule_id,
            message=message,
            metadata_json=md_for_cls,
            tool="semgrep",
        )
        owasp_ids = owasp_meta or ([cls["owasp_id"]] if cls.get("owasp_id") else [])
        parsed.append({
            "id": rule_id,
            "severity": severity,
            "languages": languages,
            "cwe": cwe,
            "owasp": owasp_ids,
            "subtype": cls.get("vuln_subtype") or "other",
            "config": config,
            "message": message[:160],
        })
    return parsed


def _fetch_registry_yaml(config: str, timeout: float = 60.0) -> str:
    """Fetch rule pack YAML from Semgrep registry (same source as CLI)."""
    cfg = config.strip()
    if not cfg or cfg == "auto":
        return ""
    # Local path / URL passthrough
    if cfg.startswith(("http://", "https://")):
        url = cfg
    elif Path(cfg).expanduser().exists():
        return Path(cfg).expanduser().read_text(encoding="utf-8", errors="replace")
    else:
        # p/security-audit → https://semgrep.dev/c/p/security-audit
        url = f"{REGISTRY_BASE}/{cfg.lstrip('/')}"

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.text


def _load_cached(config: str) -> dict[str, Any] | None:
    path = _cache_dir() / f"{hashlib.sha1(config.encode()).hexdigest()}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - float(data.get("cached_at") or 0) > CACHE_TTL_SEC:
            return None
        return data
    except Exception:
        return None


def _save_cache(config: str, payload: dict[str, Any]) -> None:
    path = _cache_dir() / f"{hashlib.sha1(config.encode()).hexdigest()}.json"
    payload = {**payload, "cached_at": time.time()}
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _dump_config_via_cli(config: str, timeout: float = 90.0) -> str | None:
    """Prefer Semgrep CLI dump-config so inventory matches rules the engine loads."""
    import shutil
    import subprocess

    binary = shutil.which("semgrep")
    if not binary:
        return None
    cfg = (config or "").strip()
    if not cfg or cfg == "auto":
        return None
    if cfg.startswith(("http://", "https://")) or Path(cfg).expanduser().exists():
        # Local/URL configs: read directly rather than CLI dump.
        return None
    try:
        proc = subprocess.run(
            [binary, "--config", cfg, "--dump-config", "--metrics", "off"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except Exception as exc:
        logger.debug("semgrep dump-config failed for %s: %s", cfg, exc)
        return None
    raw = (proc.stdout or "").strip()
    if proc.returncode != 0 or not raw:
        return None
    return raw


def resolve_config_rules(config: str) -> tuple[list[dict[str, Any]], str | None]:
    """Return (rules, error) for one Semgrep config.

    Prefer ``semgrep --dump-config`` (CLI-loaded rules), then registry/HTTP/local YAML.
    """
    cfg = (config or "").strip()
    if not cfg or cfg == "auto":
        return [], None

    cached = _load_cached(cfg)
    if cached and isinstance(cached.get("rules"), list):
        return cached["rules"], None

    raw = None
    source_tag = "semgrep_registry"
    try:
        dumped = _dump_config_via_cli(cfg)
        if dumped:
            raw = dumped
            source_tag = "semgrep_cli_dump"
        else:
            raw = _fetch_registry_yaml(cfg)
        if not raw or not raw.strip():
            return [], f"empty response for {cfg}"
        rules = parse_rules_yaml(raw, config=cfg)
        content_hash = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
        _save_cache(
            cfg,
            {"config": cfg, "content_hash": content_hash, "rules": rules, "source": source_tag},
        )
        return rules, None
    except Exception as exc:
        logger.warning("Failed to resolve Semgrep config %s: %s", cfg, exc)
        return [], str(exc)[:500]


def build_rule_inventory_summary(
    configs: list[str],
    *,
    sample_per_subtype: int = SAMPLE_PER_SUBTYPE,
    project_languages: set[str] | list[str] | None = None,
) -> dict[str, Any]:
    """
    Build persisted rule_inventory summary for scanner_summary.detail.

    Stores by_subtype / by_owasp counts and sample rule ids (not full dump).
    Prefers CLI dump-config when available so counts reflect rules Semgrep loads.

    When ``project_languages`` is set, drop rules whose languages do not intersect
    the project (empty/generic languages are kept).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_rules: list[dict[str, Any]] = []
    errors: list[str] = []
    resolved_configs: list[str] = []
    used_cli = False

    work = [cfg for cfg in configs if cfg and cfg != "auto"]
    results: list[tuple[str, list[dict[str, Any]], str | None]] = []
    if work:
        workers = min(4, len(work))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(resolve_config_rules, cfg): cfg for cfg in work}
            for fut in as_completed(futures):
                cfg = futures[fut]
                try:
                    rules, err = fut.result()
                except Exception as exc:
                    rules, err = [], str(exc)[:500]
                results.append((cfg, rules, err))

    # Preserve original config order for stable output
    by_cfg = {cfg: (rules, err) for cfg, rules, err in results}
    for cfg in work:
        rules, err = by_cfg.get(cfg, ([], f"missing result for {cfg}"))
        if err:
            errors.append(f"{cfg}: {err}")
            continue
        resolved_configs.append(cfg)
        all_rules.extend(rules)
        cached = _load_cached(cfg)
        if cached and cached.get("source") == "semgrep_cli_dump":
            used_cli = True

    # Deduplicate by rule id (later packs may overlap)
    by_id: dict[str, dict[str, Any]] = {}
    for r in all_rules:
        rid = r["id"]
        if rid not in by_id:
            by_id[rid] = r
    unique = list(by_id.values())
    unfiltered_total = len(unique)

    lang_set = _normalize_lang_set(project_languages)
    filtered = bool(lang_set)
    if filtered:
        unique = [r for r in unique if rule_matches_project_languages(r, lang_set)]

    by_subtype: Counter[str] = Counter()
    by_owasp: Counter[str] = Counter()
    samples_by_subtype: dict[str, list[str]] = {}
    samples_by_owasp: dict[str, list[str]] = {}

    for r in unique:
        subtype = str(r.get("subtype") or "other")
        by_subtype[subtype] += 1
        bucket = samples_by_subtype.setdefault(subtype, [])
        if len(bucket) < sample_per_subtype:
            bucket.append(r["id"])

        for oid in r.get("owasp") or []:
            by_owasp[str(oid)] += 1
            ob = samples_by_owasp.setdefault(str(oid), [])
            if len(ob) < SAMPLE_PER_OWASP:
                ob.append(r["id"])

    inventory_error = "; ".join(errors) if errors else None
    if not unique and inventory_error and unfiltered_total == 0:
        source = "error"
    elif unique and used_cli:
        source = "semgrep_cli_dump"
    elif unique:
        source = "semgrep_registry"
    elif unfiltered_total > 0 and filtered:
        source = "semgrep_cli_dump" if used_cli else "semgrep_registry"
    else:
        source = "empty"

    return {
        "source": source,
        "configs": resolved_configs or list(configs),
        "total_rules": len(unique),
        "by_subtype": dict(by_subtype),
        "by_owasp": dict(by_owasp),
        "sample_rules_by_subtype": samples_by_subtype,
        "sample_rules_by_owasp": samples_by_owasp,
        "inventory_error": inventory_error,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "project_languages": sorted(lang_set) if filtered else [],
        "filtered": filtered,
        "unfiltered_total_rules": unfiltered_total,
    }


def format_inventory_log_line(inventory: dict[str, Any]) -> str:
    """Short scan-event message for rule inventory."""
    total = int(inventory.get("total_rules") or 0)
    by_sub = inventory.get("by_subtype") or {}
    highlights = []
    for key in ("sql_injection", "xss", "command_injection", "ssrf", "path_traversal", "deserialization"):
        if by_sub.get(key):
            highlights.append(f"{key}={by_sub[key]}")
    extra = "，".join(highlights[:8]) if highlights else "无重点子类型命中"
    src = inventory.get("source") or "unknown"
    err = inventory.get("inventory_error")
    msg = f"Semgrep 规则清单: 共 {total} 条；{extra}（来源 {src}）"
    if err:
        msg += f"；部分失败: {err[:200]}"
    return msg
