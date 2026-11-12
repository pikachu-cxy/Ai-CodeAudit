"""Project / Semgrep language ids and helpers."""

from __future__ import annotations

import json
from typing import Any

# User-facing language ids (API / UI).
ALLOWED_SCAN_LANGUAGES: tuple[str, ...] = (
    "java",
    "python",
    "javascript",
    "typescript",
    "go",
    "php",
    "ruby",
    "csharp",
    "kotlin",
    "rust",
)

LANGUAGE_LABELS: dict[str, str] = {
    "java": "Java",
    "python": "Python",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "go": "Go",
    "php": "PHP",
    "ruby": "Ruby",
    "csharp": "C#",
    "kotlin": "Kotlin",
    "rust": "Rust",
}

# User language id → Semgrep pack.
LANGUAGE_TO_PACK: dict[str, str] = {
    "java": "p/java",
    "python": "p/python",
    "javascript": "p/javascript",
    "typescript": "p/typescript",
    "go": "p/golang",
    "php": "p/php",
    "ruby": "p/ruby",
    "csharp": "p/csharp",
    "kotlin": "p/kotlin",
    "rust": "p/rust",
}

# Semgrep pack → user language ids (primary first).
PACK_TO_LANGUAGES: dict[str, tuple[str, ...]] = {
    "p/java": ("java", "kotlin"),
    "p/kotlin": ("kotlin", "java"),
    "p/python": ("python",),
    "p/javascript": ("javascript",),
    "p/typescript": ("typescript",),
    "p/golang": ("go",),
    "p/php": ("php",),
    "p/ruby": ("ruby",),
    "p/csharp": ("csharp",),
    "p/rust": ("rust",),
}


def normalize_scan_languages(raw: Any) -> list[str]:
    """Return de-duplicated allowed language ids; invalid entries dropped."""
    if raw is None:
        return []
    items: list[Any]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            items = parsed if isinstance(parsed, list) else [text]
        except json.JSONDecodeError:
            items = [p.strip() for p in text.split(",") if p.strip()]
    elif isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        lang = str(item or "").strip().lower()
        if lang == "c#":
            lang = "csharp"
        if lang == "golang":
            lang = "go"
        if lang not in ALLOWED_SCAN_LANGUAGES or lang in seen:
            continue
        seen.add(lang)
        out.append(lang)
    return out


def pack_scan_languages_json(langs: list[str] | None) -> str | None:
    cleaned = normalize_scan_languages(langs)
    if not cleaned:
        return None
    return json.dumps(cleaned, ensure_ascii=False)


def parse_scan_languages_json(raw: str | None) -> list[str]:
    if not raw or not str(raw).strip():
        return []
    return normalize_scan_languages(raw)


def packs_for_languages(langs: list[str] | set[str] | None) -> list[str]:
    """Ordered unique Semgrep language packs for user language ids."""
    packs: list[str] = []
    seen: set[str] = set()
    for lang in normalize_scan_languages(list(langs or [])):
        pack = LANGUAGE_TO_PACK.get(lang)
        if pack and pack not in seen:
            seen.add(pack)
            packs.append(pack)
    return packs


def detected_languages_from_source_counts(
    source_counts: dict[str, Any] | None,
    *,
    primary_ratio: float = 0.65,
) -> list[dict[str, Any]]:
    """Build display rows from Semgrep detail.source_counts (pack → file count)."""
    tallies: dict[str, int] = {}
    for pack, count in (source_counts or {}).items():
        try:
            n = int(count)
        except (TypeError, ValueError):
            n = 0
        if n <= 0:
            continue
        langs = PACK_TO_LANGUAGES.get(str(pack).strip())
        if not langs:
            continue
        # Attribute count to the pack's primary language id.
        primary = langs[0]
        tallies[primary] = tallies.get(primary, 0) + n

    if not tallies:
        return []
    total = sum(tallies.values())
    ordered = sorted(tallies.items(), key=lambda kv: (-kv[1], kv[0]))
    top_id, top_count = ordered[0]
    primary_id = top_id if (total > 0 and top_count / total >= primary_ratio) or len(ordered) == 1 else top_id
    return [
        {
            "id": lang_id,
            "label": LANGUAGE_LABELS.get(lang_id, lang_id),
            "file_count": count,
            "primary": lang_id == primary_id,
        }
        for lang_id, count in ordered
    ]


def detected_languages_from_scanner_summary(scanner_summary: str | None) -> list[dict[str, Any]]:
    if not scanner_summary or not str(scanner_summary).strip():
        return []
    try:
        parsed = json.loads(scanner_summary)
    except json.JSONDecodeError:
        return []
    runs = parsed if isinstance(parsed, list) else []
    if isinstance(parsed, dict) and isinstance(parsed.get("scanners"), list):
        runs = parsed["scanners"]
    for entry in runs:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("scanner") or "") != "semgrep":
            continue
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        counts = detail.get("source_counts") if isinstance(detail, dict) else None
        return detected_languages_from_source_counts(counts if isinstance(counts, dict) else None)
    return []
