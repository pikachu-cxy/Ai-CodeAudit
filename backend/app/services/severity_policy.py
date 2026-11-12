"""Adjust finding severity using vulnerability-type policy."""

_SEVERITY_ORDER = ("UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Minimum severity floor by vulnerability sub-type
SUBTYPE_SEVERITY_FLOOR: dict[str, str] = {
    "sql_injection": "HIGH",
    "command_injection": "CRITICAL",
    "code_injection": "CRITICAL",
    "xss": "HIGH",
    "ldap_injection": "HIGH",
    "xpath_injection": "HIGH",
    "nosql_injection": "HIGH",
    "ssti": "HIGH",
    "header_injection": "HIGH",
    "xml_injection": "HIGH",
    "expression_injection": "HIGH",
    "log_injection": "MEDIUM",
    "other_injection": "HIGH",
    "path_traversal": "HIGH",
    "idor": "HIGH",
    "open_redirect": "MEDIUM",
    "csrf": "MEDIUM",
    "deserialization": "CRITICAL",
    "ssrf": "HIGH",
    "hardcoded_secret": "HIGH",
    "weak_crypto": "MEDIUM",
    "auth_failure": "HIGH",
}

OWASP_SEVERITY_FLOOR: dict[str, str] = {
    "A03": "HIGH",
    "A08": "HIGH",
    "A10": "HIGH",
}


def _severity_rank(value: str) -> int:
    key = (value or "UNKNOWN").upper()
    try:
        return _SEVERITY_ORDER.index(key)
    except ValueError:
        return 0


def max_severity(*values: str) -> str:
    best = "UNKNOWN"
    best_rank = -1
    for value in values:
        if not value:
            continue
        rank = _severity_rank(value)
        if rank > best_rank:
            best = value.upper()
            best_rank = rank
    return best


def adjust_severity(
    current: str,
    *,
    vuln_subtype: str | None = None,
    owasp_id: str | None = None,
) -> str:
    """
    Raise severity to a type-based floor without downgrading tool-reported levels.
    Semgrep often reports injection rules as WARNING -> MEDIUM; SQLi/XSS should be HIGH+.
    """
    floor = SUBTYPE_SEVERITY_FLOOR.get(vuln_subtype or "")
    if not floor and owasp_id:
        floor = OWASP_SEVERITY_FLOOR.get(owasp_id)
    candidates = [current or "UNKNOWN"]
    if floor:
        candidates.append(floor)
    return max_severity(*candidates)
