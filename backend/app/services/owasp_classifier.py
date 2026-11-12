"""Map SAST/SCA findings to OWASP Top 10 (2021)."""

import json
import re
from typing import Any

OWASP_TOP10: dict[str, str] = {
    "A01": "访问控制失效",
    "A02": "加密机制失效",
    "A03": "注入",
    "A04": "不安全设计",
    "A05": "安全配置错误",
    "A06": "易受攻击和过时的组件",
    "A07": "身份识别和身份验证失败",
    "A08": "软件和数据完整性失效",
    "A09": "安全日志和监控失效",
    "A10": "服务端请求伪造 (SSRF)",
}

# CWE prefix -> OWASP id (common mappings)
CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01", "CWE-23": "A01", "CWE-35": "A01", "CWE-59": "A01",
    "CWE-200": "A01", "CWE-201": "A01", "CWE-219": "A01", "CWE-264": "A01",
    "CWE-275": "A01", "CWE-276": "A01", "CWE-284": "A01", "CWE-285": "A01",
    "CWE-352": "A01", "CWE-359": "A01", "CWE-377": "A01", "CWE-402": "A01",
    "CWE-425": "A01", "CWE-434": "A01", "CWE-441": "A01", "CWE-497": "A01",
    "CWE-538": "A01", "CWE-540": "A01", "CWE-548": "A01", "CWE-552": "A01",
    "CWE-566": "A01", "CWE-601": "A01", "CWE-639": "A01", "CWE-651": "A01",
    "CWE-668": "A01", "CWE-706": "A01", "CWE-862": "A01", "CWE-863": "A01",
    "CWE-259": "A02", "CWE-261": "A02", "CWE-296": "A02", "CWE-310": "A02",
    "CWE-319": "A02", "CWE-321": "A02", "CWE-322": "A02", "CWE-323": "A02",
    "CWE-324": "A02", "CWE-325": "A02", "CWE-326": "A02", "CWE-327": "A02",
    "CWE-328": "A02", "CWE-329": "A02", "CWE-330": "A02", "CWE-331": "A02",
    "CWE-335": "A02", "CWE-336": "A02", "CWE-337": "A02", "CWE-338": "A02",
    "CWE-340": "A02", "CWE-347": "A02", "CWE-523": "A02", "CWE-757": "A02",
    "CWE-759": "A02", "CWE-760": "A02", "CWE-780": "A02", "CWE-798": "A02",
    "CWE-916": "A02",
    "CWE-20": "A03", "CWE-74": "A03", "CWE-75": "A03", "CWE-77": "A03",
    "CWE-78": "A03", "CWE-79": "A03", "CWE-80": "A03", "CWE-83": "A03",
    "CWE-86": "A03", "CWE-87": "A03", "CWE-88": "A03", "CWE-89": "A03",
    "CWE-90": "A03", "CWE-91": "A03", "CWE-94": "A03", "CWE-95": "A03",
    "CWE-96": "A03", "CWE-97": "A03", "CWE-98": "A03", "CWE-99": "A03",
    "CWE-113": "A03", "CWE-116": "A03", "CWE-118": "A03",
    "CWE-119": "A03", "CWE-120": "A03", "CWE-123": "A03", "CWE-129": "A03",
    "CWE-134": "A03", "CWE-917": "A03",
    "CWE-256": "A04", "CWE-501": "A04", "CWE-522": "A04", "CWE-799": "A04",
    "CWE-16": "A05", "CWE-2": "A05", "CWE-11": "A05", "CWE-13": "A05",
    "CWE-15": "A05", "CWE-260": "A05", "CWE-315": "A05", "CWE-520": "A05",
    "CWE-526": "A05", "CWE-537": "A05", "CWE-614": "A05", "CWE-756": "A05",
    "CWE-776": "A05", "CWE-942": "A05", "CWE-1004": "A05", "CWE-1032": "A05",
    "CWE-1104": "A06",
    "CWE-287": "A07", "CWE-288": "A07", "CWE-289": "A07", "CWE-290": "A07",
    "CWE-291": "A07", "CWE-293": "A07", "CWE-294": "A07", "CWE-295": "A07",
    "CWE-297": "A07", "CWE-300": "A07", "CWE-302": "A07", "CWE-304": "A07",
    "CWE-306": "A07", "CWE-307": "A07", "CWE-346": "A07", "CWE-384": "A07",
    "CWE-521": "A07", "CWE-613": "A07", "CWE-620": "A07", "CWE-640": "A07",
    "CWE-798": "A07",
    "CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08", "CWE-494": "A08",
    "CWE-502": "A08", "CWE-565": "A08", "CWE-784": "A08", "CWE-829": "A08",
    "CWE-830": "A08",
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",
    "CWE-918": "A10",
}

RULE_KEYWORDS: list[tuple[str, list[str]]] = [
    ("A03", ["sql-injection", "sqli", "xss", "command-injection", "ldap-injection",
             "xpath-injection", "template-injection", "ssti", "nosql", "injection",
             "eval", "exec", "shell", "os-command"]),
    ("A02", ["hardcoded", "secret", "password", "api-key", "apikey", "credential",
             "crypto", "weak-cipher", "md5", "sha1", "tls", "ssl", "gitleaks"]),
    ("A01", ["idor", "access-control", "authorization", "authz", "privilege",
             "path-traversal", "directory-traversal", "lfi", "rfi", "open-redirect"]),
    ("A07", ["auth", "login", "session", "jwt", "oauth", "password", "brute",
             "authentication", "csrf"]),
    ("A05", ["misconfig", "debug", "default", "cors", "header", "cookie",
             "security-headers", "hsts", "clickjacking"]),
    ("A06", ["npm", "pip", "dependency", "outdated", "vulnerable-component", "cve-"]),
    ("A08", ["deserial", "pickle", "yaml.load", "integrity", "supply-chain", "unsigned"]),
    ("A09", ["log", "audit", "monitor", "logging"]),
    ("A10", ["ssrf", "request-forgery", "url-fetch"]),
    ("A04", ["business-logic", "race", "dos", "resource-exhaustion"]),
]


def _parse_metadata(raw: str | dict | None) -> dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _extract_owasp_from_metadata(md: dict[str, Any]) -> str | None:
    owasp = md.get("owasp") or md.get("OWASP")
    if not owasp:
        return None
    items = owasp if isinstance(owasp, list) else [owasp]
    for item in items:
        text = str(item)
        m = re.search(r"A(\d{2})", text, re.I)
        if m:
            return f"A{m.group(1)}"
    return None


def _extract_cwe_owasp(md: dict[str, Any]) -> str | None:
    cwe = md.get("cwe") or md.get("CWE")
    if not cwe:
        return None
    items = cwe if isinstance(cwe, list) else [cwe]
    for item in items:
        text = str(item).upper().replace(" ", "")
        m = re.match(r"(CWE-\d+)", text)
        if m and m.group(1) in CWE_TO_OWASP:
            return CWE_TO_OWASP[m.group(1)]
        num = re.search(r"CWE-(\d+)", text)
        if num:
            key = f"CWE-{num.group(1)}"
            if key in CWE_TO_OWASP:
                return CWE_TO_OWASP[key]
    return None


def _match_keywords(text: str) -> str | None:
    lower = text.lower()
    for owasp_id, keywords in RULE_KEYWORDS:
        for kw in keywords:
            if kw in lower:
                return owasp_id
    return None


def classify_owasp(
    *,
    rule_id: str = "",
    message: str = "",
    metadata_json: str | dict | None = None,
    tool: str = "",
    category: str | None = None,
) -> tuple[str, str]:
    """Return (owasp_id, owasp_name). Defaults to A04 for unknown design issues."""
    if category == "authorization":
        return "A01", OWASP_TOP10["A01"]
    if category == "business_logic":
        return "A04", OWASP_TOP10["A04"]

    md = _parse_metadata(metadata_json)

    owasp_id = _extract_owasp_from_metadata(md)
    if not owasp_id:
        owasp_id = _extract_cwe_owasp(md)
    if not owasp_id:
        owasp_id = _match_keywords(f"{rule_id} {message} {json.dumps(md, ensure_ascii=False)}")

    if tool in ("npm_audit", "pip_audit", "dep_exploit"):
        owasp_id = owasp_id or "A06"
    elif tool == "gitleaks":
        owasp_id = owasp_id or "A02"

    if not owasp_id:
        owasp_id = "A04"

    return owasp_id, OWASP_TOP10.get(owasp_id, "其他")


# --- Vulnerability sub-types (二级分类) ---

VULN_SUBTYPE_LABELS: dict[str, str] = {
    # A03 注入
    "sql_injection": "SQL 注入",
    "xss": "XSS 跨站脚本",
    "command_injection": "命令注入",
    "ldap_injection": "LDAP 注入",
    "xpath_injection": "XPath 注入",
    "nosql_injection": "NoSQL 注入",
    "ssti": "模板注入 (SSTI)",
    "header_injection": "Header 注入",
    "code_injection": "代码注入",
    "xml_injection": "XML 注入",
    "expression_injection": "表达式注入",
    "log_injection": "日志注入",
    "other_injection": "其他注入",
    # A01
    "path_traversal": "路径遍历",
    "idor": "IDOR / 越权访问",
    "open_redirect": "开放重定向",
    "csrf": "CSRF",
    "broken_access_control": "访问控制缺陷",
    # A02
    "hardcoded_secret": "硬编码密钥",
    "weak_crypto": "弱加密",
    # A05
    "security_misconfiguration": "安全配置错误",
    # A06
    "vulnerable_dependency": "脆弱依赖",
    # A07
    "auth_failure": "认证失效",
    # A08
    "deserialization": "不安全反序列化",
    # A10
    "ssrf": "SSRF",
    # 通用
    "other": "其他",
}

INJECTION_SUBTYPES = [
    "sql_injection", "xss", "command_injection", "ldap_injection", "xpath_injection",
    "nosql_injection", "ssti", "header_injection", "code_injection", "xml_injection",
    "expression_injection", "log_injection", "other_injection",
]

CWE_TO_SUBTYPE: dict[str, str] = {
    "CWE-89": "sql_injection",
    "CWE-564": "sql_injection",
    "CWE-943": "nosql_injection",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-83": "xss", "CWE-87": "xss",
    "CWE-116": "xss",
    "CWE-78": "command_injection", "CWE-77": "command_injection",
    "CWE-90": "ldap_injection",
    "CWE-91": "xpath_injection", "CWE-643": "xpath_injection",
    "CWE-94": "code_injection", "CWE-95": "code_injection", "CWE-96": "code_injection",
    "CWE-917": "expression_injection",
    "CWE-1336": "ssti",
    "CWE-113": "header_injection", "CWE-93": "header_injection",
    "CWE-91": "xpath_injection",
    "CWE-611": "xml_injection",
    "CWE-117": "log_injection",
    "CWE-22": "path_traversal", "CWE-23": "path_traversal", "CWE-36": "path_traversal",
    "CWE-639": "idor", "CWE-862": "idor", "CWE-863": "idor",
    "CWE-601": "open_redirect", "CWE-352": "csrf",
    "CWE-798": "hardcoded_secret", "CWE-259": "hardcoded_secret",
    "CWE-327": "weak_crypto", "CWE-326": "weak_crypto", "CWE-328": "weak_crypto",
    "CWE-502": "deserialization",
    "CWE-918": "ssrf",
    "CWE-287": "auth_failure", "CWE-306": "auth_failure",
}

SUBTYPE_KEYWORDS: list[tuple[str, list[str]]] = [
    ("sql_injection", ["sql-injection", "sqli", "sql injection", "jdbc", "sql-inject", "tainted-sql"]),
    ("xss", ["xss", "cross-site-script", "cross site script", "innerhtml", "dangerouslysetinnerhtml", "reflected-xss", "stored-xss"]),
    ("command_injection", ["command-injection", "os-command", "shell-command", "exec(", "runtime.exec", "subprocess", "shell-injection"]),
    ("ldap_injection", ["ldap-injection", "ldap injection"]),
    ("xpath_injection", ["xpath-injection", "xpath injection"]),
    ("nosql_injection", ["nosql", "mongodb-injection", "mongo injection"]),
    ("ssti", ["ssti", "template-injection", "server-side-template", "freemarker", "velocity", "thymeleaf", "jinja"]),
    ("header_injection", ["header-injection", "crlf", "http-response-splitting"]),
    ("code_injection", ["code-injection", "eval(", "code injection", "dynamic-code"]),
    ("xml_injection", ["xml-injection", "xxe", "xml external entity"]),
    ("expression_injection", ["expression-language", "el-injection", "ognl", "spel"]),
    ("log_injection", ["log-injection", "log forging", "log injection"]),
    ("path_traversal", ["path-traversal", "directory-traversal", "lfi", "file-inclusion", "../"]),
    ("idor", ["idor", "insecure-direct-object", "direct-object-reference"]),
    ("open_redirect", ["open-redirect", "unvalidated-redirect"]),
    ("csrf", ["csrf", "cross-site-request-forgery"]),
    ("hardcoded_secret", ["hardcoded", "api-key", "apikey", "secret", "password", "credential", "gitleaks"]),
    ("weak_crypto", ["weak-cipher", "md5", "sha1", "des-", "rc4", "weak-crypto", "insecure-random"]),
    ("deserialization", ["deserial", "pickle", "yaml.load", "objectinputstream", "readobject"]),
    ("ssrf", ["ssrf", "server-side-request-forgery", "url-fetch"]),
    ("auth_failure", ["broken-auth", "weak-password", "session-fixation", "jwt-none"]),
    ("vulnerable_dependency", ["cve-", "npm audit", "pip audit", "vulnerable-component"]),
    ("security_misconfiguration", ["misconfig", "debug-enabled", "default-credential", "cors", "hsts"]),
]

OWASP_DEFAULT_SUBTYPE: dict[str, str] = {
    "A01": "broken_access_control",
    "A02": "hardcoded_secret",
    "A03": "other_injection",
    "A05": "security_misconfiguration",
    "A06": "vulnerable_dependency",
    "A07": "auth_failure",
    "A08": "deserialization",
    "A10": "ssrf",
    "A04": "other",
    "A09": "other",
}

# 子类确定后，强制对齐 OWASP 一级分类（避免一级/二级不一致导致筛选为空）
SUBTYPE_TO_OWASP: dict[str, str] = {
    "sql_injection": "A03", "xss": "A03", "command_injection": "A03",
    "ldap_injection": "A03", "xpath_injection": "A03", "nosql_injection": "A03",
    "ssti": "A03", "header_injection": "A03", "code_injection": "A03",
    "xml_injection": "A03", "expression_injection": "A03", "log_injection": "A03",
    "other_injection": "A03",
    "path_traversal": "A01", "idor": "A01", "open_redirect": "A01",
    "csrf": "A01", "broken_access_control": "A01",
    "hardcoded_secret": "A02", "weak_crypto": "A02",
    "security_misconfiguration": "A05",
    "vulnerable_dependency": "A06",
    "auth_failure": "A07",
    "deserialization": "A08",
    "ssrf": "A10",
}


def _extract_cwe_subtype(md: dict[str, Any]) -> str | None:
    cwe = md.get("cwe") or md.get("CWE")
    if not cwe:
        return None
    items = cwe if isinstance(cwe, list) else [cwe]
    for item in items:
        text = str(item).upper()
        m = re.search(r"CWE-(\d+)", text)
        if m:
            key = f"CWE-{m.group(1)}"
            if key in CWE_TO_SUBTYPE:
                return CWE_TO_SUBTYPE[key]
    return None


def _match_subtype_keywords(text: str) -> str | None:
    lower = text.lower()
    for subtype, keywords in SUBTYPE_KEYWORDS:
        for kw in keywords:
            if kw in lower:
                return subtype
    return None


def classify_vuln_subtype(
    *,
    rule_id: str = "",
    message: str = "",
    metadata_json: str | dict | None = None,
    tool: str = "",
    owasp_id: str | None = None,
    category: str | None = None,
) -> tuple[str, str]:
    """Return (subtype_id, subtype_name)."""
    if category == "authorization":
        return "idor", VULN_SUBTYPE_LABELS["idor"]
    if category == "business_logic":
        return "other", VULN_SUBTYPE_LABELS["other"]

    md = _parse_metadata(metadata_json)
    blob = f"{rule_id} {message} {json.dumps(md, ensure_ascii=False)}"

    subtype = _extract_cwe_subtype(md)
    if not subtype:
        subtype = _match_subtype_keywords(blob)

    if not subtype and owasp_id:
        subtype = OWASP_DEFAULT_SUBTYPE.get(owasp_id, "other")

    if not subtype:
        subtype = "other"

    return subtype, VULN_SUBTYPE_LABELS.get(subtype, subtype)


def classify_finding(
    *,
    rule_id: str = "",
    message: str = "",
    metadata_json: str | dict | None = None,
    tool: str = "",
    category: str | None = None,
) -> dict[str, str]:
    owasp_id, owasp_name = classify_owasp(
        rule_id=rule_id,
        message=message,
        metadata_json=metadata_json,
        tool=tool,
        category=category,
    )
    subtype, subtype_name = classify_vuln_subtype(
        rule_id=rule_id,
        message=message,
        metadata_json=metadata_json,
        tool=tool,
        owasp_id=owasp_id,
        category=category,
    )
    if subtype in SUBTYPE_TO_OWASP:
        owasp_id = SUBTYPE_TO_OWASP[subtype]
        owasp_name = OWASP_TOP10[owasp_id]
    return {
        "owasp_id": owasp_id,
        "owasp_name": owasp_name,
        "vuln_subtype": subtype,
        "vuln_subtype_name": subtype_name,
    }
