import json
import logging
import urllib.request
from typing import Iterable

from app.config import settings
from app.models import Finding, FindingCategory, ReviewStatus, ScanKind, ScanSource, Severity
from app.services.scanners.common import to_repo_relative_path

logger = logging.getLogger(__name__)

_CATEGORY_LABELS: dict[str, str] = {
    FindingCategory.SAST.value: "SAST 静态分析",
    FindingCategory.BUSINESS_LOGIC.value: "业务逻辑",
    FindingCategory.AUTHORIZATION.value: "鉴权/越权",
}

_SOURCE_LABELS: dict[str, str] = {
    ScanSource.UPLOAD.value: "ZIP 上传",
    ScanSource.GITLAB.value: "GitLab",
    ScanSource.LOCAL.value: "本地",
}

_SCAN_KIND_LABELS: dict[str, str] = {
    ScanKind.BASELINE.value: "基线扫描",
    ScanKind.RETEST.value: "复测扫描",
    ScanKind.AD_HOC.value: "追加版本",
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

_REVIEW_LABELS: dict[str, str] = {
    ReviewStatus.UNREVIEWED.value: "未标记",
    ReviewStatus.CONFIRMED.value: "已确认",
    ReviewStatus.FALSE_POSITIVE.value: "误报",
    ReviewStatus.FIXED.value: "已修复",
}


def _frontend_base_url() -> str:
    base = getattr(settings, "frontend_base_url", "") or ""
    base = base.strip().rstrip("/")
    if base:
        return base
    return f"http://{settings.app_host}:{settings.app_port}"


def _build_finding_link(scan_id: int, finding_id: int) -> str:
    base = _frontend_base_url()
    return f"{base}/?scanId={scan_id}&findingId={finding_id}"


def _build_scan_link(scan_id: int, project_id: int | None = None) -> str:
    base = _frontend_base_url()
    if project_id:
        return f"{base}/?scanId={scan_id}&projectId={project_id}"
    return f"{base}/?scanId={scan_id}"


def _format_breakdown(counts: dict[str, int], *, order: list[str] | None = None, empty: str = "无") -> str:
    if not counts:
        return empty
    keys = order or sorted(counts.keys(), key=lambda k: (-counts[k], k))
    parts = [f"{k}:{counts[k]}" for k in keys if counts.get(k)]
    return "、".join(parts) if parts else empty


def _category_breakdown(by_category: dict[str, int]) -> str:
    if not by_category:
        return "无"
    parts: list[str] = []
    for key, count in sorted(by_category.items(), key=lambda item: (-item[1], item[0])):
        if not count:
            continue
        label = _CATEGORY_LABELS.get(key, key)
        parts.append(f"{label}:{count}")
    return "、".join(parts) if parts else "无"


def build_external_review_link(token: str) -> str:
    base = _frontend_base_url()
    return f"{base}/?reviewToken={token}"


def build_project_review_link(token: str) -> str:
    base = _frontend_base_url()
    return f"{base}/?projectReviewToken={token}"


def _at_text(user_ids: Iterable[str]) -> str:
    ids = [str(u).strip() for u in (user_ids or []) if str(u).strip()]
    if not ids:
        return ""
    return "".join([f'<at id="{uid}"></at>' for uid in ids]) + " "


def _at_text_plain(user_ids: Iterable[str]) -> str:
    ids = [str(u).strip() for u in (user_ids or []) if str(u).strip()]
    if not ids:
        return ""
    return "".join([f'<at user_id="{uid}"></at>' for uid in ids]) + " "


def _severity_rank(sev: Severity | str | None) -> int:
    if isinstance(sev, Severity):
        sev = sev.value
    s = str(sev or "").upper()
    return {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}.get(s, -1)


def _should_notify(severity: Severity, review_status: ReviewStatus | None = None) -> bool:
    min_sev_raw = getattr(settings, "feishu_notify_min_severity", "HIGH")
    return _severity_rank(severity) >= _severity_rank(min_sev_raw)


def _post_json(url: str, payload: dict, timeout_s: int = 8) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {"raw": body}


def _card_element_markdown(content: str) -> dict:
    return {"tag": "div", "text": {"tag": "lark_md", "content": content}}


def _card_element_hr() -> dict:
    return {"tag": "hr"}


def _card_element_button(text: str, url: str) -> dict:
    return {
        "tag": "action",
        "actions": [
            {
                "tag": "button",
                "text": {"tag": "plain_text", "content": text},
                "url": url,
                "type": "primary",
            }
        ],
    }


def _build_card(*, title: str, template: str, lines: list[str], link: str | None = None, link_label: str = "查看详情") -> dict:
    elements: list[dict] = [_card_element_markdown("\n".join(lines))]
    if link:
        elements.extend([_card_element_hr(), _card_element_button(link_label, link)])
    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": title},
                "template": template,
            },
            "elements": elements,
        },
    }


def _send_feishu_payload(payload: dict, *, override_webhook_url: str | None = None) -> bool:
    webhook = (override_webhook_url or getattr(settings, "feishu_webhook_url", "") or "").strip()
    if not webhook:
        logger.info("Feishu notify skipped: webhook URL not configured")
        return False
    try:
        result = _post_json(webhook, payload)
        if result.get("code") not in (None, 0):
            logger.warning("Feishu notify rejected: %s", result)
            return False
        return True
    except Exception as exc:
        logger.warning("Feishu notify failed: %s", exc)
        return False


def _send_feishu_text(text: str, *, override_webhook_url: str | None = None) -> bool:
    payload = {"msg_type": "text", "content": {"text": text.strip()}}
    return _send_feishu_payload(payload, override_webhook_url=override_webhook_url)


def _send_feishu_card(card: dict, *, override_webhook_url: str | None = None, fallback_text: str | None = None) -> bool:
    if _send_feishu_payload(card, override_webhook_url=override_webhook_url):
        return True
    if fallback_text:
        logger.info("Feishu card failed, falling back to text")
        return _send_feishu_text(fallback_text, override_webhook_url=override_webhook_url)
    return False


def send_feishu_scan_started(
    *,
    scan_id: int,
    scan_name: str,
    project_id: int | None = None,
    project_name: str | None = None,
    source: str,
    scan_kind: str,
    version_label: str | None = None,
    branch: str | None = None,
    source_url: str | None = None,
    enabled_scanners: list[str] | None = None,
    override_webhook_url: str | None = None,
) -> bool:
    """Notify Feishu when a scan pipeline starts."""
    at_ids = getattr(settings, "feishu_at_user_ids", []) or []
    at = _at_text(at_ids)
    link = _build_scan_link(scan_id, project_id)
    source_label = _SOURCE_LABELS.get(source, source)
    kind_label = _SCAN_KIND_LABELS.get(scan_kind, scan_kind)
    scanners = "、".join(enabled_scanners or []) or "（系统默认）"

    version_part = f" | 版本: {version_label}" if version_label else ""
    branch_part = f" | 分支: {branch}" if branch else ""
    lines = [
        f"{at}**项目**: {project_name or '—'} (ID {project_id or '—'})",
        f"**扫描**: {scan_name} (#{scan_id})",
        f"**类型**: {kind_label}{version_part}",
        f"**来源**: {source_label}{branch_part}",
        f"**启用扫描器**: {scanners}",
    ]
    if source_url:
        lines.append(f"**仓库**: {source_url}")

    fallback = "\n".join(
        [
            f"{_at_text_plain(at_ids)}【扫描已开始】",
            f"项目: {project_name or '—'} (ID {project_id or '—'})",
            f"扫描: {scan_name} (#{scan_id})",
            f"类型: {kind_label}{version_part}",
            f"来源: {source_label}{branch_part}",
            f"启用扫描器: {scanners}",
            *( [f"仓库: {source_url}"] if source_url else [] ),
            f"详情: {link}",
        ]
    )
    card = _build_card(title="扫描已开始", template="blue", lines=lines, link=link)
    return _send_feishu_card(card, override_webhook_url=override_webhook_url, fallback_text=fallback)


def send_feishu_scan_completed(
    *,
    scan_id: int,
    scan_name: str,
    project_id: int | None = None,
    project_name: str | None = None,
    stats: dict,
    failed: bool = False,
    error_message: str | None = None,
    override_webhook_url: str | None = None,
) -> bool:
    """Notify Feishu when a scan pipeline finishes (success or failure)."""
    at_ids = getattr(settings, "feishu_at_user_ids", []) or []
    at = _at_text(at_ids)
    link = _build_scan_link(scan_id, project_id)
    total = int(stats.get("total") or 0)
    by_severity = stats.get("by_severity") or {}
    by_category = stats.get("by_category") or {}
    by_tool = stats.get("by_tool") or {}

    title = "扫描已失败" if failed else "扫描已完成"
    template = "red" if failed else "green"
    lines = [
        f"{at}**项目**: {project_name or '—'} (ID {project_id or '—'})",
        f"**扫描**: {scan_name} (#{scan_id})",
        f"**漏洞总数**: {total}",
        f"**按严重性**: {_format_breakdown(by_severity, order=_SEVERITY_ORDER)}",
        f"**按类型**: {_category_breakdown(by_category)}",
        f"**按工具**: {_format_breakdown(by_tool)}",
    ]
    if failed and error_message:
        err = error_message.strip()
        if len(err) > 200:
            err = err[:200] + "…"
        lines.append(f"**失败原因**: {err}")

    fallback_lines = [
        f"{_at_text_plain(at_ids)}【{title}】",
        f"项目: {project_name or '—'} (ID {project_id or '—'})",
        f"扫描: {scan_name} (#{scan_id})",
        f"漏洞总数: {total}",
        f"按严重性: {_format_breakdown(by_severity, order=_SEVERITY_ORDER)}",
        f"按类型: {_category_breakdown(by_category)}",
        f"按工具: {_format_breakdown(by_tool)}",
    ]
    if failed and error_message:
        fallback_lines.append(f"失败原因: {error_message.strip()[:200]}")
    fallback_lines.append(f"详情: {link}")
    fallback = "\n".join(fallback_lines)

    card = _build_card(title=title, template=template, lines=lines, link=link)
    return _send_feishu_card(card, override_webhook_url=override_webhook_url, fallback_text=fallback)


def send_feishu_finding_notification(
    *,
    scan_id: int,
    finding: Finding,
    extra_text: str = "",
    override_webhook_url: str | None = None,
):
    """
    Best-effort Feishu Incoming Webhook notification.

    Minimal behavior:
    - If webhook URL is not configured, do nothing.
    - Send an interactive card containing finding summary + deep link.
    """
    webhook = (override_webhook_url or getattr(settings, "feishu_webhook_url", "") or "").strip()
    if not webhook:
        logger.info("Feishu notify skipped: webhook URL not configured")
        return
    if not _should_notify(finding.severity, finding.review_status):
        logger.info(
            "Feishu notify skipped: severity %s below threshold %s",
            finding.severity.value,
            getattr(settings, "feishu_notify_min_severity", "HIGH"),
        )
        return

    at_ids = getattr(settings, "feishu_at_user_ids", []) or []
    at = _at_text(at_ids)

    title_text = finding.message_zh or finding.message
    title_text = (title_text or "").strip()
    if len(title_text) > 80:
        title_text = title_text[:80] + "…"

    link = _build_finding_link(scan_id, finding.id)
    status = (finding.review_status or ReviewStatus.UNREVIEWED).value
    sev = finding.severity.value
    tool = finding.tool or ""
    cat = finding.category.value
    status_label = _REVIEW_LABELS.get(status, status)

    header = "安全漏洞发现/更新"
    if extra_text:
        header = f"{header} · {extra_text}"

    loc = f"{to_repo_relative_path(finding.file_path)}:{finding.line_start}"
    lines = [
        f"{at}**严重性**: {sev} | **类别**: {cat} | **工具**: {tool} | **状态**: {status_label}",
        f"**标题**: {title_text}",
        f"**位置**: {loc}",
        "（安全人员请先定性/确认；如需研发复核，请转发该链接给对应研发负责人。）",
    ]

    fallback = (
        f"{_at_text_plain(at_ids)}【{header}】\n"
        f"严重性: {sev} | 类别: {cat} | 工具: {tool} | 状态: {status_label}\n"
        f"标题: {title_text}\n"
        f"位置: {loc}\n"
        f"详情: {link}\n"
        "（安全人员请先定性/确认；如需研发复核，请转发该链接给对应研发负责人。）"
    ).strip()

    template = "orange"
    if status == ReviewStatus.CONFIRMED.value:
        template = "red"
    elif status == ReviewStatus.FALSE_POSITIVE.value:
        template = "green"
    elif status == ReviewStatus.FIXED.value:
        template = "blue"

    card = _build_card(title=header, template=template, lines=lines, link=link, link_label="查看漏洞详情")
    if not _send_feishu_card(card, override_webhook_url=webhook, fallback_text=fallback):
        logger.warning("Feishu finding notify failed for finding %s", finding.id)


def send_feishu_test_message(
    *,
    override_webhook_url: str | None = None,
    override_at_user_ids: list[str] | None = None,
    override_frontend_base_url: str | None = None,
) -> dict:
    """Send a test message to verify webhook configuration."""
    webhook = (override_webhook_url or getattr(settings, "feishu_webhook_url", "") or "").strip()
    if not webhook:
        return {
            "ok": False,
            "message": "未配置飞书 Webhook URL，请填写后保存或先点「发送测试通知」",
        }

    at_ids = override_at_user_ids if override_at_user_ids is not None else (getattr(settings, "feishu_at_user_ids", []) or [])
    at = _at_text(at_ids)
    base = (override_frontend_base_url or getattr(settings, "frontend_base_url", "") or "").strip().rstrip("/")
    if not base:
        base = f"http://{settings.app_host}:{settings.app_port}"
    link = f"{base}/?scanId=1&findingId=1"

    lines = [
        f"{at}这是一条**测试消息**，说明机器人 webhook 配置可用。",
        f"示例详情链接: {link}",
        "（安全人员请先定性/确认；如需研发复核，请转发该链接给对应研发负责人。）",
    ]
    fallback = (
        f"{_at_text_plain(at_ids)}【飞书通知测试】\n"
        "这是一条测试消息，说明机器人 webhook 配置可用。\n"
        f"示例详情链接: {link}\n"
        "（安全人员请先定性/确认；如需研发复核，请转发该链接给对应研发负责人。）"
    ).strip()
    card = _build_card(title="飞书通知测试", template="blue", lines=lines, link=link, link_label="打开示例链接")

    try:
        if _send_feishu_card(card, override_webhook_url=webhook, fallback_text=fallback):
            return {"ok": True, "message": "测试消息已发送，请在飞书群中查看"}
        return {"ok": False, "message": "飞书发送失败，请检查 Webhook URL"}
    except Exception as exc:
        return {"ok": False, "message": f"发送失败: {exc}"}
