from __future__ import annotations

import asyncio
import logging
import smtplib
import socket
import ssl
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger(__name__)

SMTP_CONNECT_TIMEOUT = 15
SMTP_TOTAL_TIMEOUT = 30


def _smtp_enabled() -> bool:
    return bool((settings.smtp_host or "").strip() and (settings.email_from or "").strip())


def smtp_configured() -> bool:
    return _smtp_enabled()


def _build_message(*, to_email: str, subject: str, html_body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.email_from.strip()
    msg["To"] = to_email.strip()
    msg.set_content("请使用支持 HTML 的邮件客户端查看审计报告。")
    msg.add_alternative(html_body, subtype="html")
    return msg


def _qq_mail_hint(host: str) -> str:
    if "qq.com" not in host.lower():
        return ""
    return (
        " QQ 邮箱须：① 在邮箱设置→账户 开启 SMTP 并生成16位授权码；"
        "② 密码填授权码（不是 QQ 登录密码）；"
        "③ 用户名/发件地址均为完整 QQ 邮箱；"
        "④ 若 465 失败可改端口 587 并勾选 TLS。"
    )


def _is_disconnect_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return isinstance(exc, smtplib.SMTPServerDisconnected) or "unexpectedly closed" in text


def _login_and_send(server: smtplib.SMTP, user: str, password: str, msg: EmailMessage) -> None:
    if user:
        server.login(user, password)
    server.send_message(msg)


def _send_via_ssl(host: str, port: int, user: str, password: str, msg: EmailMessage, ctx: ssl.SSLContext) -> None:
    with smtplib.SMTP_SSL(host, port, timeout=SMTP_CONNECT_TIMEOUT, context=ctx) as server:
        server.ehlo()
        _login_and_send(server, user, password, msg)


def _send_via_starttls(host: str, port: int, user: str, password: str, msg: EmailMessage, ctx: ssl.SSLContext) -> None:
    with smtplib.SMTP(host, port, timeout=SMTP_CONNECT_TIMEOUT) as server:
        server.ehlo()
        server.starttls(context=ctx)
        server.ehlo()
        _login_and_send(server, user, password, msg)


def _send_sync(msg: EmailMessage) -> None:
    host = settings.smtp_host.strip()
    port = int(settings.smtp_port or 465)
    user = (settings.smtp_user or "").strip()
    password = (settings.smtp_password or "").strip()
    use_tls = bool(settings.smtp_tls)
    ctx = ssl.create_default_context()
    qq_hint = _qq_mail_hint(host)

    logger.info("SMTP connect %s:%s tls=%s auth=%s", host, port, use_tls, bool(user))

    try:
        if port == 465:
            try:
                _send_via_ssl(host, port, user, password, msg, ctx)
                return
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as exc:
                if _is_disconnect_error(exc):
                    logger.warning("SMTP SSL :465 failed (%s), retry STARTTLS :587", exc)
                    _send_via_starttls(host, 587, user, password, msg, ctx)
                    return
                raise

        if port == 587 or use_tls:
            _send_via_starttls(host, port, user, password, msg, ctx)
            return

        with smtplib.SMTP(host, port, timeout=SMTP_CONNECT_TIMEOUT) as server:
            server.ehlo()
            _login_and_send(server, user, password, msg)
    except socket.timeout as exc:
        raise TimeoutError(
            f"连接 SMTP 超时（{SMTP_CONNECT_TIMEOUT}s）。请检查主机/端口/防火墙："
            f"465 通常用 SSL，587 通常用 STARTTLS（勾选 TLS）。{qq_hint}"
        ) from exc
    except smtplib.SMTPAuthenticationError as exc:
        code = getattr(exc, "smtp_code", None)
        hint = qq_hint
        if code == 526 or "526" in str(exc):
            hint = (
                "（常见于阿里/网易等企业邮：用户名填完整邮箱；"
                "密码用邮箱登录密码或客户端授权码；发件地址 From 须与登录邮箱一致；"
                "确认已在邮箱后台开启 SMTP）"
            )
        raise RuntimeError(f"SMTP 认证失败{hint}：{exc}") from exc
    except smtplib.SMTPServerDisconnected as exc:
        raise ConnectionError(
            f"SMTP 连接被服务器关闭：{exc}。"
            f"请检查端口/TLS 是否正确（QQ/163 建议先试 587 + TLS）。{qq_hint}"
        ) from exc
    except OSError as exc:
        if _is_disconnect_error(exc):
            raise ConnectionError(
                f"无法连接 SMTP {host}:{port}：{exc}。"
                f"可尝试端口 587 并勾选 TLS。{qq_hint}"
            ) from exc
        raise ConnectionError(f"无法连接 SMTP {host}:{port}：{exc}{qq_hint}") from exc
    except smtplib.SMTPException as exc:
        raise RuntimeError(f"SMTP 发送失败：{exc}{qq_hint}") from exc


async def send_html_email(*, to_email: str, subject: str, html_body: str) -> None:
    msg = _build_message(to_email=to_email, subject=subject, html_body=html_body)
    try:
        await asyncio.wait_for(asyncio.to_thread(_send_sync, msg), timeout=SMTP_TOTAL_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(
            f"邮件发送超时（{SMTP_TOTAL_TIMEOUT}s）。请检查 SMTP 地址、端口与 TLS 设置是否正确。"
        ) from exc
