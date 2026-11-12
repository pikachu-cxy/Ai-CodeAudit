import asyncio
import base64
import logging
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from app.config import settings
from app.exceptions import WebhookValidationError

logger = logging.getLogger(__name__)


def split_project_url(project_url: str) -> tuple[str, str]:
    raw = (project_url or "").strip()
    if not raw:
        raise ValueError("请填写完整的 GitLab 项目地址")
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("GitLab 项目地址格式错误，请使用 https://.../group/project.git")
    if parsed.username or parsed.password:
        raise ValueError("GitLab 项目地址不允许包含用户名或密码")
    path = (parsed.path or "").strip("/")
    if not path:
        raise ValueError("GitLab 项目地址缺少项目路径")
    if path.endswith(".git"):
        path = path[:-4]
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base, path


def _build_clone_url(gitlab_url: str, project_id: str, access_token: str | None = None) -> str:
    parsed = urlparse(gitlab_url.rstrip("/"))
    host = parsed.netloc or parsed.path
    scheme = parsed.scheme or "https"
    # IMPORTANT: keep "/" in path. GitLab expects namespace/project, not a fully-escaped string.
    encoded_project = quote(project_id, safe="/")
    return f"{scheme}://{host}/{encoded_project}.git"


def _git_auth_env(access_token: str) -> dict[str, str]:
    token = (access_token or "").strip()
    if "://" in token or token.lower().startswith("http"):
        raise ValueError("Access Token 格式错误：请填写 GitLab 令牌，不要粘贴仓库 URL")
    encoded = base64.b64encode(f"oauth2:{token}".encode()).decode("ascii")
    env = os.environ.copy()
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "http.extraHeader"
    env["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {encoded}"
    return env


async def verify_gitlab_project(gitlab_url: str, project_id: str, access_token: str) -> dict:
    base = gitlab_url.rstrip("/")
    encoded = quote(project_id, safe="")
    url = f"{base}/api/v4/projects/{encoded}"

    async with httpx.AsyncClient(timeout=30, verify=bool(settings.gitlab_tls_verify)) as client:
        try:
            resp = await client.get(url, headers={"PRIVATE-TOKEN": access_token})
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise RuntimeError("GitLab 认证失败，请检查 Access Token 是否有效并包含 read_repository 权限") from exc
            if exc.response.status_code == 404:
                raise RuntimeError("未找到 GitLab 项目，请检查项目地址是否正确") from exc
            raise RuntimeError(f"GitLab API 请求失败（HTTP {exc.response.status_code}）") from exc
        except httpx.ConnectError as exc:
            msg = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in msg or "SSL" in msg or "tls" in msg.lower():
                raise RuntimeError(
                    "无法连接到 GitLab：TLS/证书校验失败（常见于内网自签证书）。"
                    "可在 backend/.env 设置 GITLAB_TLS_VERIFY=false 后重启后端再试。"
                ) from exc
            raise RuntimeError("无法连接到 GitLab，请检查项目地址或网络连通性") from exc
        except httpx.TimeoutException as exc:
            raise RuntimeError("连接 GitLab 超时，请稍后重试") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"GitLab 请求失败: {exc}") from exc

        data = resp.json()
        return {
            "id": data.get("id"),
            "name": data.get("name"),
            "path_with_namespace": data.get("path_with_namespace"),
            "default_branch": data.get("default_branch", "main"),
            "web_url": data.get("web_url"),
        }


async def probe_gitlab_repo(
    gitlab_url: str,
    project_id: str,
    branch: str,
    access_token: str,
) -> None:
    """
    Lightweight GitLab availability probe for webhook:
    - validates repository + access token + branch existence
    - must be executed before creating DB rows

    Probe rule:
    - if git returns non-zero: map to token_permission_insufficient / gitlab_address_invalid
    - if git returns zero with empty stdout: map to branch_not_found
    """

    if not (access_token or "").strip():
        raise WebhookValidationError("token_permission_insufficient", "GitLab Access Token 未配置或为空")

    clone_url = _build_clone_url(gitlab_url, project_id)
    env = _git_auth_env(access_token)
    cmd = ["git"]
    if not settings.gitlab_tls_verify:
        cmd.extend(["-c", "http.sslVerify=false"])
    cmd.extend(["ls-remote", "--heads", clone_url, branch])

    def _probe() -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)

    import asyncio

    proc = await asyncio.to_thread(_probe)
    if proc.returncode != 0:
        stderr = (proc.stderr or proc.stdout or "").strip()
        low = stderr.lower()

        # Heuristics: redirect to login / forbidden / auth failure → token insufficient.
        if "users/sign_in" in low or "sign in" in low or "forbidden" in low or "authentication" in low or "permission denied" in low:
            raise WebhookValidationError(
                "token_permission_insufficient",
                "GitLab 仓库不可访问：Access Token 权限不足或被重定向登录页",
            )

        raise WebhookValidationError("gitlab_address_invalid", f"GitLab 仓库不可访问：{stderr[:2000]}")

    out = (proc.stdout or "").strip()
    if not out:
        raise WebhookValidationError("branch_not_found", f"远程分支不存在：{branch}")


async def clone_gitlab_repo(
    gitlab_url: str,
    project_id: str,
    branch: str,
    access_token: str,
    dest_dir: Path,
) -> Path:
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    dest_dir.mkdir(parents=True, exist_ok=True)

    clone_url = _build_clone_url(gitlab_url, project_id)
    env = _git_auth_env(access_token)
    cmd = ["git"]
    if not settings.gitlab_tls_verify:
        cmd.extend(["-c", "http.sslVerify=false"])
    cmd.extend(["clone", "--depth", "1", "--branch", branch, clone_url, str(dest_dir)])

    def _clone() -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)

    proc = await asyncio.to_thread(_clone)
    if proc.returncode != 0:
        stderr = (proc.stderr or proc.stdout or "").strip()
        if "users/sign_in" in stderr or "sign in" in stderr.lower():
            raise RuntimeError(
                "Git clone 失败：GitLab 将请求重定向到了登录页，通常是 Access Token 无权限/无效，"
                "或项目路径解析错误。请确认 Token 有 read_repository 权限且项目地址正确。"
            )
        raise RuntimeError(f"Git clone failed: {stderr[:2000]}")

    return dest_dir
