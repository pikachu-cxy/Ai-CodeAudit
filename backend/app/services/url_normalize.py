"""GitLab project URL normalization (single source of truth)."""

from __future__ import annotations

from urllib.parse import urlparse

from app.services.gitlab_service import split_project_url


def normalize_gitlab_url(project_url: str) -> str:
    """
    Canonical key for matching GitLab repos across .git / trailing slash / case variants.
    Raises ValueError when the URL is not a usable GitLab HTTP(S) project URL.
    """
    base, path = split_project_url(project_url)
    parsed = urlparse(base)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.netloc or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("GitLab 项目地址仅允许 http 或 https")
    if not host:
        raise ValueError("GitLab 项目地址格式错误")
    clean_path = path.strip("/").lower()
    return f"{scheme}://{host}/{clean_path}"


def try_normalize_gitlab_url(project_url: str | None) -> str | None:
    if not project_url or not str(project_url).strip():
        return None
    try:
        return normalize_gitlab_url(project_url)
    except ValueError:
        return None
