"""Domain-specific API errors."""

from __future__ import annotations

from app.models import Project


class DuplicateGitUrlError(ValueError):
    """Raised when manual scan creation targets a Git URL that already has a project."""

    def __init__(self, project: Project) -> None:
        self.project = project
        super().__init__(f"duplicate_git_url:{project.id}:{project.name}")


class DuplicateProjectNameError(ValueError):
    """Raised when creating or renaming a project to a name that already exists."""

    def __init__(self, project: Project) -> None:
        self.project = project
        super().__init__(f"duplicate_project_name:{project.id}:{project.name}")


def duplicate_project_http_detail(exc: DuplicateGitUrlError | DuplicateProjectNameError) -> dict:
    project = exc.project
    if isinstance(exc, DuplicateProjectNameError):
        return {
            "code": "duplicate_project_name",
            "message": f"项目名「{project.name}」已存在，请更换名称或追加到该项目。",
            "project": {"id": project.id, "name": project.name, "source_url": project.source_url},
        }
    return {
        "code": "duplicate_git_url",
        "message": f"该 Git 地址已存在于项目「{project.name}」，请改用「追加扫描版本」或更换地址。",
        "project": {"id": project.id, "name": project.name, "source_url": project.source_url},
    }


WEBHOOK_VALIDATION_ERROR_HTTP = {
    # 4. 参数缺失
    "missing_parameter": 400,
    # 1. Token 权限不足（含 WEBHOOK_TOKEN/GITLAB_ACCESS_TOKEN 未配置/无权限）
    "token_permission_insufficient": 403,
    # 2. Git 地址不对（URL/权限/路径错：仅允许 settings 配置的 GitLab 实例）
    "gitlab_address_invalid": 404,
    # 3. 分支不存在
    "branch_not_found": 405,
}


class WebhookValidationError(Exception):
    """Structured webhook validation/probe failure (used by Jenkins)."""

    code: str
    http_status: int
    message: str

    def __init__(self, code: str, message: str) -> None:
        if code not in WEBHOOK_VALIDATION_ERROR_HTTP:
            raise ValueError(f"Unknown webhook error code: {code}")
        self.code = code
        self.http_status = WEBHOOK_VALIDATION_ERROR_HTTP[code]
        self.message = message
        super().__init__(message)


def webhook_validation_error_detail(exc: WebhookValidationError) -> dict:
    return {"code": exc.code, "message": exc.message, "http_status": exc.http_status}
