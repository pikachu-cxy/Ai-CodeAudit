# 架构与能力边界

## 1. 组件与请求链路

```text
浏览器 ── http://127.0.0.1:8080 ──> frontend (nginx:1.27-alpine)
                                      ├── / , /assets/*  → /usr/share/nginx/html (SPA + fallback)
                                      └── /api/*         → proxy_pass http://backend:8787
                                                             │
                                                             ▼
                                                  backend (python:3.12-slim-bookworm)
                                                    ├── FastAPI /api/*
                                                    ├── 扫描器 CLI（镜像内置）
                                                    └── /data  ← 命名卷（SQLite / repos / uploads / cache）
```

- 浏览器只看见一个端口；前端产物使用**同源 `/api`**，不写死后端地址。
- 后端 8787 只在 compose 内网暴露，默认不映射到宿主机。
- 默认 SQLite 位于命名卷；MySQL 为可选 profile。

## 2. 模块独立性

| 模块 | 依赖清单 | 构建 | 可单独运行 |
| --- | --- | --- | --- |
| `frontend/` | `package.json` / `package-lock.json` | `node:20-bookworm-slim` → `nginx:1.27-alpine` | 是（需能解析服务名 `backend`） |
| `backend/` | `requirements.txt` | `python:3.12-slim-bookworm` | 是 |

两者通过 HTTP 契约 `/api/*` 耦合，没有共享源码或运行时文件系统。

## 3. 后端分层

- `app/routers/`：API 路由，统一 `APIRouter(prefix="/api", dependencies=[Depends(require_auth)])`；平台管理端点额外要求管理员。
- `app/services/scanners/`：7 个扫描器插件 + registry；`list_scanners()` 会逐个报告 `available` 与原因。
- `app/services/`：扫描编排、去重与抑制库、LLM 误报研判、端点审计、形态识别、报告构建。
- `app/models.py` / `app/database.py`：ORM 与 `create_all`；`migrations/{sqlite,mysql}/` 为增量迁移。
- `app/templates/`：浏览器报告与 PDF 报告模板。

## 4. 前端分层

- `src/app/`：AppShell、导航注册表、最小 History API 路由、旧 query URL 兼容。
- `src/modules/`：按业务域拆分的页面。
- `src/shared/`：设计系统与表单组件。
- `src/components/`：既有业务组件（扫描详情、发现详情、系统设置等）。
- `src/api.ts`：请求封装、token 与候选基址。

## 5. 镜像内扫描器

| 扫描器 | 镜像内来源 |
| --- | --- |
| semgrep | pip `--target /opt/semgrep-libs` + `/opt/scanner-tools/bin/semgrep` wrapper |
| codeql | **可选**：`INSTALL_CODEQL=1` 时才安装 CodeQL CLI + `default-jdk-headless` + `maven`；默认跳过，扫描器标记不可用 |
| bandit | `requirements.txt` |
| gitleaks | GitHub Release → `/opt/scanner-tools/bin/gitleaks` |
| npm_audit | Debian `nodejs` / `npm` |
| pip_audit | `requirements.txt` |
| dep_exploit | 纯 Python + `/opt/scanner-tools/bin/osv-scanner` |

安装脚本 `backend/scripts/install-scanner-tools.sh` 在构建末尾逐个校验可执行文件，缺失即让构建失败，避免出现「容器起来了但扫描器全不可用」。

## 6. 能力边界（务必如实理解）

| 已具备 | **不**具备 |
| --- | --- |
| Agent 配置定义的增删改查与持久化 | Planner/Worker 调度器、代码事实黑板、Agent 执行链路 |
| 从现有 LLM 设置解析有效模型 | 按 Agent 记录发起模型调用、任务分发 |
| MCP Server 注册与一次真实 `initialize` 握手 | 工具枚举/调用、stdio 进程启动、Agent 绑定 MCP |
| SSRF 防护与凭据类 Header 拒存 | 凭据加密存储、动态 PoC 验证 |
| 单 admin 改密、会话撤销、平台操作留痕 | 多用户/RBAC/按用户数据隔离 |

`GET /api/agents/capabilities` 返回 `runtime_status=configuration_only`、`execution_wired=false`。**配置页不等于已具备多 Agent 代码审计执行能力。**

Skill 管理入口在后端 `/api/skills` 未部署时会显示「后端未部署」，不渲染管理器、不填充示例数据。
