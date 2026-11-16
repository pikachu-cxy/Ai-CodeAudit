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

## 6. Deep Audit V1 与平台能力

扫描任务结束后，Agent 配置页和任务详情页可启动 Deep Audit V1。调度器从原有扫描结果、接口发现和同版本黑板准备输入。Planner 只处理结构化数据，单个 Worker 顺序调用只读源码工具。SQLAlchemy 将运行、任务、事实和证据持久化到现有数据库。带证据的候选进入现有 Finding，由人工复核。原端点审计、数据流研判和扫描上下文对话各自保留入口。

AgentDefinition 可绑定 Worker 的模型、附加指示与预算。MCP Server 管理仍提供配置与一次初始化握手，Skill 页面依赖已部署的管理 API。V1 的工具白名单只包含本地只读代码工具。接口、迁移、验收和限制见 [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md)。
