# AI Deep Audit

本地可运行的 AI 代码安全审计平台：SAST 扫描器编排、LLM 误报研判与端点审计、项目/任务/漏洞管理、HTML/PDF/Markdown 报告，以及 Agent / MCP / Skill 的**配置管理**界面。

前后端统一在本仓库，但保持模块独立；一条命令即可用 Docker Compose 构建并启动。

> **许可证状态：待确认。** 代码权属与第三方依赖许可证审查尚未完成，本仓库当前**未提供任何开源许可证授权**，请勿视为可自由使用、修改或再分发。在完成审查并取得必要授权前，不要把本仓库发布到公共平台。详见 `docs/OWNERSHIP.md`。

---

## 1. 前置要求

| 平台 | 要求 |
| --- | --- |
| Windows | Docker Desktop 4.x+（启用 WSL 2 后端），PowerShell 5.1+ 或 Git Bash |
| Linux | Docker Engine 24+ 与 Docker Compose v2 插件，`bash`、`curl`、`openssl` |
| 通用 | 至少 4 GB 可用内存、约 10 GB 磁盘（镜像内含扫描器 CLI 与 JDK） |

不需要在宿主机安装 Python、Node.js、数据库或任何扫描器：**依赖与扫描器全部在镜像构建时安装**。

---

## 2. 快速开始

### Linux / macOS / Git Bash

```bash
git clone <your-private-fork-url> ai-deep-audit
cd ai-deep-audit
bash scripts/start.sh
```

### Windows（Docker Desktop）

```powershell
cd ai-deep-audit
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

`start` 脚本会依次：

1. 从 `.env.example` 生成 `.env`（已被 `.gitignore` 忽略），并用密码学随机数生成 `AUTH_PASSWORD` 与 `AUTH_SECRET_KEY`；**不在终端打印凭据**。
2. 执行 `docker compose up -d --build` 构建前后端镜像并启动。
3. 轮询 `http://127.0.0.1:8080/api/health`，返回 200 后打印容器状态。

首次构建需要下载基础镜像、Python/Node 依赖与扫描器 CLI，通常需要数分钟。

### 访问

| 地址 | 用途 |
| --- | --- |
| `http://127.0.0.1:8080` | 前端工作台（唯一对外端口） |
| `http://127.0.0.1:8080/api/health` | 后端健康检查（经 nginx 反代） |

**首次登录**：用户名来自 `.env` 的 `AUTH_USERNAME`（默认 `admin`），密码为同一文件中 `AUTH_PASSWORD` 的自动生成值。请用文本编辑器打开 `.env` 查看，登录后可在「账户管理」中修改。

> 服务默认**只绑定 `127.0.0.1`**，不会暴露到局域网。如需改端口，修改 `.env` 的 `HTTP_PORT` 后重新执行 `start` 脚本。

---

## 3. 停止与日常操作

```bash
bash scripts/stop.sh          # 停止容器，保留数据卷
bash scripts/start.sh         # 再次启动（数据仍在）
docker compose logs -f backend
docker compose ps
```

Windows 对应 `scripts\stop.ps1` / `scripts\start.ps1`。

数据位于命名卷 `ai-deep-audit_backend-data`（SQLite 数据库、克隆的仓库、上传包、扫描缓存），以及仓库根目录的 `.env`（从 UI 保存的系统设置）。报告为按需即时生成，不作为文件持久化。**不要删除卷，否则项目与扫描历史会丢失。**

---

## 4. 内置能力

| 类别 | 内容 |
| --- | --- |
| SAST / SCA | Semgrep、Bandit、Gitleaks、npm audit、pip-audit、Java 依赖可利用性分析（osv-scanner）；CodeQL（Java 深度分析）默认**不安装**，需 `INSTALL_CODEQL=1` 构建 |
| AI 审计 | LLM 误报研判、端点深度审计、形态识别与专属审计视角（需在 `.env` 配置 `LLM_API_KEY` 并启用） |
| 业务 | 项目、扫描任务、漏洞复核、加白名单、HTML/PDF/Markdown 报告、Webhook 触发 |
| 平台配置 | Agent 定义、MCP Server 注册与握手测试、Skill 管理入口、账户与会话管理 |

所有扫描器 CLI 在**镜像构建时**从公开上游安装（见 `backend/scripts/install-scanner-tools.sh`），不依赖宿主机已安装组件，也不挂载宿主机工具目录。可在「系统管理 → 扫描器管理」查看每个扫描器的可用状态。

> **能力边界**：Agent / MCP 页面提供的是**配置管理与真实握手测试**，不包含多 Agent 调度器、代码事实黑板或动态 PoC 执行；保存一条 Agent 记录不会触发审计任务。Skill 页面在后端接口未部署时会明确显示「后端未部署」，不会伪造数据。

---

## 5. 可选配置

全部在 `.env` 中设置，改完执行 `scripts/start.sh`（或 `docker compose up -d`）：

| 变量 | 说明 |
| --- | --- |
| `LLM_API_KEY` / `LLM_API_BASE` / `LLM_MODEL` | 启用 AI 审计；留空则关闭 LLM 功能，SAST 仍可用 |
| `LLM_ENABLED` / `LLM_CODE_AUDIT_ENABLED` | 扫描后自动误报研判 / 端点深度审计 |
| `GITLAB_ACCESS_TOKEN` / `WEBHOOK_TOKEN` | Webhook 触发的仓库克隆与鉴权 |
| `FEISHU_WEBHOOK_URL` / `SMTP_*` | 通知 |
| `SSO_ENABLED` / `SSO_*` | 单点登录（可选） |
| `DATABASE_BACKEND=mysql` | 切换 MySQL：另需 `docker compose --profile mysql up -d --build` 并填写 `MYSQL_*` |

完整变量清单见 `.env.example`，全部为占位符，不含真实凭据。

---

## 6. 目录结构

```text
ai-deep-audit/
├── frontend/          # React + TS + Vite SPA；Dockerfile 多阶段构建 → 官方 nginx
├── backend/           # FastAPI + SQLAlchemy；Dockerfile 官方 Python + 内置扫描器
├── deploy/nginx/      # 统一端口的反向代理配置（官方 nginx 标准路径）
├── scripts/           # bootstrap / start / stop（bash + PowerShell）
├── docs/              # 部署、架构、安全审查、权属、项目上下文
├── docker-compose.yml # 一键编排（默认 SQLite + 仅本机端口）
├── .env.example       # 公开环境变量模板
├── .gitignore / .dockerignore
└── README.md
```

---

## 7. 安全须知

- `.env` 含自动生成的口令与可选 API Key，**已被忽略，切勿提交或随镜像分发**。
- 默认只监听 `127.0.0.1`。如需对外开放，请自行配置 TLS、反向代理与访问控制。
- 平台扫描的是你**自己提供**的源码；对第三方系统发起扫描前请确认已获授权。
- 不要把内部审计报告、真实业务数据或扫描结果提交到公共仓库。

---

## 8. 文档

| 文档 | 内容 |
| --- | --- |
| `docs/DEPLOYMENT.md` | Windows / Linux 详细部署、备份与故障排查 |
| `docs/ARCHITECTURE.md` | 模块边界、端口与数据流、能力边界 |
| `docs/SECURITY_REVIEW.md` | 发布快照敏感信息、Git 历史与镜像审查结果 |
| `docs/OWNERSHIP.md` | 代码权属、第三方依赖许可证与发布阻断项 |
| `docs/TOKEN_ROTATION.md` | 需人工轮换的历史凭据清单（脱敏） |
| `docs/PROJECT_CONTEXT.md` | 真实完成的工作与验收记录 |

首次构建会在镜像内安装 Node/npm、中文字体、Pango/Cairo 以及 6 个扫描器 CLI，
**首次构建耗时与网络带宽强相关**；后续构建会命中 Docker 层缓存。
默认镜像合计约 1.5–2 GB。

**CodeQL 默认不下载。** 它只用于 Java 深度分析，CLI 约 400 MB，还需要 JDK/Maven。
需要时在 `.env` 里设 `INSTALL_CODEQL=1` 后重新构建：

```bash
INSTALL_CODEQL=1 docker compose build backend
docker compose up -d
```

未安装时「扫描器」页会如实显示 CodeQL 不可用，其余扫描器不受影响。
