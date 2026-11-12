# PROJECT_CONTEXT — 真实完成的工作与验收记录

> 只记录本仓库中**已实现并实际验证**的内容。不把「配置页面」写成「已具备执行能力」。

## 1. 本阶段目标与边界

从两个已脱敏的独立仓库（backend / frontend）整理为一个新的 Monorepo 发布快照，
提供 Docker Compose 一键部署，并完成开源前验证。
**本阶段不改业务逻辑、不新增后端 API、不改数据库结构、不实现多 Agent 调度或 PoC 执行；**
只对容器化必需的 3 处做了最小适配（前端同源 `/api`、CodeQL 不可用文案、`pydyf` 版本锁定）。
原前后端仓库及其 Git 历史保持不变；本快照采用全新 Git 历史。

## 2. 目录结构（实际）

```text
ai-deep-audit/
├── frontend/                 React+TS+Vite SPA，多阶段构建到官方 nginx
│   ├── Dockerfile
│   ├── src/                  77 个源文件（含 api.ts 生产同源 /api 适配）
│   └── package-lock.json
├── backend/                  FastAPI + SQLAlchemy async
│   ├── Dockerfile            官方 python:3.12-slim-bookworm
│   ├── app/                  路由 / 服务 / 模板 / Java CVE 知识库
│   ├── migrations/           sqlite + mysql 各 9 个增量迁移
│   ├── samples/              故意有漏洞的最小演示样例
│   └── scripts/install-scanner-tools.sh
├── deploy/nginx/default.conf 官方 nginx 标准路径 + /api 反代 + SPA fallback
├── scripts/                  bootstrap / start / stop（bash + PowerShell 各一套）
├── docs/                     DEPLOYMENT / ARCHITECTURE / SECURITY_REVIEW /
│                             OWNERSHIP / TOKEN_ROTATION / PROJECT_CONTEXT
├── docker-compose.yml        默认 SQLite + 仅本机端口；可选 MySQL profile
├── .env.example / .gitignore / .dockerignore / README.md
```

## 3. 实际改动清单

| 文件 | 改动 |
| --- | --- |
| `backend/Dockerfile` | 官方 `python:3.12-slim-bookworm`；系统依赖 + 内置 6 个扫描器 CLI；CodeQL/JDK/Maven 由 `INSTALL_CODEQL` 按需开启；`DATA_DIR=/data` |
| `frontend/Dockerfile` | 官方 `node:20-bookworm-slim` → `nginx:1.27-alpine` 多阶段构建 |
| `deploy/nginx/default.conf` | 官方镜像标准路径 `/etc/nginx/conf.d/`；`/api/` 反代到 `backend:8787`；SPA fallback |
| `frontend/src/api.ts` | 生产构建固定同源 `/api`，仅 Vite dev 保留直连回退 |
| `backend/app/services/scanners/codeql.py` | 不可用原因改为说明「官方镜像默认不安装 CodeQL，可用 `INSTALL_CODEQL=1` 开启」 |
| `backend/requirements.txt` | 锁定 `pydyf==0.10.0`：`weasyprint 62.3` 未限制上限，新版会让 PDF 导出失败 |
| `docker-compose.yml` | 默认 SQLite + 命名卷 + `.env` 单文件挂载；端口绑定 `127.0.0.1:${HTTP_PORT}`；可选 `--profile mysql` |
| `.env.example` / `.gitignore` / `.dockerignore` | 公开占位、忽略真实凭据与运行时产物、构建上下文最小化 |
| `scripts/*` | bootstrap 生成随机口令（不打印）、start/stop 一键编排（Windows + Linux） |
| `backend/scripts/install-scanner-tools.sh` | 从公开上游安装 gitleaks / osv-scanner / semgrep 并逐个校验；CodeQL 仅在 `INSTALL_CODEQL=1` 时下载 |
| `docs/*` | 部署、架构、安全审查、权属、凭据轮换、项目上下文 |

补齐了导出时遗漏的 `backend/app/data/dep_exploit_kb/java_high_risk.yaml`，
否则 `dep_exploit` 扫描器在容器内会静默退化为无知识库状态。

## 4. 一键启停命令

```bash
bash scripts/start.sh        # Linux / macOS / Git Bash
bash scripts/stop.sh         # 停止但保留数据卷
```
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

默认地址 `http://127.0.0.1:8080`。**验收阶段本机临时使用 `HTTP_PORT=18080`**
（当时 8080/8787 被其他运行中的服务占用），验收通过后已把本地 `.env` 改回 8080
并在该端口复跑浏览器验收 15/15。`.env.example` 的默认值一直是 8080。

## 5. 实际验收结果

| 项目 | 结果 |
| --- | --- |
| `docker compose build` | 前端 PASS / 后端 PASS |
| `docker compose config` / `--profile mysql config` | PASS |
| shell 脚本 `bash -n`、nginx `-t`、Dockerfile COPY 源 | PASS |
| `docker compose up -d` + `/api/health` | PASS |
| 单端口 / SPA fallback / 静态资源 | PASS |
| 扫描器可用 | 6/7（缺 CodeQL，默认不安装） |
| 登录、项目、任务、扫描、发现、报告、Agent/MCP/账户 | API 36/36 PASS |
| 浏览器路由、深链接、前进后退、截图 | 15/15 PASS |
| `compose down` → `up -d` 数据持久化 | 5/5 PASS |
| 快照敏感信息 / Git 历史 / 镜像审查 | 见 `docs/SECURITY_REVIEW.md` |

### 实测标识
- 测试端口：`18080`；创建的项目 `2`、扫描 `2`、发现 `4` 条。
- 浏览器截图目录：`ai-audit-tmp/ui-shots/monorepo_*.png`（位于快照之外，不随仓库发布）。
- Agent 能力边界实测：`runtime_status=configuration_only`、`execution_wired=false`。

## 6. 能力边界（如实）

- Agent / MCP / Skill 页面只提供配置管理与真实握手测试；**没有** Planner/Worker、代码事实黑板、工具调用或动态 PoC 执行。
- Skill 页面在 `/api/skills` 未部署时明确提示「后端未部署」，不伪造数据。
- 默认关闭 LLM（`LLM_ENABLED=false`）；配置 `LLM_API_KEY` 后才启用 AI 审计。
- MySQL 为可选 profile，需自行填写 `MYSQL_*` 并使用 `--profile mysql`。

## 7. 已知限制与待办

1. 首次构建需下载中文字体等系统包并安装 3 个扫描器 CLI（实测约 20 分钟，与带宽强相关）；
   镜像合计 backend 1.71GB / frontend 74.9MB。
2. CodeQL 默认不安装：需要 Java 深度分析时以 `INSTALL_CODEQL=1` 重新构建，会额外下载约 400 MB CLI 并安装 JDK/Maven。
3. `frontend/src/api.ts` 的本地开发回退仍写死 `127.0.0.1:8787`，只在 Vite dev（端口 5173）生效。
4. `.env` 以单文件 bind mount 提供，Windows Docker Desktop 需确保驱动器已共享。
5. **未添加 LICENSE / NOTICE**；代码权属、第三方工具再分发许可、历史凭据轮换均待人工确认。
6. 本轮按用户明确指示，把快照推送到公开仓库 `pikachu-cxy/Ai-CodeAudit`（单提交、全新历史）；
   **未创建 Release、未修改其他仓库可见性、未重写原仓库历史、未删除任何原有数据**。
7. 仍未添加 `LICENSE`：补许可证并确认代码权属前，默认适用著作权保留，不对第三方授权。
