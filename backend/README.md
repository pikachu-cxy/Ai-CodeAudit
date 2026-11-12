# backend

FastAPI + SQLAlchemy async 后端，提供扫描编排、漏洞管理、报告、Webhook 与平台配置 API。

## 镜像

构建上下文是 **Monorepo 根目录**（`backend/Dockerfile`），基于官方 `python:3.12-slim-bookworm`：

```bash
docker compose build backend
# 或：docker build -f backend/Dockerfile -t ai-deep-audit-backend:local .
```

镜像内自带（不依赖宿主机）：

| 依赖 | 用途 |
| --- | --- |
| `requirements.txt` | FastAPI、SQLAlchemy、bandit、pip-audit、WeasyPrint 等 |
| Pango/Cairo/Noto CJK 字体 | PDF 报告中文字体与 WeasyPrint 运行时 |
| Git / curl / unzip | 仓库克隆、健康检查、工具安装 |
| Node.js / npm | `npm audit` 扫描器 |
| JDK + Maven | CodeQL Java autobuild |
| semgrep（独立 `--target` 安装） | Semgrep 扫描器，路径 `/opt/scanner-tools/bin/semgrep` |
| gitleaks / osv-scanner / CodeQL CLI | 从公开上游下载到 `/opt/scanner-tools/` |

安装脚本：`scripts/install-scanner-tools.sh`。默认启用的 7 个扫描器（semgrep / codeql / bandit / gitleaks / npm_audit / pip_audit / dep_exploit）均可在容器内解析到所需 CLI。

## 运行

```bash
docker compose up -d backend
docker compose logs -f backend
curl http://127.0.0.1:8080/api/health       # 经前端 nginx 反代
curl http://127.0.0.1:8787/api/health       # 仅容器内可用；默认不映射到宿主机
```

- 数据目录 `DATA_DIR=/data`（命名卷），SQLite 文件 `/data/audit.db`。
- `AI_AUDIT_ENV_FILE=/app/.env`：从 UI 保存的系统设置写入挂载的 `.env`。
- `AUTH_ENABLED=true` 时，`AUTH_PASSWORD` 必须非空且 `AUTH_SECRET_KEY` 至少 32 字符，否则拒绝启动。

## 迁移与测试

`migrations/sqlite/` 与 `migrations/mysql/` 为增量 SQL；应用启动时也会执行 `Base.metadata.create_all`。

```bash
python -m unittest tests.test_platform_management tests.test_finding_dedupe
```

`tests/` 没有 `__init__.py`，不要用 `unittest discover -s tests`（会报目录不可导入），需显式列出模块名。

## 目录

| 路径 | 作用 |
| --- | --- |
| `app/routers/` | API 路由（scans / projects / auth / agents / mcp / accounts / webhooks） |
| `app/services/` | 扫描编排、扫描器插件、LLM 审计、报告、抑制库 |
| `app/models.py` / `app/database.py` | ORM 与建库 |
| `app/templates/` | HTML / PDF 报告模板 |
| `migrations/` | sqlite / mysql 增量迁移 |
| `tests/` | unittest 回归用例 |
| `samples/vulnerable-app/` | 故意有漏洞的演示样例（权属待确认，见 `docs/OWNERSHIP.md`） |
