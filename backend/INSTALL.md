# 安装与启动（双仓）

后端：https://git.example.com/your-org/ai-audit-backend  
前端：https://git.example.com/your-org/ai-audit-frontend

> 生产形态：**nginx 前端容器（8080）** + **FastAPI API 容器（8787，内网）**。改前端只重建 frontend；改后端只重建 backend。

## 1. 获取代码

```bash
git clone https://git.example.com/your-org/ai-audit-backend.git
git clone https://git.example.com/your-org/ai-audit-frontend.git
# 两个目录需为同级（compose 使用 ../ai-audit-frontend）
```

## 2. 环境要求

| 依赖 | 版本 | 说明 |
|------|------|------|
| Docker / Compose | 较新 | 推荐部署方式 |
| Python | 3.11+ | 本机直跑 API 时需要 |
| Node.js | 18+ | 本机前端开发时需要 |

### 2.1 扫描器：宿主机安装 + 挂载（推荐）

**镜像内不打包** semgrep / CodeQL / gitleaks / osv-scanner。在**宿主机**准备 Linux amd64 文件，挂载到容器 `/host-tools`。

完整说明（含正确/错误对照）：[.host-tools/README.md](./.host-tools/README.md)

**目标树（`codeql/codeql` 必须是可执行文件，不能再套一层）：**

```text
tools/                         # 如 .host-tools 或 /data/ai-audit/tools
├── bin/gitleaks
├── bin/osv-scanner
├── bin/semgrep                # 可选包装脚本
├── codeql/codeql              # ← 文件；错误示例是 codeql/codeql/codeql
└── semgrep-bin/semgrep        # PATH 入口（pip 常装在 semgrep-bin/bin/，需软链上来）
```

**CodeQL 解压注意（最易错）：**

```bash
# 正确：解压到 tools 根目录（zip 自带顶层 codeql/）
unzip -d /data/ai-audit/tools codeql-linux64.zip
# 得到：/data/ai-audit/tools/codeql/codeql

# 错误：先 mkdir codeql 再解进去 → 多嵌套一层
# mkdir codeql && unzip -d codeql ...  →  tools/codeql/codeql/codeql
```

生产机无仓库时：

```bash
export HOST_TOOLS_DIR=/data/ai-audit/tools
# 把 scripts/fetch-host-tools.sh 拷到机器后：
bash fetch-host-tools.sh
```

或本仓内：

```bash
bash scripts/fetch-host-tools.sh
```

**镜像内仍自带**：bandit、pip-audit、nodejs/npm。

验收：

```bash
# 宿主机：确认是文件不是目录
ls -la /data/ai-audit/tools/codeql/codeql
file /data/ai-audit/tools/codeql/codeql

# 容器
docker exec ai-audit-backend sh -c 'which gitleaks osv-scanner codeql semgrep; codeql version'
curl -fsS http://127.0.0.1:8787/api/scanners/status   # 若镜像含此接口
```

缺工具时对应扫描器会跳过，整次扫描不会失败。

## 3. Docker Compose 联调（推荐）

在 **backend** 目录：

```bash
cd ai-audit-backend
cp .env.example .env
# 准备 .host-tools 或设置 HOST_TOOLS_DIR
# FRONTEND_BASE_URL=http://localhost:8080
# WEBHOOK_TOKEN=...
# GITLAB_ACCESS_TOKEN=...
docker compose up -d --build
```

如果你希望“系统设置”页面里保存的配置在重建/重启后仍然保留，必须把宿主机 `.env`
挂载到容器 `/app/.env`。后端会从这个文件读取配置，并在 UI 保存设置时写回它。

当前仓库里的 `docker-compose.yml` 已包含：

```yaml
environment:
  AI_AUDIT_ENV_FILE: /app/.env
volumes:
  - ./.env:/app/.env
```

生产机建议使用固定路径，例如：

```bash
/data/ai-audit-backend/.env
```

验收：

- http://localhost:8080 — UI
- http://localhost:8080/api/health — `{"status":"ok",...}`
- http://localhost:8080/api/scanners/status — 各扫描器 `available`
- 启用认证时必须显式配置 `AUTH_USERNAME`、`AUTH_PASSWORD` 和至少 32 字符的 `AUTH_SECRET_KEY`；未配置时后端拒绝启动。

数据卷：`ai_audit_data` → `/data`；`ai_audit_tools` → `/app/.tools`（CodeQL 缓存等）。

### 3.1 数据库（本地 / 生产分库）

| 环境 | 推荐 | 库名示例 |
|------|------|----------|
| 本地 | SQLite（默认）或 Compose MySQL | `ai_audit_dev` |
| 生产 K8s | MySQL + PVC（`/data` 仍存 repos/uploads） | `ai_audit_prod` |

- 系统设置 → **数据存储**：配置 MySQL、测试连接；**改库需重启 backend**。
- Schema 变更在仓库 [`migrations/README.md`](./migrations/README.md)；发版前先 `python -m app.migrate`。
- 本地联调 MySQL：`docker compose --profile mysql up -d mysql`，`.env` 设 `DATABASE_BACKEND=mysql` 等（见 `.env.example`）。

### 仅重建一侧

```bash
docker compose build frontend && docker compose up -d frontend
docker compose build backend && docker compose up -d backend
```

## 4. 本机分别启动（不用 Docker 扫描挂载）

**后端：**

```bash
cd ai-audit-backend
python -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
pip install semgrep          # 可选
cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 8787
```

本机 PATH 上需有 gitleaks / osv-scanner / codeql 等（Windows 可用 WinGet / 官方安装包）。

**前端开发：**

```bash
cd ai-audit-frontend
npm ci
npm run dev
# http://localhost:5173 ，/api → 127.0.0.1:8787
```

### 4.1 PDF 报告导出

PDF 由 `PDF_ENGINE` 决定用哪个渲染器，默认 `auto`：**优先 WeasyPrint，不可用时自动回退到无头浏览器**。

| 引擎 | 依赖 | 说明 |
|---|---|---|
| WeasyPrint | GTK/Pango 运行库 + 中文字体 | 体积小；Linux/Docker 上推荐 |
| 无头浏览器 | Chrome / Chromium / Edge | 体积大；渲染更接近浏览器，中文由系统字体保证 |

**Linux（含 Docker）装 WeasyPrint：**

```bash
apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info fonts-noto-cjk
pip install weasyprint
```

**Linux（含 Docker）走无头 Chromium：**

```bash
apt-get install -y chromium fonts-noto-cjk
```

容器里以 root 运行，代码已自动带上 `--no-sandbox` 与 `--disable-dev-shm-usage`，无需额外配置。
装好后 `/usr/bin/chromium` 会被自动探测到，`PDF_ENGINE=auto` 即可。

**Linux 上两个高频坑：**

1. **不要用 Ubuntu 的 `chromium-browser`** —— 它是 snap 包装脚本，容器里根本跑不起来。
   要用 Debian 源的 `chromium`（装到 `/usr/bin/chromium`）。
2. **必须装中文字体**（`fonts-noto-cjk`），否则 PDF 里中文全是方块。
   注意 `--disable-dev-shm-usage` 也是必需的：Docker 默认 `/dev/shm` 只有 64MB，
   缺了它 Chromium 会崩溃或静默挂住（代码已内置该参数）。

**Windows 本地**：WeasyPrint 需要 Pango，官方现在推荐用 MSYS2 安装
（`pacman -S mingw-w64-ucrt-x86_64-pango`，再设 `WEASYPRINT_DLL_DIRECTORIES=C:\msys64\ucrt64\bin`）。
不想装 MSYS2 也可以——**只要本机有 Chrome/Edge，`auto` 会自动走无头浏览器**，无需任何额外安装。

**强制指定引擎 / 浏览器路径：**

```bash
PDF_ENGINE=chrome              # 只用无头浏览器
PDF_ENGINE=weasyprint          # 只用 WeasyPrint（不可用时直接报错）
PDF_CHROME_PATH=/usr/bin/chromium
```

> 注意：无头浏览器必须使用独立的 `--user-data-dir`（代码已处理），
> 否则当机器上已有浏览器在运行时，请求会被转交给既有实例且不产出文件。

**验证部署后 PDF 是否真的可用**（会打印识别到的引擎、字节数与内嵌字体）：

```bash
docker compose exec backend python -c "
import asyncio
from app.services.report_service import _render_pdf_bytes, find_pdf_browser, _load_weasyprint
print('browser :', find_pdf_browser())
print('weasy   :', _load_weasyprint()[0])
pdf = asyncio.run(_render_pdf_bytes('<h1>中文测试</h1>'))
print('bytes   :', len(pdf), pdf[:8])
"
```

字体列表里出现 `Noto Sans CJK`（或其它中文字体）才说明中文不会乱码。

## 5. Jenkins / CI 触发扫描

平台镜像仓的 `Jenkinsfile` **只构建镜像**。业务仓要触发审计，请在业务 pipeline 中调用 webhook。

### 5.1 推荐策略

后台 **系统设置 → LLM 自动** 的两个勾选是全局的，下次 webhook 即生效。Jenkins 仍只 `POST /api/webhooks/scan`，不必改 payload。

| 模式 | 何时用 | 怎么开 |
|------|--------|--------|
| **仅 SAST/SCA（推荐门禁）** | 每次 MR / 主干 | webhook；两个勾选都关 |
| SAST + LLM 误报审计 | 夜间 / 主干、已配 LLM Key | 打开「扫描完成后自动进行 SAST 误报审计」 |
| SAST + LLM 端点审计 | 夜间 / 主干、已配 LLM Key | 打开「扫描完成后自动进行 LLM 端点审计」 |
| 误报 + 端点都开 | 深度夜间任务 | 两个都开：先误报审计，再端点审计 |

Webhook **不能**在 payload 里选「只跑 LLM」；扫描器列表来自全局 `enabled_scanners`。端点审计耗时长，Jenkins stage timeout 建议 ≥ 30 分钟（克隆同步，审计在后台继续）。

### 5.2 后台能否看到新项目？

**能。** 首次 webhook 按 `project_url` **自动建 Project**；同 URL 再次触发 → 同一项目新版本扫描。UI 侧栏刷新即可。

### 5.3 前置配置（backend `.env`）

```bash
WEBHOOK_TOKEN=replace-with-a-random-shared-secret
GITLAB_ACCESS_TOKEN=replace-with-your-gitlab-token
FRONTEND_BASE_URL=http://<host>:8080
```

如果是 ECS / 单独 `docker run`，请把宿主机 `.env` 直接挂载到 `/app/.env`：

```bash
docker run -d \
  --name ai-audit-backend \
  -e AI_AUDIT_ENV_FILE=/app/.env \
  -v /data/ai-audit-backend/.env:/app/.env \
  -v /data/ai-audit:/data \
  -v /data/ai-audit/tools:/host-tools:ro \
  ai-audit-backend:latest
```

这样做后：
- 容器启动时直接读取宿主机配置
- UI 保存设置时直接写回宿主机 `.env`
- 重新构建/重新部署后无需重复填写

### 5.4 业务仓 Jenkins 示例

```groovy
pipeline {
  agent any
  options { timeout(time: 30, unit: 'MINUTES') }
  environment {
    AI_AUDIT_URL = 'http://ai-audit.example.com:8080'
  }
  stages {
    stage('AI Audit scan') {
      steps {
        withCredentials([string(credentialsId: 'ai-audit-webhook-token', variable: 'AI_AUDIT_WEBHOOK_TOKEN')]) {
          sh '''
            curl -fsS -X POST "${AI_AUDIT_URL}/api/webhooks/scan" \
              -H "Content-Type: application/json" \
              -H "X-Webhook-Token: ${AI_AUDIT_WEBHOOK_TOKEN}" \
              -d "{\\"project_url\\":\\"${GIT_URL}\\",\\"branch\\":\\"${GIT_BRANCH}\\"}"
          '''
        }
      }
    }
  }
}
```

## 6. 平台仓 Jenkins（构建镜像）

- `ai-audit-frontend` → nginx 镜像
- `ai-audit-backend` → API 镜像（扫描器靠宿主机挂载）

## 7. 配置要点

- `HOST_TOOLS_DIR`：宿主机工具目录，默认 `./.host-tools`
- `OSV_SCANNER_PATH`：默认 `/host-tools/bin/osv-scanner`
- `DATA_DIR`：Docker 下为 `/data`
- `FRONTEND_BASE_URL` / `WEBHOOK_TOKEN` / `GITLAB_ACCESS_TOKEN`
