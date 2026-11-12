# 部署说明（Windows Docker Desktop / Linux）

## 1. 通用前置

| 项 | 要求 |
| --- | --- |
| Docker | Windows：Docker Desktop 4.x+（WSL 2 后端）；Linux：Docker Engine 24+ |
| Compose | `docker compose version` 显示 v2.x |
| 内存 | 建议 ≥ 4 GB 分配给 Docker（后端镜像含 JDK 与扫描器 CLI） |
| 磁盘 | 建议 ≥ 10 GB（两个镜像 + 数据卷） |
| 宿主机工具 | 无需 Python / Node / 数据库 / 扫描器；只需 `bash`、`curl`、`openssl`（Windows 用 PowerShell 脚本则只需 Docker Desktop） |

首次构建会从 Docker Hub、PyPI、npm registry 与 GitHub Releases 下载依赖与扫描器 CLI，请确保构建环境可访问这些公开源。

## 2. Windows（Docker Desktop）

1. 安装 Docker Desktop，启用 **WSL 2** 后端；在 Settings → Resources 中把内存调到 ≥ 4 GB。
2. 打开 PowerShell，进入仓库目录：

```powershell
cd ai-deep-audit
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

   若执行策略禁止脚本，可改用：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
docker compose up -d --build
```

3. 浏览器访问 `http://127.0.0.1:8080`。
4. 首次登录密码在仓库根目录 `.env` 的 `AUTH_PASSWORD`（脚本自动生成，不打印到终端）。

> Git Bash 用户可直接运行 `bash scripts/start.sh`。
> 若 `.env` 单文件挂载失败，请确认 Docker Desktop 已共享该驱动器，且 `.env` 是文件而非目录。

## 3. Linux

```bash
git clone <your-private-fork-url> ai-deep-audit
cd ai-deep-audit
bash scripts/start.sh
# 或手动：
cp .env.example .env && bash scripts/bootstrap.sh
docker compose up -d --build
```

如当前用户不在 `docker` 组，需 `sudo usermod -aG docker $USER` 后重新登录，或在命令前加 `sudo`。

## 4. 端口与网络

| 端口 | 绑定 | 说明 |
| --- | --- | --- |
| `HTTP_PORT`（默认 8080） | `127.0.0.1` | 唯一对外端口，nginx 同时提供前端与 `/api` |
| 8787 | 仅 compose 内网 | 后端 API，不映射到宿主机 |

修改端口：编辑 `.env` 的 `HTTP_PORT`，重新执行 `start` 脚本。

**默认不监听 `0.0.0.0`**。确需局域网访问时，请自行把 `docker-compose.yml` 的端口绑定改为受控地址，并在前面加 TLS 与访问控制；直接改绑 `0.0.0.0` 会让未加固的服务暴露在网络中。

## 5. 数据与备份

| 数据 | 位置 |
| --- | --- |
| SQLite 数据库、克隆仓库、上传包、扫描缓存 | 命名卷 `ai-deep-audit_backend-data` → 容器 `/data` |
| 从 UI 保存的系统设置、登录凭据 | 仓库根 `.env` → 容器 `/app/.env` |
| 可选 MySQL 数据 | 命名卷 `ai-deep-audit_mysql-data` |

报告（HTML/PDF/Markdown/JSON）由接口按请求即时生成，不落盘；重启后仍可从同一份扫描数据重新导出。

> **启用 MySQL profile 前必须自行设置强口令**：`docker-compose.yml` 为了本地可跑提供了
> `change-me-root` / `change-me` 兜底值。请在 `.env` 中显式填写 `MYSQL_ROOT_PASSWORD` 与
> `MYSQL_PASSWORD` 后再执行 `docker compose --profile mysql up -d --build`，不要使用兜底值。

`docker compose down` **保留**上述卷。只有显式执行 `docker compose down -v` 或删除卷才会清除数据。

备份卷：

```bash
docker run --rm -v ai-deep-audit_backend-data:/data -v "$PWD":/backup \
  alpine tar czf /backup/ai-deep-audit-data.tar.gz -C /data .
```

恢复时把归档解回同名卷即可。请同时备份 `.env`（含凭据，妥善保管）。

## 6. 健康检查与故障排查

```bash
docker compose ps
curl -i http://127.0.0.1:8080/api/health
docker compose logs --tail=100 backend
docker compose logs --tail=100 frontend
```

| 现象 | 排查 |
| --- | --- |
| `/api/health` 返回 502 | 后端未 healthy：`docker compose logs backend`；首次启动需等待依赖加载与迁移 |
| 登录报 401 | `.env` 中 `AUTH_PASSWORD` / `AUTH_SECRET_KEY` 为空或长度不足，运行 `scripts/bootstrap.sh` |
| 页面能开但接口失败 | 确认浏览器地址是 `127.0.0.1:8080`；生产构建固定走同源 `/api` |
| 扫描器显示「未安装」 | 检查 `docker compose exec backend sh -lc 'which semgrep gitleaks osv-scanner npm bandit'`；CodeQL 默认不安装（`INSTALL_CODEQL=1` 才装），显示不可用属预期 |
| PDF 中文方块 | 镜像已装 `fonts-noto-cjk`；确认未被自定义镜像覆盖 |
| 构建时下载失败 | 检查能否访问 Docker Hub / PyPI / npm / GitHub Releases，必要时配置构建代理后重试 |

## 7. 升级与停止

```bash
bash scripts/start.sh     # 重新构建并启动，数据保留
bash scripts/stop.sh      # docker compose down，数据保留
```

只更新前端代码：`docker compose up -d --build frontend`；只更新后端：`docker compose up -d --build backend`。

## 8. 卸载（会删除数据）

```bash
docker compose down -v     # 删除容器与命名卷：项目、扫描、报告全部丢失
```

执行前请确认已完成第 5 节的备份。
