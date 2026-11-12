# frontend

React 18 + TypeScript + Vite 单页应用。生产构建由官方 `nginx` 镜像提供静态资源，并把同源 `/api` 反代到后端。

## 构建

构建上下文是 **Monorepo 根目录**（`frontend/Dockerfile`）：

```bash
docker compose build frontend
# 或：docker build -f frontend/Dockerfile -t ai-deep-audit-frontend:local .
```

多阶段：`node:20-bookworm-slim` 执行 `npm ci` + `npm run build`，产物 `dist/` 复制到 `nginx:1.27-alpine` 的 `/usr/share/nginx/html`。nginx 配置来自 `deploy/nginx/default.conf`（官方镜像标准路径 `/etc/nginx/conf.d/`），**不再使用旧版非标准 `/nginx/` 目录**。

只复制 `package*.json`、`index.html`、TS/构建配置和 `src/`，不复制任何 `.env` 文件，避免本地环境值被打包进前端产物。

## API 基址

生产构建固定使用同源 `/api`（`src/api.ts` 的 `candidateBases()`），由 nginx 反代到 `backend:8787`。
只有 Vite 开发服务器（端口 5173）才会额外尝试直连 `127.0.0.1:8787` 作为后端重启时的回退。

## 本地开发

```bash
npm ci
npm run dev        # http://localhost:5173，/api 代理见 vite.config.ts
npx tsc --noEmit -p tsconfig.json
npm run build
```

开发模式需要后端在 `127.0.0.1:8787`（或设置 `VITE_API_PROXY_TARGET`）。

## 目录

| 路径 | 作用 |
| --- | --- |
| `src/app/` | AppShell、导航注册表、History API 路由 |
| `src/modules/` | 按业务域拆分的页面（项目、任务、Agent、MCP、账户、Skill、系统） |
| `src/shared/` | 设计系统组件、表单、hooks |
| `src/components/` | 复用的既有业务组件（扫描详情、设置、发现详情等） |
| `src/api.ts` | 全部后端请求与 token 处理 |
