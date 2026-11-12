# 发布快照安全审查报告

> 审查对象：`ai-deep-audit/` 全新 Monorepo 快照（244 个受版本控制的文件，不含 `.env` 与运行时数据）。
> 本报告只描述**已实际执行**的扫描与验证；不含任何真实凭据、员工/客户信息或内部域名。

## 1. 快照来源与隔离边界

- 从两个已完成脱敏的原仓库按**白名单**导出，只读源仓库，**未修改原仓库任何文件**。
- 未复制 `.git`、checkpoint ref、dangling/unreachable object、内部审计笔记、
  `.env`（真实）、`data/`、`.local/`、`.workbuddy*/`、`node_modules/`、`dist/`、日志、数据库或缓存。
- 导出脚本 `stage_monorepo_export.py` 带完整性断言；导出后又按源仓库逐类比对补齐了
  `app/data/dep_exploit_kb/java_high_risk.yaml`（Java 依赖可利用性知识库），避免容器化后
  `dep_exploit` 扫描器退化。
- 原前后端仓库的 Git 历史**保持不变**，未重写、未强推、未删除对象。

## 2. 工作区敏感信息扫描

复用此前开源审查的同一套规则（凭据、内网域名、私网 IP、企业邮箱、手机号、身份证、
高熵 token、含凭据的数据库连接串等），全量遍历快照全部文件：

| 指标 | 结果 |
| --- | --- |
| 扫描文件数 | 244 |
| 内部标识命中 | **0** |
| 禁止夹带的产物 | **0** |
| 规则命中（含 info/误报） | 162 |
| blocker 级命中 | 0 |
| 模板/占位凭据（已降级为 info） | 2 |
| 二进制资产 | 1 |

blocker 级命中 **0** 条。

另有 2 条 `db_url_with_credentials` 命中经逐条上下文核对为**代码模板 / 占位符**，
不是真实凭据。扫描器新增「占位凭据」识别后把这两条降级为 `info`，但原始命中仍完整保留在
`monorepo_snapshot_scan.json` 的 `suppressed_templates` 字段中（未删除、未隐藏）：

- `backend/app/config.py`：数据库连接串 f-string 模板，用户名与口令均为插值变量。
- `frontend/src/components/SettingsModal.tsx`：设置页连接串 placeholder，用户名与口令为占位文本。

其余命中为已知良性：`frontend/package-lock.json` 的 `sha512-` integrity 摘要
（120 条高熵命中）、`tests/test_poc_http.py` 的
SSRF 保留地址测试夹具、变量名/`settings.*` 引用、公开示例邮箱。

`.env.example` / `backend/.env.example` / `.env.production.example` / `frontend/.env.example`
只含空值或公开占位；真实 `.env` 由 `scripts/bootstrap` 本机随机生成，已被 `.gitignore` 忽略。

## 3. Git 历史检查

| 检查 | 结果 |
| --- | --- |
| 是否携带原仓库 `.git` | **否** |
| 全新仓库提交数 | **1** |
| 历史中的 blob 总数 | 237 |
| 历史中出现内部标识 / 凭据 | **0** |
| `refs/codex/*` checkpoint / dangling object | **0** |
| 是否存在原仓库提交 hash | **否** |

新仓库在独立目录以 `git init` + 单次提交建立；1 个提交只包含本次白名单文件。
原仓库本地对象库中仍存在的敏感对象**不会**随此快照传播。

## 4. 构建产物与镜像检查

| 检查 | 结果 |
| --- | --- |
| 两个 Dockerfile 基础镜像 | 全部为 Docker Hub 官方公开镜像（nginx:1.27-alpine, node:20-bookworm-slim, python:3.12-slim-bookworm） |
| 内部镜像仓库地址 | **0** |
| 前端镜像内 `.env` / `.env.local` | **0** |
| 前端构建产物中直连后端地址 | 仅保留 Vite dev 回退分支（生产走同源 `/api`） |
| 前端镜像 nginx 配置路径 | 官方 `/etc/nginx/conf.d/`（非标准 `/nginx/` 已移除） |
| 镜像内敏感文件扫描 | PASS |
| 镜像大小 | backend 1.71GB / frontend 74.9MB |
| CodeQL / JDK / Maven | **可选**：`INSTALL_CODEQL=1` 才安装，默认镜像内不存在 |

## 5. 功能性验证（同一套 Compose 栈）

| 验证 | 结果 |
| --- | --- |
| `docker compose build` | 前端 PASS / 后端 PASS |
| `docker compose up -d` + 健康检查 | PASS（`/api/health` 200） |
| 单端口访问 + SPA fallback | PASS |
| 扫描器可用性（CodeQL 为可选组件，默认不安装） | 6/7 |
| API 回归 | 36/36 PASS |
| 浏览器交互与截图 | 15/15 PASS |
| `compose down` → `up -d` 数据持久化 | 5/5 PASS |

## 6. 已修复 / 待人工确认 / 阻止公开

### 已修复
1. 两个 Dockerfile 改用官方公开基础镜像，移除内部 registry 与内部路径。
2. 前端 nginx 改用官方镜像标准配置目录，并补齐 `/api` 反向代理。
3. 生产构建固定同源 `/api`，移除浏览器直连 `127.0.0.1:8787` 的假设（开发模式仍保留）。
4. 默认只绑定 `127.0.0.1`；SQLite 数据、克隆仓库、上传包、报告与 UI 设置均持久化。
5. 所有敏感参数走环境变量，`.env` 由 bootstrap 随机生成且被忽略。
6. 全新快照隔离了原仓库历史中的内部标识、内部笔记与悬空凭据对象。
7. 锁定 `pydyf==0.10.0`：`weasyprint 62.3` 只声明 `pydyf>=0.10.0` 无上限，
   新版 pydyf 会令 PDF 导出 500/503（`'super' object has no attribute 'transform'`）。
8. CodeQL 改为**按需安装**（`INSTALL_CODEQL` 构建参数）：CLI 约 400 MB，仅用于 Java
   深度分析；关闭后镜像由 3.37 GB 降到 1.71 GB，未安装时扫描器如实标记不可用。

### 待人工确认
- 历史凭据轮换未闭环，见 `docs/TOKEN_ROTATION.md`（T1 飞书 webhook、T2 GitHub PAT、T3 样例 `sk-` 串、T4 会话凭据）。
- `samples/vulnerable-app.zip` 与文档原型来源、CodeQL CLI / semgrep 随镜像分发的许可边界。
- 原私有仓库本地对象库与 checkpoint ref 是否清理（本轮未动）。

### 发布决策与遗留风险
1. **无 `LICENSE` / `NOTICE`**：代码权属与再许可权限仍未书面确认，见 `docs/OWNERSHIP.md`。
   未声明许可证时默认适用著作权保留，他人无权复制、修改或再分发。
2. 历史凭据尚未确认全部轮换/吊销；这些凭据**不在**本快照的历史对象中（0 敏感命中、0 悬空对象）。
3. 用户在 2026-11-12 明确指示将本快照推送到公开仓库 `pikachu-cxy/Ai-CodeAudit`，本轮据此执行；
   **未创建 Release、未修改其他仓库可见性、未重写原仓库历史**。

> 结论：技术层面（敏感信息 / Git 历史 / 镜像 / 构建 / 功能回归）已全部通过；
> **法务层面（许可证与代码权属）仍未闭环**，对外授权使用前必须先补 `LICENSE` 并确认权属。
