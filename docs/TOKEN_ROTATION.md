# 历史凭据核实与轮换清单（人工执行）

> 原则：**凡是无法证明为假的凭据，一律按「可能已泄露」处理**。
> 本文件不含任何真实凭据明文，只给出类型、来源、脱敏指纹与处理建议。
> 本次工作**没有**调用任何外部服务执行轮换，也没有删除或重写原仓库历史。
> 原前后端仓库及其 Git 历史保持原状；本 Monorepo 是从脱敏源码导出的**全新快照**，
> 不含原 `.git`、checkpoint ref、dangling object 或内部笔记。

## 1. 需要立即轮换 / 吊销

| # | 凭据类型 | 来源位置 | 是否仍可能有效 | 建议处理 |
| --- | --- | --- | --- | --- |
| T1 | 飞书机器人 Webhook Token（形如 36 字符随机串，脱敏指纹 `sha256:dfba805e69`） | 两个原仓库的 `Jenkinsfile`，master 可达提交：后端 `5a21657`、前端 `bb260db` | **无法证明失效，按有效处理** | 在飞书开放平台删除/重置该自定义机器人并生成新 webhook；同步更新所有 CI 凭据；检查机器人消息历史是否被滥用 |
| T2 | GitHub Personal Access Token（`ghp_` 前缀、40 字符，脱敏指纹 `sha256:555325232d`） | 后端原仓库**不可达/悬空 blob** `19bf099a26`，无可达提交；同时该 PAT 曾在本项目会话中用于推送到私有 GitHub 镜像 | **无法证明失效，按有效处理** | 在 GitHub Settings → Developer settings 中 **Revoke** 该 PAT；如仍需推送，新建最小权限、带有效期的 fine-grained token；检查仓库 Settings 与审计日志中的异常访问 |
| T3 | 历史演示样例中的 `sk-` 形态字符串（28 字符，脱敏指纹 `sha256:e057ce0ef4`） | 后端 `samples/plugin-scan-demo/python/app.py`，提交 `b86cc56`（`feature/ai-security-check-mvp` 分支，**非 master 祖先**） | **无法确认真假**：形态像 provider key，但属于 intentionally vulnerable sample | 由人工在对应 LLM provider 控制台按前缀核对是否存在该 key；存在即吊销；不存在则在样例中改写为明显假值并补说明。**不得直接判定为安全** |
| T4 | 会话中提供过的 GitHub PAT、GitLab Access Token 等交互凭据 | 本项目的聊天/临时凭据文件（临时文件已删除） | **无法证明失效** | 与 T2 合并处理：凡在对话中出现过的 token 一律轮换；今后改用短时效凭据 + 仓库外凭据文件 |

## 2. 未进入 Git 历史、但属于真实运行凭据（按环境风险决定）

这些值位于本机 `.env`（已被 `.gitignore` 忽略，**从未进入历史扫描的 blocker 集合**）。
若该开发机、备份或 `.env` 副本曾共享给他人，应一并轮换：

| 凭据类型 | 位置 | 说明 |
| --- | --- | --- |
| `AUTH_PASSWORD` / `AUTH_SECRET_KEY` | 原后端 `.env`；新快照由 `scripts/bootstrap` 随机生成 | 新快照已使用**全新的随机值**，不复用旧值 |
| `LLM_API_KEY` | 原后端 `.env` | LLM provider 控制台轮换 |
| `GITLAB_ACCESS_TOKEN` | 原后端 `.env` | 只读令牌，仍建议在 GitLab 侧轮换 |
| `MYSQL_PASSWORD` / `SMTP_PASSWORD` / `SSO_CLIENT_SECRET` / `WEBHOOK_TOKEN` | 原后端 `.env` | 按各系统轮换 |

> 新 Monorepo 的 `.env.example` 全部为空值/公开占位，`.env` 由 bootstrap 在本机生成且被忽略，**不包含上述任何历史值**。

## 3. 经核实为示例/占位，无需轮换（留档说明）

| 形态 | 来源 | 判定依据 |
| --- | --- | --- |
| `WEBHOOK_TOKEN=replace-me`、`GITLAB_ACCESS_TOKEN=glpat-...` | `INSTALL.md` 历史版本 | 明显占位文本，长度 10 / 9 |
| `Authorization: Bearer ...`（33 字符） | `tests/test_ai_fix_service.py` 测试夹具 | 含占位词，测试 mock |
| 数据库连接串模板（含用户名/口令插值变量） | `app/config.py` f-string、前端设置页 placeholder | 代码模板，无真实主机/口令 |
| `mysql_password` / `api_key` 等命中 | `app/routers/scans.py`、`database_service.py`、`llm_provider.py` | 变量名与 `settings.*` 引用，非字面量 |
| `package-lock.json` 中 120 处高熵串 | 前端 lockfile | `sha512-...` integrity 摘要，非凭据 |
| 私网 IPv4 | `tests/test_poc_http.py` | SSRF 防护的保留地址测试夹具 |

## 4. 原私有仓库的处置建议（不在本轮执行）

- 原两个仓库继续保留为**私有**，不要改为 Public。
- 若要彻底消除本地对象库中的敏感对象（T2 的悬空 blob、引用 4 份内部审计笔记的
  `refs/codex/turn-diffs/checkpoints/*`），应从**干净快照**重新建立远端，或仅推送指定分支，
  **不要** `push --all` / `push --mirror` / 直接复制 `.git` 目录。
- 是否清理本地对象库、是否删除 checkpoint ref，属于对原仓库的操作，需另行授权；
  本轮明确**没有**执行历史重写、强制推送或删除。
