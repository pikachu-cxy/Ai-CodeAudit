# 项目知识库

## 当前开发基线

2026-11-13 核对了 `pikachu-cxy/Ai-CodeAudit` 本地 `main` 与远端 `main`，两者均指向 `28b38b6f7248bf27f1c15d9c2f838f07baacc2b3`。Deep Audit V1 在本地工作树开发。此目录为包含 `backend/`、`frontend/`、`deploy/`、`scripts/` 的独立仓库。后端 FastAPI + async SQLAlchemy，前端 React + TypeScript + Vite，Docker Compose 默认 SQLite，可选 MySQL。发布快照阶段的部署细节在 `DEPLOYMENT.md`，本阶段验收以本文记录为准。

## 代码地图

| 入口 | 实际职责 |
| --- | --- |
| `backend/app/services/scan_service.py` | 原有 SAST 调度、Finding 保存、人工复核与评分。Deep Audit 读取既有扫描结果，人工确认复用原有复核服务。 |
| `llm_endpoint_audit_service.py`、`llm_flow_recon_service.py` | 原有端点审计按 Origin、Understand 和领域 Goal 循环执行。数据流研判保留独立的工具循环。 |
| `agent_chat_service.py`、`agent_tools.py`、`llm_provider.py` | 原有扫描上下文对话、源码查询和模型调用。V1 复用接口发现、符号搜索、相关文件定位、动作 JSON 解析和 Provider；Provider 的用量和禁重试选项由 V1 显式使用。 |
| `deep_audit_service.py`、`deep_audit_planner.py`、`deep_audit_worker.py` | 调度、纯数据规划、单个通用 Worker。Worker 按任务顺序查询源码并提交事实、假设和候选。 |
| `deep_audit_guards.py`、`deep_audit_budget.py`、`tool_log_redaction.py` | 只读源码清单、参数与权限校验、运行预算和日志脱敏。 |
| `blackboard_service.py`、`models.py` | 黑板数据库 API、事实与证据去重、候选关联及证据门槛。 |
| `routers/deep_audit.py`、`routers/agents.py` | 启动、预览、读黑板、取消、恢复、复核与能力查询。 |
| `frontend/src/components/DeepAuditPanel.tsx` | Agent 配置页启动、任务详情页调查与复核、对话页执行轨迹，复用既有页面和 API 客户端。 |

## 执行和权限

1. 选取已结束且仍有源码的扫描，可指定一条已启用的 `AgentDefinition`。调度器验证源码位于平台仓库目录或上传目录，并准备范围内的源码清单、SAST 线索和已提取接口。
2. Planner 接收项目、线索、同版本黑板和用户范围，按鉴权与水平越权、注入及危险数据流、业务逻辑风险生成结构化任务。规划模块是纯数据变换。相同版本下已完成的同类型、同目标任务可跳过。
3. 单个 Worker 顺序调查。仅允许 `list_endpoints`、`list_controllers`、`search_code`、`read_file`、`read_files_batch`。目录前缀按路径段匹配，禁止越界、链接、凭据路径和超限文件。源码读取由只读能力接口执行，审计写入走数据库服务。Shell、仓库写入、任意网络工具、MCP 和 Skill 执行能力均未授权。
4. 运行预算默认 12 个模型轮次、36 次工具调用、60000 Token、600 秒和每工具 15 秒。默认单文件 512 KiB、单窗 200 行、单次输出正文 6000 字符、批量 6 个文件、最多 6 个任务。AgentDefinition 可收紧模型轮次、工具次数、批读文件数和 Token。模型请求按完整上下文估算剩余额度，禁自动重试，返回后优先按 Provider 用量记账。预算耗尽以失败结束，已保存事实保留。
   管理员可在「LLM 设置 → Deep Audit V1 预算」调整整次运行的 LLM 轮次、工具调用和 Token 上限。页面值保存在当前数据库，优先于环境默认值。保存后启动的新运行使用新预算，恢复运行继续使用原预算。
5. 工具事件复用 `ScanEvent`，记录任务、工具名、结果大小、耗时和状态。取消为协作式，恢复使用原预算和版本；源码清单变化时需新开运行。单进程限制同一扫描同时运行一个 Deep Audit。

## 黑板与迁移

SQLite 和 MySQL 的 `010_deep_audit.sql` 新增四张表。

| 模型 | 数据 |
| --- | --- |
| `AuditRun` | 扫描、状态、执行配置、路径范围、源码版本、起止时间、预算和错误。 |
| `AuditTask` | Run、Agent、类型、目标、优先级、状态、结果和任务指纹。 |
| `AuditFact` | Run、Task、类型、来源、摘要、置信度、事实指纹和可选 Finding 外键。 |
| `AuditEvidence` | Fact、源码版本、相对路径、实际完整行范围、切片 SHA-256 和证据摘要。 |

版本采用范围内源码清单 SHA-256，读取时核验文件摘要。相同扫描、相同版本可复用事实。已提交事实和证据保留在 SQLite/MySQL。代码事实、漏洞假设和候选是三种事实类型。候选必须有同版本、同路径且覆盖候选行的代码证据，才关联既有 `Finding`。初始状态为 `unreviewed / pending`。人工确认后进入既有漏洞和报告体系，保留黑板证据。

## API 契约

以下路径统一以 `/api` 开头，使用既有平台鉴权。

| 方法和路径 | 输入或返回 |
| --- | --- |
| GET / PUT `/deep-audit/settings` | 管理员读取或更新 Deep Audit V1 的三个全局预算上限。 |
| GET `/deep-audit/capabilities` | 模式、方向、工具白名单、预算、LLM 配置状态。 |
| POST `/scans/{scan_id}/deep-audit/plan` | `focus`、`path_prefixes`、`max_tasks`。返回版本和规划任务，不持久化。 |
| POST `/scans/{scan_id}/deep-audit/runs` | 同预览，可加 `agent_slug`。返回 201 和 Run。 |
| GET `/scans/{scan_id}/deep-audit/runs` | 扫描的运行列表。 |
| GET `/deep-audit/runs/{run_id}` | 当前 Agent、任务、预算、事实、候选和已确认漏洞。 |
| GET `/deep-audit/runs/{run_id}/facts` | 可按 `fact_type` 查询，包含证据。 |
| GET `/deep-audit/runs/{run_id}/events` | 运行事件，支持 `limit`。 |
| POST `/deep-audit/runs/{run_id}/cancel`、`/resume` | 请求取消或恢复已中断运行。 |
| POST `/deep-audit/runs/{run_id}/findings/{finding_id}/confirm` | 可传 `review_note`，要求该运行有对应代码证据。 |

## 验收与对照

后端运行 `python -m unittest discover -s tests -q`。前端运行 `npm ci` 和 `npm run build`。容器使用 `docker compose build`，并在独立 Compose 项目和本机端口上验证。

| 验证项 | 实测 |
| --- | --- |
| 后端回归 | 294 项，293 通过，1 项因宿主机缺 WeasyPrint 跳过。 |
| Deep Audit 两套 Python 样例 | 漏洞样例 4 条证据支持的候选，覆盖鉴权、两处 SQL 拼接和客户端金额。安全对照 0 条候选。未复核时均无已确认漏洞。 |
| 工具、黑板和预算 | 跨任务读取共享事实，重复运行事实数不增长。取消后证据保留，源码变化后拒绝恢复。无证据仅产生假设。验证工具次数、轮次、Token 和时间预算。模型轮次使用 Provider 测试替身，仍执行真实只读工具。 |
| 原有扫描 | 通过原扫描流程运行真实 Bandit，漏洞样例有结果，安全对照无结果。 |
| 前端和 Docker | TypeScript/Vite 生产构建和两镜像构建通过。Chrome 通过 Agent 定义选择、预览、启动、任务证据、确认和对话执行轨迹。前端仍有大资源包提示。容器重建后确认 SQLite 已登记 010 迁移，浏览器验收产生的 15 条证据和 1 条人工确认记录均保留。 |

| 模式 | 漏洞样例 | 安全对照 | Token |
| --- | --- | --- | --- |
| V1 无模型回退 | 4 条候选，12 次工具调用，约 7.2 秒 | 0 条候选，12 次工具调用，约 5.4 秒 | 两次均为 0 |
| 旧版单流程 LLM | 端点返回缺少 LLM API Key | 同一前置条件 | 无实测 |

安全对照未出现候选误报。样例覆盖有限。当前环境没有模型凭据，旧版和 V1 的真实模型发现率、误报率、耗时和 Token 仍待同条件测量。

## 已知限制与下一阶段

- 首版采用进程内调度。容器重启后可手动恢复；跨实例调度、自动接管和多 Worker 并发留待后续。
- 无模型回退使用有限的可审阅规则。跨文件定位属于启发式，复杂鉴权中间件、调用图和业务状态机需扩大语料验证。
- 只读约束位于工具能力层。若后续引入可执行插件，应先建立独立进程、只读挂载和操作系统级权限。
- MySQL 迁移已提供，本轮容器验收使用 SQLite。CodeQL 默认镜像仍需启用构建选项。
- 下一阶段优先为两种模式配置相同模型、重复运行同一批项目，记录人工复核后发现、误报、耗时和 Token，再依据覆盖与调度数据决定是否扩展至 2–3 个 Worker。
