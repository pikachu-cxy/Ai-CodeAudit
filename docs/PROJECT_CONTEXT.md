# 项目知识库

## 当前开发基线

本轮以本地和 GitHub `main` 的 `929f04f` 为基线。基线核对时工作区干净。此目录为包含 `backend/`、`frontend/`、`deploy/`、`scripts/` 的独立仓库。后端 FastAPI + async SQLAlchemy，前端 React + TypeScript + Vite，Docker Compose 默认 SQLite，可选 MySQL。发布快照阶段的部署细节在 `DEPLOYMENT.md`，本阶段验收以本文记录为准。

## 代码地图

| 入口 | 实际职责 |
| --- | --- |
| `backend/app/services/scan_service.py` | 原有 SAST 调度、Finding 保存、人工复核与评分。Deep Audit 读取既有扫描结果，人工确认复用原有复核服务。 |
| `llm_endpoint_audit_service.py`、`llm_flow_recon_service.py` | 原有端点审计按 Origin、Understand 和领域 Goal 循环执行。数据流研判保留独立的工具循环。 |
| `agent_chat_service.py`、`agent_tools.py`、`llm_provider.py` | 原有扫描上下文对话、源码查询和模型调用。V1 复用接口发现、符号搜索、相关文件定位、动作 JSON 解析和 Provider；Provider 的用量和禁重试选项由 V1 显式使用。 |
| `deep_audit_service.py`、`deep_audit_lineup.py`、`deep_audit_model_planner.py`、`deep_audit_planner.py`、`deep_audit_worker.py` | 校验并固化阵容；按选择调用 Planner 模型或运行内置规则；按擅长方向分派任务，分批调查并提交结论。 |
| `deep_audit_guards.py`、`deep_audit_budget.py`、`tool_log_redaction.py` | 只读源码清单、参数与权限校验、运行预算和日志脱敏。 |
| `blackboard_service.py`、`models.py` | 黑板数据库 API、事实与证据去重、候选关联及证据门槛。 |
| `routers/deep_audit.py`、`routers/agents.py` | 启动、预览、读黑板、取消、恢复、复核与能力查询。 |
| `asset_graph_service.py`、`audit_graph_service.py` | 分别保存源码资产结构、投影本次 Run 的任务与证据。 |
| `frontend/src/components/DeepAuditPanel.tsx`、`DeepAuditGraphs.tsx` | Agent 配置页启动、任务详情页调查与复核、双图联动、对话页执行轨迹。 |

## 执行和权限

1. 选取已结束且仍有源码的扫描，在 Agent 管理页「本次审计阵容」中选用内置规则或一个已启用的 Planner，并选择内置 Worker 或 1–3 个已启用的 Worker。Reviewer 和 Reporter 仅可登记配置。调度器验证源码位于平台仓库目录或上传目录，并准备范围内的源码清单、SAST 线索和已提取接口。
2. Planner 接收项目、SAST、端点、同版本黑板和审计范围。自定义 Planner 使用快照中的模型和提示词，模型只收到序列化线索和允许的相对路径，没有工具权限。后端校验 JSON、方向、目标与数量，拒绝整份越界计划，再走内置规则并记录 `fallback_reason`。同版本、同方向、同目标且有有效覆盖的任务才可自动跳过。
3. 多 Agent 已接通。Worker 优先按结构化 `specialties` 匹配任务，其次使用通用 Worker，没有匹配时由所选 Worker 中分派任务较少的成员承担。任务记录保存负责的 Agent 标识；调度按优先级降序与任务 ID 升序分批，同一批最多两个不同 Worker，每个任务各用一个 AsyncSession。默认 `DEEP_AUDIT_TASK_CONCURRENCY=2`，设为 1 回退；一个 Worker 或旧 `agent_slug` 入口仍串行。三名 Worker 可入阵，空不出槽位的任务排队。同批共享上一批提交后的事实摘要；同批不能直接引用对方即时写入的证据。仅允许 `list_endpoints`、`list_controllers`、`search_code`、`read_file`、`read_files_batch`。目录前缀按路径段匹配，禁止越界、链接、凭据路径和超限文件。源码读取由只读能力接口执行，审计写入走数据库服务。Shell、仓库写入、任意网络工具、MCP 和 Skill 执行能力均未授权。
4. 运行预算默认 12 个模型轮次、36 次工具调用、60000 Token、600 秒和每工具 15 秒。默认单文件 512 KiB、单窗 200 行、单次输出正文 6000 字符、批量 6 个文件、最多 6 个任务。整次运行共享轮次、工具次数、Token 和时间上限。每个角色另有自己的累计额度，任务间和恢复时保留用量。Worker 的工具次数上限按角色轮次的三倍计算，批读范围也受角色预算约束。旧 `agent_slug` 继续保留单 Worker 和原有总预算收紧行为。每个角色显式持有预算句柄。请求前预留轮次和输入估算加输出额度，返回后按 Provider 实际用量结算；工具发出前扣额度。进程级模型请求上限默认四个（`DEEP_AUDIT_MODEL_CONCURRENCY`）。遇到进程中止时按已保存的预留额度保守计算。预算耗尽以失败结束，已保存事实保留。
   管理员可在「LLM 设置 → Deep Audit V1 预算」调整整次运行的 LLM 轮次、工具调用和 Token 上限。页面值保存在当前数据库，优先于环境默认值。保存后启动的新运行使用新预算，恢复运行继续使用原预算。
5. 工具事件复用 `ScanEvent`，记录规划来源、回退原因、任务、Agent、工具、耗时和状态。取消为协作式；新运行恢复时沿用固化的阵容、模型、提示词、预算和代码版本。原有未保存阵容的历史运行仍用旧恢复方式。源码清单有变化时需新开运行。单进程限制同一扫描同时运行一个 Deep Audit；取消时停止领任务，已提交证据保留，恢复不重跑已完成任务。

## 黑板与迁移

SQLite 和 MySQL 的 `010_deep_audit.sql` 建立下列四张表。`011_agent_specialties` 增加 `agent_definitions.specialties` JSON 列，旧记录为空时按通用角色处理。阵容、计划结果写入原 `AuditRun.config_snapshot`，快照引用 `asset_graph_id` 和并发上限；逐角色用量写入 `AuditRun.budget_usage`，任务分配使用原 `AuditTask.agent_id`。运行查询不返回自定义提示词。

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
| POST `/scans/{scan_id}/deep-audit/plan` | `focus`、`path_prefixes`、`max_tasks`，可选 `planner_slug`、`worker_slugs`。返回版本、计划来源、回退原因和任务分配。选用 Planner 模型时会消耗该次预览的调用额度，不写入审计运行，也不启动 Worker。 |
| POST `/scans/{scan_id}/deep-audit/runs` | 同预览。旧客户端可使用单独的 `agent_slug`，不能与新阵容字段并用。返回 201 和 Run，后台生成本次正式计划。 |
| GET `/scans/{scan_id}/deep-audit/runs` | 扫描的运行列表。 |
| GET `/deep-audit/runs/{run_id}` | 保留 `current_task`；新增 `active_tasks[]` 和 `task_concurrency_limit`。 |
| GET `/deep-audit/runs/{run_id}/facts` | 可按 `fact_type` 查询，包含证据。 |
| GET `/deep-audit/runs/{run_id}/events` | 运行事件，支持 `limit`。 |
| POST `/deep-audit/runs/{run_id}/cancel`、`/resume` | 请求取消或恢复已中断运行。 |
| POST `/deep-audit/runs/{run_id}/findings/{finding_id}/confirm` | 可传 `review_note`，要求该运行有对应代码证据。 |
| POST `/scans/{scan_id}/deep-audit/asset-graph/build` | 用当前源码清单建图，按规范化前缀复用；无模型调用。 |
| GET `/scans/{scan_id}/deep-audit/asset-graph` | 支持 `run_id` 定位历史快照并叠加该 Run 的状态，`root_asset_id` 局部展开；纯读取。 |
| GET `/deep-audit/runs/{run_id}/audit-graph` | Planner、任务、事实、证据、Finding 投影。 |
| GET `/deep-audit/runs/{run_id}/evidence/{evidence_id}/source` | 只返回可追溯的证据切片。源码缺失、版本或切片校验失败返回 409。 |

## 双图与覆盖

- SQLite、MySQL 的 012 新增 `asset_graph_snapshots`。快照唯一键是扫描 ID、范围内源码清单 SHA-256、规范化路径范围和提取器版本。节点 ID 依赖快照键及规范化身份；入口区分请求方法、路由、文件、处理器及声明行，不按路由名合并。同文件同路由有歧义时不自动绑定任务。资产图复用已有规则解析器，目录归类用虚线，只有真正定位到处理器声明时才画处理器关系。
- 扫描详情的「资产图」可按 Run 选历史快照。审计覆盖只在读取时叠加，任务通过 `scope_json.asset_ids` 关联；通用调查可无资产关联。Run 的「审计图」从黑板及 Finding 自动投影，复用事实保留原始 Task 归属。任务分支可切换到对应资产；源码预览验证当前只读清单及切片哈希，不以新版替代历史。
- 任务覆盖与执行状态分别记录。有效带证据的模型结论、无模型规则核查、未覆盖、无效输出、超时回退和预算耗尽分别展示。模型失败后执行过规则检查也不会被标为模型审计通过。旧报告仍按实际 Finding 统计，不从任务数推导覆盖或安全结论。旧 Run 未保存资产快照时仍可用任务列表和黑板。

## 本轮并发与双图验收

- 隔离容器后端回归共 302 项，300 项通过，2 项跳过。同步屏障验证两 Worker 均进入后才释放；并发设为 1 无重叠，第三个任务等待原 Worker 结束。两角色竞争最后一轮预算，仅一方成功；重复读同一证据及重复发布候选得到去重结果。
- 取消后停止派发，恢复沿用原配置，已完成任务未重跑。已提交证据保留，源码变化后拒绝恢复原版本。测试验证无效模型分支未覆盖，正常分支保留代码证据和候选，候选可人工确认。同版本同范围复用快照，同名路由隔离，历史图与新版本不串联。
- TypeScript、Vite、两个 Docker 镜像构建及隔离 Compose SQLite 服务启动通过；验收库已登记 012，有快照和人工确认记录。Chrome 从 Agent 页选择 Planner、权限 Worker 和业务 Worker，再从扫描详情验证两条任务分支同时运行、退款入口 → 权限任务 → 证据源码 → 返回资产图，并确认候选。大资源包构建提示仍存在。MySQL 有增量 SQL，未连接 MySQL 实例实测。
- 调度使用受控测试模型验证；未度量真实模型的提速、发现率或误报率。旧端点审计和 SAST 实现保持原入口。

## 上一轮角色编排验收（929f04f 基线）

- 隔离容器运行后端完整回归，299 项中 297 项通过、2 项跳过。角色编排测试使用模型 Provider 替身验证调用的模型和提示词，仍执行真实只读文件读取。
- 同一扫描切换到 Planner Agent 后，计划目标和优先级变化。鉴权与注入任务分给两个不同 Worker，调用顺序验证为串行。启动后停用并修改 Worker 配置，运行仍使用原模型和提示词。
- 角色错配、重复 Worker 和新旧参数混用被拒绝。越界模型计划在预览和正式运行中均被拒绝，正式运行仅落内置规则任务，并保存回退原因。
- 验证旧入口、无模型模式、角色与总预算恢复、已有 SQLite AgentDefinition 的迁移、黑板证据、取消恢复和人工复核。漏洞样例保留 4 条候选，安全对照为 0。
- 前端 TypeScript、Vite 生产构建及 `docker compose build` 的两个镜像通过，仍有既有的大资源包提示。本轮未用真实外部模型检验规划质量，未连接 MySQL 实例验收迁移。

## 基线验收与对照

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

- 首版采用进程内调度。容器重启后可手动恢复；跨实例调度和自动接管留待后续。
- 无模型回退使用有限的可审阅规则。跨文件定位属于启发式，复杂鉴权中间件、调用图和业务状态机需扩大语料验证。
- 只读约束位于工具能力层。若后续引入可执行插件，应先建立独立进程、只读挂载和操作系统级权限。
- MySQL 迁移已提供，本轮容器验收使用 SQLite。CodeQL 默认镜像仍需启用构建选项。
- 下一阶段优先为两种模式配置相同模型、重复运行同一批项目，记录人工复核后发现、误报、耗时和 Token，再依据覆盖与调度数据决定是否扩展并发。资产图的端点和处理器覆盖受现有语言提取器限制。
