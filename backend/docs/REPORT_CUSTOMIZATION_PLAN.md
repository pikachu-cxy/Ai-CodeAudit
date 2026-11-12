# 漏洞报告功能优化计划：支持自定义选择漏洞生成报告

> 状态：**Phase 1 已实现，Phase 2 内容增强已部分实现**（详见文末「实现进度」）
> 范围：`ai-audit-backend` + `ai-audit-frontend`
> 目标：把「报告 = 整次扫描的全量快照」升级为「报告 = 可自由圈定范围、可配置内容、可留存分享的交付物」

## 已确认的产品决策

- **勾选即导出**：不做报告持久化表（`reports`），不引入「保存报告方案」。选定范围后直接生成/下载。
- **PDF 条数上限 2000 条**：超出时返回明确提示，引导改用 HTML / Markdown。

---

## 一、现状梳理（代码理解）

### 1.1 后端报告链路

| 层 | 位置 | 说明 |
|---|---|---|
| 数据装配 | `app/services/report_service.py:370` `build_scan_report_payload()` | **唯一数据入口**，返回 `{meta, stats, findings}` |
| 出口 1 | `build_scan_html_report()` | 注入 `templates/scan_report.html` 的 `/*__REPORT_DATA__*/`，由浏览器端 JS 做筛选与弹窗 |
| 出口 2 | `build_scan_pdf_report()` | WeasyPrint 渲染 `templates/scan_report_pdf.html` |
| 出口 3 | `build_scan_markdown_report()` | 给 AI 阅读的 Markdown（含「给 AI 的阅读建议」章节） |
| 出口 4 | `build_scan_json_report()` | 原始 payload JSON |
| 路由 | `app/routers/scans.py:1185-1239` | 4 个 **GET** 端点，仅接受 `scan_id`，无任何筛选参数 |
| 统计 | `app/services/scan_service.py:2270` `get_scan_stats()` | **恒按 scan 全量**分组统计 |
| 邮件 | `app/services/scan_service.py:389` `_maybe_send_scan_report_email()` | 扫描完成后自动把 HTML 报告作为邮件正文发出 |

关键实现细节：

- 报告 payload 中的 `stats` 来自 `get_scan_stats(session, scan_id)`，是**全量统计**，与 `findings` 列表不联动。
- `_finding_payload()`（`report_service.py:108`）当前输出字段：
  `id / severity / category / source / tool / rule_id / title / message / file_path / line_start / snippet / ai_verdict / ai_reason / ai_confidence / review_status / review_note / owasp_id / owasp_name`
- HTML 报告模板（`templates/scan_report.html`，405 行）本身已有**客户端筛选**：危害 / OWASP / 来源 / 关键词 + 明细弹窗，但它只能筛**已经装进 payload 的那一批**漏洞——筛选发生在浏览器，不影响导出的 PDF / MD / JSON。
- PDF 渲染 `HTML(string=html).write_pdf()` 在 **async 函数中同步执行**，会阻塞事件循环。
- 路由级已挂 `Depends(require_auth)`（`scans.py:139`），但**无按用户的数据隔离**——任一登录用户可读任一扫描的报告，与现有 `/scans/{id}` 行为一致。

### 1.2 前端报告链路

| 位置 | 说明 |
|---|---|
| `src/components/AuditReportHeader.tsx:171-239` | 报告头部，4 个按钮：查看 HTML / 下载 PDF / 下载 Markdown / 下载 JSON，**全部只传 `scan.id`** |
| `src/api.ts:1300-1318` | `openScanReport`（fetchHtml → Blob → `window.open`）、`downloadScanReportPdf/Markdown/Json`（fetchBlob → `<a download>`） |
| `src/api.ts:865 / 892` | `fetchHtml` / `fetchBlob` —— **仅支持 GET + Authorization 头**，无 POST body 能力；含多 base 重试与 401 处理 |

### 1.3 已有的可复用能力（本次方案的关键杠杆）

`ScanDetailView.tsx` 已经存在一套**完整的跨页勾选机制**，无需从零搭建：

- 状态：`selectedFindingIds: Set<number>`（`:164`）
- 操作：`toggleSelectPage`（`:639`）、`selectHighOnPage`（`:650`，一键勾选本页 Critical+High）、`clearSelection`（`:655`）
- 已有消费方（全部是 `POST + finding_ids: number[]` 模式）：
  - 漏洞研判 `api.analyze`（`:666`）
  - SAST 深度研判 `api.sastDeepAudit`（`:696`）
  - 定向复测（`:878`）
- 列表页已有丰富筛选：关键词 / 工具 / 安全标记 / 严重级别 / OWASP / 子类型 / 分类 tab / diff 筛选

### 1.4 现存痛点

1. **报告粒度只有「整次扫描」**——无法只导出部分漏洞，也无法按模块/按等级拆分交付。
2. **统计与明细口径会打架**——`stats` 全量、`findings` 可筛选，一旦做筛选导出，报告头部数字将与明细对不上。
3. **报告内容偏"扫描结果"，不像"漏洞报告"**——缺验证 PoC（`metadata_json.verification_poc` 已存在但未取用）、缺修复建议、缺重测结论、缺 `vuln_subtype` 与 `external_status`。
4. **HTML 报告的筛选是"假筛选"**——只在浏览器内生效，导出的 PDF/MD/JSON 永远是全量。
5. **PDF 同步阻塞**——大扫描渲染期间整个服务的事件循环被占住。
6. **无条数上限与分页**——`build_scan_report_payload` 无条件 `select` 全部 findings。
7. **导出文件名固定**（`{项目}-scan-{id}.pdf`）——多次不同口径的导出会互相覆盖，无法区分。
8. **渲染逻辑重复**——`_build_markdown_report`、`_render_pdf_html`、`_static_fallback`、模板内 JS 各自重算一遍 `by_src` / 分布数据。

---

## 二、优化目标

核心诉求拆成三层能力：

- **L1 选择维度**：手动勾选（按 ID）/ 按条件圈定（等级、OWASP、来源、工具、分类、AI 判定、人工标记、关键词、diff）
- **L2 报告配置**：标题、是否含代码片段 / PoC / AI 研判理由 / 误报条目 / 重测结论；分组方式、排序方式
- **L3 输出与留存**：HTML 在线预览、PDF、Markdown、JSON、邮件；报告可命名、可保存、可分享

---

## 三、方案设计

### 3.1 后端改造

#### (1) 引入统一的 `ReportSpec`，把"报告请求"变成一等公民

```python
class ReportFilters(BaseModel):
    severity: list[str] | None = None
    owasp: list[str] | None = None
    source: list[str] | None = None          # sast / llm
    tool: list[str] | None = None
    category: list[str] | None = None
    ai_verdict: list[str] | None = None
    review_status: list[str] | None = None
    subtype: list[str] | None = None
    keyword: str | None = None
    only_diff: bool = False

class ReportInclude(BaseModel):
    snippet: bool = True
    poc: bool = False
    ai_reason: bool = True
    false_positive: bool = False
    retest: bool = True
    remediation: bool = True

class ReportSpec(BaseModel):
    scan_id: int
    title: str | None = None
    finding_ids: list[int] | None = None      # 显式勾选，优先级最高
    filters: ReportFilters | None = None      # 结构化筛选
    include: ReportInclude = ReportInclude()
    group_by: Literal["severity", "owasp", "file", "tool", "none"] = "severity"
    sort: Literal["severity", "file", "owasp", "id"] = "severity"
```

**改造要点：只改 `build_scan_report_payload(session, scan_id, spec=None)` 一个函数签名**，4 个出口自动获得筛选能力，改动面最小。

- `spec=None` 时行为与现状完全一致（向后兼容）。
- `finding_ids` 优先于 `filters`；两者都给时以 `finding_ids` 为准，并把 `filters` 作为二次收敛。
- **必须校验** `finding_ids` 中每个 id 的 `scan_id` 都等于入参 `scan_id`，防止越权读取其他扫描的漏洞。

#### (2) 统计口径必须重算（最容易踩的坑）

新增纯函数 `_stats_from_findings(findings) -> dict`，输出与 `get_scan_stats` 同构的 `by_severity / by_owasp / by_tool / by_category / by_verdict / by_review / total`。

- 筛选/勾选场景：**一律用重算结果**，保证「头部数字 = 明细条数」。
- 全量场景：可继续用 `get_scan_stats`（走库聚合更省内存），但建议一并切到重算以消除两条口径。
- 校验手段：写一条测试断言「全量 spec 的重算结果 == `get_scan_stats` 结果」。

#### (3) 接口层：POST 为主，GET 保留兼容

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/scans/{id}/report/preview` | 返回筛选后的轻量 payload（条数 + 分布），供前端弹窗实时预览 |
| POST | `/scans/{id}/report.html` | 返回 HTML（新标签页预览） |
| POST | `/scans/{id}/report.pdf` | 下载 PDF |
| POST | `/scans/{id}/report.md` | 下载 Markdown |
| POST | `/scans/{id}/report.json` | 下载 JSON |
| GET | 现有 4 个 | **保留**，内部转成 `spec=None` 的全量请求 |

**为什么用 POST 而不是给 GET 加 query 参数**：`finding_ids` 可能几百个，GET query 会超长；且项目内 `analyze` / `retest` 已是 `POST + finding_ids` 的既定风格。

#### (4) 文件名带上口径摘要

`{项目}-{口径}-scan-{id}-{yyyymmddHHMM}.pdf`，其中「口径」如 `all` / `critical-high` / `custom-42`。避免多次导出互相覆盖。

#### (5) PDF 并发保护

```python
pdf_bytes = await asyncio.to_thread(lambda: HTML(string=html).write_pdf())
```

并加条数上限（建议 > 2000 条时返回 400，提示改用 HTML / Markdown 导出）。

#### (6) 前端下载通道补齐 POST 能力

`fetchHtml` / `fetchBlob` 增加可选 `options?: { method, body }`，或新增 `postHtml` / `postBlob`，复用现有的多 base 重试与 401 逻辑。

### 3.2 前端改造

#### (1) 新增 `ReportBuilderModal.tsx`（报告生成器）

入口改造：`AuditReportHeader` 的 4 个平铺按钮 → 收敛为 **「生成报告」主按钮 + 快速导出下拉**（保留原 4 个全量导出，满足习惯用法）。

弹窗分三段：

1. **范围**
   - 默认「全部 N 条」
   - 若列表已有勾选 → 默认「已选 M 条」（复用 `selectedFindingIds`）
   - 支持切到「按条件筛选」——把列表页当前筛选条件带入并可视化展示
2. **内容**
   - 开关：代码片段 / 验证 PoC / AI 研判理由 / 误报条目 / 重测结论 / 修复建议
   - 分组方式（按等级 / 按 OWASP / 按文件 / 不分组）、排序方式
3. **输出**
   - 报告标题输入框（默认「{项目名} 安全审计报告」）
   - 格式：HTML 预览 / PDF / Markdown / JSON
   - 可选：邮件发送（复用现有 `notify_emails`）

实时预览：调 `report/preview`，显示「将包含 N 条，其中 Critical x / High y / Medium z」。

#### (2) 选择状态打通

`selectedFindingIds` 与列表筛选条件**已存在**，只需透传给弹窗，**无需新建选择逻辑**。

#### (3) 偏好记忆

把上次的 `include` / `group_by` / `sort` 存 localStorage，避免每次重选。

### 3.3 报告内容增强（让它真的像"漏洞报告"）

在 `_finding_payload` 中补充字段，模板按 `include` 开关渲染：

| 新增字段 | 来源 | 价值 |
|---|---|---|
| `poc` | `metadata_json.verification_poc`（已有 `poc_service.get_stored_poc`） | 可复现验证步骤 |
| `remediation` | `metadata_json` 中的修复建议 / 按 `rule_id` 聚合的通用建议 | 交付物必备 |
| `retest` | 复测结论（`RetestVerdict`） | 体现修复进展 |
| `external_status` | `Finding.external_status` | 外部复核状态 |
| `vuln_subtype` / `vuln_subtype_name` | `Finding` 已有字段 | 更细的分类 |

### 3.4 报告持久化与分享（建议二期）

- 新增 `reports` 表：`id / scan_id / spec_json / title / format / created_by / created_at / token`
- 生成后得到稳定链接 `/r/{token}`，避免每次重算
- 邮件可发「精选报告」（如仅 Critical+High）而非全量
- 复用现有 `app/services/public_link_service.py` 的签名 token 机制

---

## 四、实施顺序（分批）

**Phase 1 — 核心能力（可自定义选漏洞生成报告）**
1. `_stats_from_findings()` + `build_scan_report_payload(spec)` 改造
2. 5 个 POST 端点 + 保留现有 GET
3. `fetchHtml` / `fetchBlob` 支持 POST
4. `ReportBuilderModal` 基础版（全部 / 已选 / 按筛选 + 格式选择 + 实时预览）
5. `AuditReportHeader` 入口接入

**Phase 2 — 内容增强**
6. `_finding_payload` 补 `poc` / `remediation` / `retest` / `external_status` / `vuln_subtype`
7. HTML 与 PDF 模板渲染这些区块
8. PDF 走 `asyncio.to_thread` + 条数上限
9. 导出文件名加口径摘要

**Phase 3 — 体验与治理**
10. 渲染逻辑去重（抽出公共的分布计算与卡片渲染）
11. 报告持久化 + 分享链接 + 邮件发精选报告
12. 报告模板配置（公司名 / Logo / 页眉页脚）落到 `SettingsModal`

---

## 五、风险与注意点

1. **统计口径**：筛选导出必须重算 stats，否则头部数字与明细不符——这是最容易踩的坑，需配测试兜底。
2. **越权校验**：`finding_ids` 必须逐条校验归属 `scan_id`。
3. **向后兼容**：现有 GET 端点被扫描完成邮件与可能的外部脚本调用，**不可删除**。
4. **PDF 内存**：数千条 finding 的 HTML 字符串可达数十 MB，WeasyPrint 渲染慢且吃内存，必须有上限。
5. **URL 长度**：批量 id 走 POST body，不走 query。
6. **敏感数据**：报告含代码片段与 PoC，属高敏内容；虽然路由已有 `require_auth`，但当前**无按用户隔离**（任一登录用户可读任一扫描），若未来需要项目级权限，报告端点需一并纳入。
7. **前端一致性**：`openScanReport` 走 Blob + `window.open`，改为 POST 后需确认不会触发浏览器弹窗拦截（应先 `window.open` 占位再写入，或继续用 Blob URL 方案）。

---

## 六、验收标准

- [ ] 列表勾选 3 条漏洞 → 生成报告，报告中**仅**含这 3 条，且头部统计 = 3
- [ ] 按「严重级别 = HIGH 且 来源 = LLM」筛选 → 生成的 PDF 内容与筛选结果一致
- [ ] 全量导出（不传 spec）→ 与改造前输出一致（向后兼容）
- [ ] `finding_ids` 中混入其他扫描的 id → 返回 400/403，不泄漏数据
- [ ] 导出文件名能区分不同口径，不互相覆盖
- [ ] 大扫描（>2000 条）导出 PDF → 返回明确提示而非超时/崩溃

---

## 七、实现进度

### Phase 1 — 已完成

**后端**

| 文件 | 改动 |
|---|---|
| `app/schemas.py` | 新增 `ReportFilters` / `ReportInclude` / `ReportSpec` / `ReportPreviewOut` |
| `app/services/report_service.py` | `build_scan_report_payload(session, scan_id, spec=None)` 支持范围收敛；新增 `_stats_from_findings()` 统计重算、`_match_filters()`、`_sort_findings()`、`_group_findings()`、`_load_retest_map()`、`build_scan_report_preview()`；文件名改为 `{项目}-{口径}-scan-{id}-{时间戳}.{ext}` |
| `app/routers/scans.py` | 新增 5 个 POST 端点（`report/preview` / `report.html` / `report.pdf` / `report.md` / `report.json`），保留原 4 个 GET 端点 |

**前端**

| 文件 | 改动 |
|---|---|
| `src/api.ts` | 新增 `postHtml` / `postBlob`；新增 `previewScanReport` 与 `openScanReportWithSpec` / `downloadScanReport*WithSpec`；新增 `ReportSpec` / `ReportPreview` 等类型 |
| `src/components/ReportBuilderModal.tsx` | **新增**。三段式：范围（全部 / 仅已勾选 / 按当前筛选）→ 内容开关 → 版式（标题 / 分组 / 排序），带防抖实时预览；偏好写入 localStorage |
| `src/components/AuditReportHeader.tsx` | 「生成报告」升为主按钮，原 4 个全量导出收进「快速导出全量」折叠区；接入弹窗 |
| `src/components/ScanDetailView.tsx` | 把已有的 `selectedFindingIds` 与列表筛选条件（memo 后）透传给报告头部 |

**Phase 2 已提前完成的部分**

- `_finding_payload` 补齐 `poc` / `remediation` / `retest` / `external_status` / `vuln_subtype` / `vuln_subtype_name`
- HTML / PDF / Markdown 三个渲染器都支持分组与新增字段
- PDF 改走 `asyncio.to_thread`，并加 2000 条上限
- 导出文件名带口径与时间戳

**顺带修掉的一个既有缺陷**

原 `select(Finding).order_by(Finding.severity.desc())` 对字符串枚举实际是**按字母序**排（UNKNOWN > MEDIUM > LOW > INFO > HIGH > CRITICAL），报告里 Critical 并不在最前。现在改为按 `_SEVERITY_RANK` 显式排序。

### 尚未实现（Phase 2 剩余 / Phase 3）

- 报告邮件发送自定义范围（现有邮件链路仍走全量 GET）
- 报告模板配置（公司名 / Logo / 页眉页脚）
- 渲染逻辑去重（MD / PDF / 模板 JS 各自算一遍分布）
- 报告持久化与分享链接 —— 已按「勾选即导出」决策**主动不做**

### 验证结果

- 新增 `tests/test_report_custom_scope.py`（24 项，纯函数）与 `tests/test_report_scope_db.py`（6 项，内存库集成）
- 重点覆盖：**头部统计 == 明细条数**、**跨扫描 finding_ids 被拒绝**、误报开关、排序与分组
- 后端 93 项测试全绿（1 项跳过：本机未装 WeasyPrint）
- 前端 `tsc --noEmit` 与 `vite build` 均通过；渲染出的 HTML 报告内联脚本通过 `node --check`
