# 代码权属与第三方许可证审查（未结案）

> **结论：本仓库当前不满足公开发布条件。** 未添加任何 `LICENSE` / `NOTICE` 文件，
> 也不构成任何明示或默示的授权。在完成权属确认并取得必要再许可授权前，
> 不得把本仓库设为 Public、不得发布 Release、不得推送到公共平台。

## 1. 为什么暂缓确定许可证

所有者倾向 Apache-2.0，但 Apache-2.0 要求贡献者拥有对全部源码的版权或足够的再许可权限。
本仓库源码来自两个既有的、含企业内部交付背景的仓库，且没有逐文件版权头、没有贡献者协议（CLA）、
没有公司出具的开源授权文件。在以下事项确认前添加许可证会形成**无法撤回的权利声明错误**：

| 待确认项 | 当前状态 | 阻断级别 |
| --- | --- | --- |
| 全部源码的著作权归属（个人 / 公司 / 混合） | 无书面材料 | **阻断公开** |
| 公司是否授权以 Apache-2.0 再许可 | 无书面材料 | **阻断公开** |
| 是否存在客户/项目交付中产生的受限代码 | 无法排除 | **阻断公开** |
| 贡献者名单与 CLA / DCO | 缺失 | 需补齐 |
| 原仓库 `master` 历史中的内部标识与凭据 | 已通过「全新快照」隔离，见 `SECURITY_REVIEW.md` | 已隔离，但原仓库仍为私有 |

**建议做法**：由权利人以书面形式确认可开源范围与许可证，逐文件核对 `samples/`、
`docs/`、CI 脚本与从其他项目借鉴的算法/规则表，再决定是否添加 `LICENSE`、`NOTICE` 与版权头。

## 2. 第三方依赖许可证盘点

### 2.1 前端（npm，`frontend/package-lock.json` lockfileVersion 3）

- 直接依赖：`react` / `react-dom` / `lucide-react` / `recharts`；构建期：`vite`、`typescript`、`tailwindcss`、`postcss`、`autoprefixer`、`@vitejs/plugin-react`、`@types/*`。
- lockfile 中 225 个包条目，224 个带 `license` 字段，分布：MIT 193、ISC 22、Apache-2.0 4、BSD-3-Clause 3、CC-BY-4.0 1（`caniuse-lite`，数据许可）、`MIT AND ISC` 1（`victory-vendor`）。
- 224 条 `"resolved"` 全部指向 `registry.npmjs.org`，**无私有 registry、无 `file:`/`git:` 依赖**。
- 需要留意但通常不构成发布阻断：`caniuse-lite` 的 CC-BY-4.0 数据需在分发时保留归属说明；`typescript`、`baseline-browser-mapping` 等为 Apache-2.0。

### 2.2 后端（PyPI，`backend/requirements.txt`，16 个直接依赖）

| 依赖 | 许可证（已安装元数据） | 依赖 | 许可证 |
| --- | --- | --- | --- |
| fastapi | MIT（classifier: OSI Approved） | sqlalchemy | MIT |
| uvicorn[standard] | BSD-3-Clause | aiosqlite | MIT（OSI Approved） |
| python-multipart | Apache-2.0 | asyncmy | Apache-2.0 |
| httpx | BSD-3-Clause | pydantic-settings | MIT |
| openai | Apache-2.0 | aiofiles | Apache-2.0 |
| python-dotenv | BSD-3-Clause | PyJWT | MIT |
| bcrypt | Apache-2.0 | bandit | Apache-2.0 |
| pip-audit | Apache-2.0（OSI Approved） | PyYAML | MIT |
| weasyprint | BSD-3-Clause（OSI Approved） | | |

均为宽松许可证，未发现 GPL/AGPL/SSPL 等强传染性直接依赖。

### 2.3 构建期安装的外部工具（不随源码分发，随镜像分发）

| 工具 | 来源 | 说明 |
| --- | --- | --- |
| gitleaks | GitHub Release（官方仓库） | Apache-2.0 / MIT 双许可，镜像内二进制 |
| osv-scanner | GitHub Release（Google 官方仓库） | Apache-2.0，镜像内二进制 |
| CodeQL CLI | GitHub Release（`github/codeql-cli-binaries`） | **有使用条款限制**：仅可用于对开源代码或自有代码的安全研究/测试，商业用途受限，需单独确认 |
| semgrep | PyPI `semgrep` | LGPL-2.1 等，需确认 `--target` 隔离安装与再分发边界 |
| OpenJDK / Maven / nodejs / npm / Debian 系统库 | Debian bookworm 官方源 | 各包自有许可证，随基础镜像分发 |

> **待人工确认**：CodeQL CLI 与 semgrep 的许可条款是否允许随本项目的公开镜像分发；
> 若不允许，应改为「首次启动时按需下载」或提供不预装的镜像变体。

## 3. 仓库内第三方代码与样例

- 未发现 `vendor/`、`third_party/` 目录，未发现 vendored 源码或复制粘贴的第三方实现（基于文件清单与依赖清单核对）。
- `backend/samples/vulnerable-app.zip`（534 字节）与 `samples/vulnerable-app/requirements.txt` 是**故意包含漏洞的最小演示样例**，用于验证扫描器。
  - 权属未逐字节确认；发布前需确认其来源，或重写为明确标注为本项目原创的样例。
  - `docs`/README 中已标注其为演示样例，**不得当作真实业务代码**。
- `backend/INSTALL.md`、`backend/docs/SSO_RBAC_HANDOFF.md` 等文档已改为公开示例，但文档原型来源于内部交付材料，权属同样需要确认。

## 4. 发布阻断项汇总

1. **无 `LICENSE` / `NOTICE`，权属与再许可权限未确认** —— 阻断。
2. **CodeQL CLI / semgrep 随镜像分发的许可边界未确认** —— 阻断镜像公开发布。
3. `samples/vulnerable-app.zip` 与文档原型来源未逐项确认 —— 待确认。
4. 历史凭据轮换未闭环 —— 见 `TOKEN_ROTATION.md`，不改变本快照的干净性，但影响原私有仓库的处置。

> 本报告只记录审查事实与待办，**不代替法律意见**。最终是否开源、采用何种许可证，须由权利人书面决定。
