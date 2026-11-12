import { ArrowUpRight, FileCode2, ListTodo, Puzzle, Settings2 } from "lucide-react";
import { api, type AuditSkill } from "../../api";
import { navigate } from "../../app/router";
import type { PageContext } from "../../app/pageTypes";
import { AuditSkillManager } from "../../components/AuditSkills";
import { useAsyncData } from "../../shared/hooks/useAsyncData";
import {
  ErrorState,
  KeyValueRow,
  LoadingState,
  MonoMeta,
  PageHeader,
  SectionCard,
  StatusPill,
} from "../../shared/ui";
import { CapabilityNotice } from "../../shared/ui/forms";

const ENTRIES = [
  {
    label: "扫描任务",
    description: "从任务列表进入扫描详情页，用「深度审计」按钮发起 Skill 审计并查看真实运行记录。",
    icon: ListTodo,
    route: "/tasks",
  },
  {
    label: "项目详情",
    description: "在项目详情页选择扫描版本，进入同一个 Skill 审计入口。",
    icon: FileCode2,
    route: "/projects",
  },
  {
    label: "系统管理",
    description: "LLM 深度审计参数、文件采样上限与审计策略分类配置。",
    icon: Settings2,
    route: "/system",
  },
  {
    label: "LLM 设置",
    description: "Skill 审计实际使用的模型、API 连接与任务级模型覆盖。",
    icon: Puzzle,
    route: "/llm",
  },
];

export function SkillsPage(ctx: PageContext) {
  const skills = useAsyncData<AuditSkill[]>(() => api.listAuditSkills(), [ctx.refreshKey]);
  const rows = skills.data ?? [];
  const enabled = rows.filter((row) => row.enabled).length;
  const tools = Array.from(new Set(rows.flatMap((row) => row.manifest?.tools ?? []))).sort();
  const archetypes = Array.from(
    new Set(rows.flatMap((row) => row.manifest?.applies_to?.archetypes ?? [])),
  ).sort();
  const skillsUnavailable = Boolean(skills.error) && /404|not found/i.test(skills.error ?? "");
  const showManager = !skills.loading && skills.error === null;

  return (
    <div className="page-container space-y-4">
      <PageHeader
        eyebrow="Platform / Skills"
        title="Skill 管理"
        description="审计技能包的安装、启用与默认配置梳理，并汇总 Skill 审计的真实入口。"
        actions={
          <button type="button" className="btn-action inline-flex items-center gap-1" onClick={() => navigate("/tasks")}>
            前往扫描任务 <ArrowUpRight className="h-3.5 w-3.5" />
          </button>
        }
      />

      <CapabilityNotice title="本页负责技能包管理，Skill 执行发生在扫描详情页" tone="cyan">
        安装、校验、启用和默认配置都复用既有 <MonoMeta>AuditSkillManager</MonoMeta> 组件的真实接口。
        真正发起 Skill 审计的入口在扫描详情页的「深度审计」按钮（<MonoMeta>SkillAuditDialog</MonoMeta>），
        运行记录由 <MonoMeta>SkillAuditHistory</MonoMeta> 展示。本页不重复实现执行逻辑，也不伪造技能包列表。
      </CapabilityNotice>

      <SectionCard title="现有能力概览" description="来自 /api/skills 的真实返回；接口不可用时显示真实错误，不填充示例数据。">
        {skills.loading ? (
          <LoadingState label="正在读取技能包…" />
        ) : skills.error ? (
          skillsUnavailable ? (
            <div className="space-y-3 rounded-lg border border-amber-500/25 bg-amber-500/5 px-4 py-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusPill tone="warning">后端未部署</StatusPill>
                <span className="text-sm">当前后端未注册 <MonoMeta>/api/skills</MonoMeta> 路由，技能包列表无法读取。</span>
              </div>
              <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
                接口真实返回：<MonoMeta>{skills.error}</MonoMeta>。技能包后端目前位于
                <MonoMeta>codex/audit-skills-local</MonoMeta> 分支，master 尚未合并；本页不会用示例数据填充，
                也不会显示假的「已安装 Skill」。部署后重新检测即会展示真实的技能包、工具声明与适用项目形态。
              </p>
              <button type="button" className="btn-action" onClick={() => skills.reload()}>重新检测</button>
            </div>
          ) : (
            <ErrorState message={skills.error} onRetry={() => skills.reload()} />
          )
        ) : (
          <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
            <KeyValueRow label="已安装技能包"><MonoMeta>{rows.length}</MonoMeta></KeyValueRow>
            <KeyValueRow label="已启用"><MonoMeta>{enabled}</MonoMeta></KeyValueRow>
            <KeyValueRow label="声明的工具">
              {tools.length ? <MonoMeta>{tools.join(" / ")}</MonoMeta> : <StatusPill tone="muted">无</StatusPill>}
            </KeyValueRow>
            <KeyValueRow label="适用项目形态">
              {archetypes.length ? <MonoMeta>{archetypes.join(" / ")}</MonoMeta> : <StatusPill tone="muted">无</StatusPill>}
            </KeyValueRow>
            <div className="md:col-span-2 pt-2 text-xs leading-relaxed text-[var(--text-muted)]">
              技能包后端可能尚未部署在当前分支；此时上方会显示真实的接口错误，而不会回退到静态占位数据。
            </div>
          </div>
        )}
      </SectionCard>

      <SectionCard title="Skill 相关入口" description="只链接到系统中真实存在的页面与操作，不新增假的「运行 Skill」按钮。">
        <div className="grid gap-2 md:grid-cols-2">
          {ENTRIES.map((entry) => (
            <button
              key={entry.route}
              type="button"
              className="flex items-start gap-3 rounded-lg border border-surface-border px-3 py-3 text-left transition-colors hover:bg-[var(--hover-overlay)]"
              onClick={() => navigate(entry.route)}
            >
              <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-surface-border bg-[var(--bg-muted)] text-cyan-500">
                <entry.icon className="h-4 w-4" />
              </span>
              <span className="min-w-0">
                <span className="flex items-center gap-1 text-sm font-medium">
                  {entry.label} <ArrowUpRight className="h-3 w-3 text-[var(--text-faint)]" />
                </span>
                <span className="mt-1 block text-xs leading-relaxed text-[var(--text-secondary)]">{entry.description}</span>
                <MonoMeta>{entry.route}</MonoMeta>
              </span>
            </button>
          ))}
        </div>
      </SectionCard>

      <SectionCard
        title="已安装的 Skill"
        description="上传、校验、安装、启用与默认配置均由原有组件调用真实后端接口完成。"
      >
        {showManager ? (
          <AuditSkillManager />
        ) : (
          <div className="rounded-lg border border-dashed border-surface-border px-4 py-6 text-center text-xs leading-relaxed text-[var(--text-secondary)]">
            {skills.loading ? (
              "正在等待技能包接口响应…"
            ) : (
              <>
                <MonoMeta>/api/skills</MonoMeta> 不可用，暂不加载 <MonoMeta>AuditSkillManager</MonoMeta>，
                避免对同一缺失接口重复报错。接口恢复后此处会自动启用真实的上传 / 校验 / 安装 / 启用操作。
              </>
            )}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
