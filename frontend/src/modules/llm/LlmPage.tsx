import { SettingsModal, type SettingsSection } from "../../components/SettingsModal";
import type { PageContext } from "../../app/pageTypes";

const SECTIONS: SettingsSection[] = ["llm-api", "llm-models", "llm-auto", "deep-audit-budget"];

export function LlmPage({ onDataChanged }: PageContext) {
  return (
    <div className="flex h-full min-h-0 w-full flex-col gap-3 p-4">
      <div className="shrink-0">
        <h1 className="text-xl font-semibold tracking-tight">LLM 设置</h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          配置模型、API 连接、扫描自动化和 Deep Audit V1 的执行预算。
        </p>
      </div>
      <div className="min-h-0 flex-1">
        <SettingsModal
          open={false}
          embedded
          title="LLM 设置"
          sections={SECTIONS}
          initialSection="llm-api"
          onClose={() => undefined}
          onSaved={onDataChanged}
        />
      </div>
    </div>
  );
}
