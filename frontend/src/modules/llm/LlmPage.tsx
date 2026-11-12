import { SettingsModal, type SettingsSection } from "../../components/SettingsModal";
import type { PageContext } from "../../app/pageTypes";

/** LLM settings live in a real page now, but reuse the original save logic. */
const SECTIONS: SettingsSection[] = ["llm-api", "llm-models", "llm-auto"];

export function LlmPage({ onDataChanged }: PageContext) {
  return (
    <div className="flex h-full min-h-0 w-full flex-col gap-3 p-4">
      <div className="shrink-0">
        <h1 className="text-xl font-semibold tracking-tight">LLM 设置</h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          模型、API 连接与扫描后自动化。沿用原有系统设置的保存与测试逻辑，API Key 不会回显。
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
