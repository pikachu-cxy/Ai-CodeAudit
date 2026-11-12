import { SettingsModal, SYSTEM_SECTIONS } from "../../components/SettingsModal";
import type { PageContext } from "../../app/pageTypes";

/**
 * Routed System Management page.
 *
 * Uses the category shell (`layout="categories"`) instead of embedding the
 * legacy settings modal. The config form logic is shared with the modal so
 * every original setting, test action and save semantic stays intact.
 *
 * LLM API/model sections are owned by /llm, audit skills by /skills.
 */
export function SystemPage({ onDataChanged }: PageContext) {
  return (
    <div className="h-full min-h-0 w-full">
      <SettingsModal
        open={false}
        embedded
        layout="categories"
        sections={SYSTEM_SECTIONS}
        onClose={() => undefined}
        onSaved={onDataChanged}
      />
    </div>
  );
}
