import type { Finding } from "../api";

export type InheritedFpKind = "strict" | "relaxed";

export function inheritedFpKind(finding: Finding): InheritedFpKind | null {
  const note = (finding.review_note || "").trim();
  if (note.startsWith("继承历史误报")) return "strict";
  const reason = (finding.ai_reason || "").trim();
  if (reason.startsWith("疑似继承历史误报")) return "relaxed";
  return null;
}

export function inheritedFpLabel(kind: InheritedFpKind): string {
  return kind === "strict" ? "继承误报" : "疑似重复";
}
