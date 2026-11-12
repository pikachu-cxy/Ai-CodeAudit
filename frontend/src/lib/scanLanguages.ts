/** Allowed project scan language ids (must match backend ALLOWED_SCAN_LANGUAGES). */
export const SCAN_LANGUAGE_OPTIONS: { id: string; label: string }[] = [
  { id: "java", label: "Java" },
  { id: "python", label: "Python" },
  { id: "javascript", label: "JavaScript" },
  { id: "typescript", label: "TypeScript" },
  { id: "go", label: "Go" },
  { id: "php", label: "PHP" },
  { id: "ruby", label: "Ruby" },
  { id: "csharp", label: "C#" },
  { id: "kotlin", label: "Kotlin" },
  { id: "rust", label: "Rust" },
];

export const SCAN_LANGUAGE_LABELS: Record<string, string> = Object.fromEntries(
  SCAN_LANGUAGE_OPTIONS.map((o) => [o.id, o.label])
);

export function formatScanLanguages(ids: string[] | null | undefined): string {
  if (!ids?.length) return "";
  return ids.map((id) => SCAN_LANGUAGE_LABELS[id] || id).join("、");
}
