import { FindingDetailView } from "../../components/FindingDetailView";
import { ScanDetailView } from "../../components/ScanDetailView";
import { navigate } from "../../app/router";

interface Props {
  scanId: number;
  projectId: number | null;
  findingId: number | null;
  /** Which canonical route family owns this workspace. */
  base: "project" | "task";
  refreshKey: number;
  onDataChanged: () => void;
}

/**
 * Preserves the pre-refactor scan detail experience (report, findings,
 * copilot, chat) inside the new shell. FindingDetailView is rendered as an
 * overlay while ScanDetailView stays mounted so scroll position survives.
 */
export function ScanWorkspace({
  scanId,
  projectId,
  findingId,
  base,
  refreshKey,
  onDataChanged,
}: Props) {
  const withBase = (scan: number, params?: URLSearchParams): string => {
    const suffix = params?.size ? `?${params}` : "";
    if (base === "project" && projectId) return `/projects/${projectId}${suffix}`;
    return `/tasks/${scan}${suffix}`;
  };

  const openFinding = (finding: number, scan = scanId, owner: number | null = projectId) => {
    const params = new URLSearchParams();
    if (base === "project" && owner) params.set("scan", String(scan));
    params.set("finding", String(finding));
    navigate(base === "project" && owner ? `/projects/${owner}?${params}` : `/tasks/${scan}?finding=${finding}`);
  };

  const backToList = () => navigate(base === "project" && projectId ? `/projects/${projectId}` : "/tasks");

  return (
    <div className="relative flex h-full min-h-0 w-full flex-col">
      <div
        className={
          findingId
            ? "invisible pointer-events-none absolute inset-0 flex min-h-0 flex-col"
            : "flex h-full min-h-0 flex-col"
        }
        aria-hidden={Boolean(findingId)}
      >
        <ScanDetailView
          key={scanId}
          scanId={scanId}
          refreshKey={refreshKey}
          isActive={!findingId}
          onDeleted={() => {
            onDataChanged();
            backToList();
          }}
          onScanUpdated={onDataChanged}
          onOpenFinding={(finding) => openFinding(finding)}
          onSelectScan={(id, owner) => {
            const params = new URLSearchParams();
            if (base === "project" && (owner ?? projectId)) params.set("scan", String(id));
            navigate(
              base === "project" && (owner ?? projectId)
                ? `/projects/${owner ?? projectId}${params.size ? `?${params}` : ""}`
                : `/tasks/${id}`,
            );
          }}
          onOpenScanFinding={(scan, finding, owner) => openFinding(finding, scan, owner ?? null)}
          onAppendVersion={(owner) => navigate(`/projects/new?appendProjectId=${owner}`)}
        />
      </div>

      {findingId && (
        <main className="grid-bg relative z-10 h-full min-h-0 overflow-auto p-6">
          <FindingDetailView
            scanId={scanId}
            findingId={findingId}
            onBack={() => {
              const params = new URLSearchParams();
              if (base === "project") params.set("scan", String(scanId));
              navigate(withBase(scanId, params), true);
            }}
          />
        </main>
      )}
    </div>
  );
}
