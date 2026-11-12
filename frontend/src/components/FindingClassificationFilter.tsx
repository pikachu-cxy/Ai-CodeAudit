import type { ScanStats } from "../api";
import {
  OWASP_ORDER,
  OWASP_TOP10,
  SUBTYPE_LABELS,
  subtypesForOwasp,
} from "../lib/owaspUtils";

interface Props {
  stats: ScanStats;
  filterOwasp: string;
  filterSubtype: string;
  onOwaspChange: (owaspId: string) => void;
  onSubtypeChange: (owaspId: string, subtypeId: string) => void;
}

export function FindingClassificationFilter({
  stats,
  filterOwasp,
  filterSubtype,
  onOwaspChange,
  onSubtypeChange,
}: Props) {
  const subtypeCounts = filterOwasp
    ? subtypesForOwasp(filterOwasp)
        .map((id) => ({
          id,
          count: stats.by_owasp_subtype?.[filterOwasp]?.[id] || 0,
        }))
        .filter((x) => x.count > 0)
    : [];

  const activeOwaspTotal = filterOwasp ? stats.by_owasp?.[filterOwasp] || 0 : stats.total;

  return (
    <div className="space-y-2.5 py-3 border-b border-surface-border">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-xs text-slate-500 shrink-0 w-14">漏洞分类</span>
        <div className="flex flex-wrap gap-1.5 flex-1 min-w-0">
          <button
            type="button"
            className={!filterOwasp ? "filter-chip filter-chip-active" : "filter-chip"}
            onClick={() => onOwaspChange("")}
          >
            全部
            <span className="ml-1 opacity-70">{stats.total}</span>
          </button>
          {OWASP_ORDER.map((id) => {
            const count = stats.by_owasp?.[id] || 0;
            if (count === 0) return null;
            const active = filterOwasp === id;
            return (
              <button
                key={id}
                type="button"
                title={OWASP_TOP10[id]}
                className={active ? "filter-chip filter-chip-active" : "filter-chip"}
                onClick={() => onOwaspChange(active ? "" : id)}
              >
                <span className="font-mono">{id}</span>
                <span className="ml-1 hidden sm:inline">{OWASP_TOP10[id]}</span>
                <span className="ml-1 opacity-70">{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {filterOwasp && subtypeCounts.length > 0 && (
        <div className="flex items-start gap-3 flex-wrap pl-0 sm:pl-[3.75rem]">
          <span className="text-[10px] text-slate-600 shrink-0 pt-1">子类</span>
          <div className="flex flex-wrap gap-1.5 flex-1">
            <button
              type="button"
              className={!filterSubtype ? "filter-chip-sub filter-chip-sub-active" : "filter-chip-sub"}
              onClick={() => onSubtypeChange(filterOwasp, "")}
            >
              全部
              <span className="ml-1 opacity-80">{activeOwaspTotal}</span>
            </button>
            {subtypeCounts.map(({ id, count }) => {
              const active = filterSubtype === id;
              return (
                <button
                  key={id}
                  type="button"
                  className={active ? "filter-chip-sub filter-chip-sub-active" : "filter-chip-sub"}
                  onClick={() => onSubtypeChange(filterOwasp, active ? "" : id)}
                >
                  {SUBTYPE_LABELS[id] || id}
                  <span className="ml-1 opacity-80">{count}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {(filterOwasp || filterSubtype) && (
        <p className="text-[11px] text-slate-600 sm:pl-[3.75rem]">
          当前：
          <span className="text-slate-400 ml-1">
            {filterOwasp ? `${filterOwasp} ${OWASP_TOP10[filterOwasp]}` : "全部"}
            {filterSubtype && (
              <>
                <span className="mx-1 text-slate-600">/</span>
                {SUBTYPE_LABELS[filterSubtype]}
              </>
            )}
          </span>
        </p>
      )}
    </div>
  );
}
