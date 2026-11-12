import type { Finding, ReviewStatus } from "../api";
import { displayMessage, shortPath } from "../lib/findingUtils";
import {
  CategoryBadge,
  OwaspBadge,
  ReviewBadge,
  ReviewMarkButtons,
  SeverityBadge,
  SubtypeBadge,
  ToolbarButton,
  VerdictBadge,
} from "./ui";

interface Props {
  findings: Finding[];
  onOpen: (finding: Finding) => void;
  onReview: (findingId: number, status: ReviewStatus) => void;
  reviewingId?: number | null;
}

export function FindingListTable({ findings, onOpen, onReview, reviewingId }: Props) {
  if (findings.length === 0) {
    return (
      <p className="p-12 text-center text-slate-500 text-sm">暂无发现</p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-slate-500 border-b border-surface-border bg-surface/50">
            <th className="px-4 py-3 font-medium w-24">严重度</th>
            <th className="px-4 py-3 font-medium w-28 hidden md:table-cell">OWASP</th>
            <th className="px-4 py-3 font-medium">问题</th>
            <th className="px-4 py-3 font-medium w-36 hidden lg:table-cell">位置</th>
            <th className="px-4 py-3 font-medium w-24 hidden md:table-cell">标记</th>
            <th className="px-4 py-3 font-medium w-28 hidden xl:table-cell">AI</th>
            <th className="px-4 py-3 font-medium w-44">操作</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-border">
          {findings.map((f) => (
            <tr
              key={f.id}
              className="hover:bg-surface/60 transition-colors group"
            >
              <td className="px-4 py-3 align-top">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="px-4 py-3 align-top hidden md:table-cell">
                <div className="space-y-1">
                  <OwaspBadge owaspId={f.owasp_id} owaspName={f.owasp_name} compact />
                  {f.vuln_subtype && (
                    <SubtypeBadge subtype={f.vuln_subtype} subtypeName={f.vuln_subtype_name} />
                  )}
                </div>
              </td>
              <td className="px-4 py-3 align-top min-w-[200px]">
                <button
                  type="button"
                  className="text-left w-full"
                  onClick={() => onOpen(f)}
                >
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="md:hidden">
                      <OwaspBadge owaspId={f.owasp_id} owaspName={f.owasp_name} compact />
                    </span>
                    <CategoryBadge category={f.category} />
                    <span className="text-[10px] text-slate-600">{f.tool}</span>
                  </div>
                  <p className="font-medium text-slate-200 group-hover:text-accent transition-colors line-clamp-2">
                    {displayMessage(f)}
                  </p>
                  <p className="text-xs text-slate-500 font-mono mt-1 lg:hidden">
                    {shortPath(f.file_path)}:{f.line_start}
                  </p>
                </button>
              </td>
              <td className="px-4 py-3 align-top hidden lg:table-cell">
                <p className="font-mono text-xs text-slate-400 break-all">
                  {shortPath(f.file_path)}
                </p>
                <p className="text-xs text-slate-600">L{f.line_start}</p>
              </td>
              <td className="px-4 py-3 align-top hidden md:table-cell">
                <ReviewBadge status={f.review_status} />
              </td>
              <td className="px-4 py-3 align-top hidden xl:table-cell">
                {f.category === "sast" || f.tool === "llm" ? (
                  <VerdictBadge verdict={f.ai_verdict} />
                ) : (
                  <span className="text-xs text-slate-600">—</span>
                )}
              </td>
              <td className="px-4 py-3 align-top">
                <div className="flex flex-col gap-2">
                  <ToolbarButton onClick={() => onOpen(f)}>查看详情</ToolbarButton>
                  <ReviewMarkButtons
                    compact
                    current={f.review_status}
                    disabled={reviewingId === f.id}
                    onMark={(status) => onReview(f.id, status)}
                  />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
