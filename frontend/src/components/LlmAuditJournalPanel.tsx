import { useMemo, type ReactNode } from "react";
import type { LlmAuditJournalEntry, ScanSummary } from "../api";

const TYPE_LABELS: Record<string, string> = {
  plan: "审计方案",
  inventory: "端点清单",
  business_model: "业务理解",
  settings_snapshot: "策略快照",
  domain_selection: "域选择",
  investigation_trace: "调查轨迹",
  tool_round: "代码调查",
  findings_batch: "提交发现",
  candidate_batch: "高风险候选",
  suppressed_findings_summary: "抑制入库",
  finish_reason: "结束原因",
  coverage_summary: "覆盖摘要",
  controller_start: "开始审计",
  controller_done: "审计完成",
  controller_error: "审计失败",
  cancelled: "已暂停",
  complete: "全部完成",
  bootstrap_done: "自动预调查",
  bootstrap_tool: "预调查",
  high_risk_sink_pass: "高危 sink 预检索",
  iteration_limit: "安全上限",
  salvage_finish: "迭代收尾",
  error: "错误",
};

interface Props {
  scan: ScanSummary | null;
  entries: LlmAuditJournalEntry[];
  onPause?: () => void;
  pausing?: boolean;
}

type ArchPayload = {
  overview?: string;
  pipeline?: string[];
  layers?: string[];
  data_flow?: string;
};

export function LlmAuditJournalPanel({ scan, entries, onPause, pausing }: Props) {
  const isRunning = scan?.status === "llm_auditing";
  const progress = scan?.progress ?? 0;

  const plan = useMemo(() => entries.find((e) => e.type === "plan"), [entries]);
  const inventory = useMemo(() => entries.find((e) => e.type === "inventory"), [entries]);
  const businessModel = useMemo(
    () => [...entries].reverse().find((e) => e.type === "business_model"),
    [entries],
  );
  const iterationLimit = useMemo(
    () => [...entries].reverse().find((e) => e.type === "iteration_limit"),
    [entries],
  );
  const settingsSnapshot = useMemo(
    () => entries.find((e) => e.type === "settings_snapshot"),
    [entries],
  );
  const domainSelection = useMemo(
    () => entries.find((e) => e.type === "domain_selection"),
    [entries],
  );
  const doneFiles = useMemo(() => {
    const set = new Set<string>();
    for (const e of entries) {
      if (e.type === "controller_done" && e.payload.file) {
        set.add(String(e.payload.file));
      }
    }
    return set;
  }, [entries]);

  const startedFile = useMemo(() => {
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i];
      if (e.type === "controller_start") return String(e.payload.file || "");
    }
    return "";
  }, [entries]);

  const progressStats = useMemo(() => {
    const inv = inventory?.payload;
    const total = Number(inv?.controller_count ?? 0);
    const done = doneFiles.size;
    return { total, done, current: startedFile };
  }, [inventory, doneFiles, startedFile]);

  if (!isRunning && entries.length === 0) return null;

  const arch = (plan?.payload?.architecture as ArchPayload) || {};

  const summaryHint = isRunning
    ? [
        progress > 0 ? `${progress}%` : null,
        progressStats.total > 0 ? `Controller ${progressStats.done}/${progressStats.total}` : null,
      ]
        .filter(Boolean)
        .join(" · ")
    : entries.length > 0
      ? `${entries.length} 条记录`
      : "";

  return (
    <details className="audit-panel p-4">
      <summary className="text-sm font-medium text-slate-300 cursor-pointer">
        LLM 端点审计日志
        {summaryHint && (
          <span className="ml-2 text-xs font-normal text-slate-500">{summaryHint}</span>
        )}
      </summary>

      <div className="mt-3 space-y-3 text-xs">
        {(scan?.progress_message || isRunning) && (
          <div className="flex items-center justify-between gap-3 flex-wrap">
            {scan?.progress_message && (
              <p className="text-slate-400">{scan.progress_message}</p>
            )}
            <div className="flex items-center gap-2 ml-auto">
              {isRunning && onPause && (
                <button
                  type="button"
                  className="btn-action text-xs px-3 py-1.5 border-surface-border/80 text-slate-200 hover:bg-white/5"
                  disabled={pausing}
                  onClick={onPause}
                >
                  {pausing ? "暂停中…" : "暂停审计"}
                </button>
              )}
              {(isRunning || progress > 0) && (
                <span className="text-xs font-mono text-slate-200">{progress}%</span>
              )}
            </div>
          </div>
        )}

        {isRunning && (
          <div>
            <div className="h-1.5 bg-surface rounded-full overflow-hidden">
              <div
                className="h-full bg-slate-200/70 transition-all duration-500"
                style={{ width: `${Math.min(100, progress)}%` }}
              />
            </div>
            <p className="text-[10px] text-slate-400 mt-1">
              暂停将在当前 Controller 的 LLM 调用完成后生效
            </p>
          </div>
        )}

        {progressStats.total > 0 && (
          <p className="text-[11px] text-slate-300 font-mono">
            Controller 进度 {progressStats.done}/{progressStats.total}
            {isRunning && progressStats.current && (
              <span className="text-slate-400 ml-2 truncate max-w-[320px] inline-block align-bottom">
                当前: {progressStats.current.split("/").pop()}
              </span>
            )}
          </p>
        )}

        <div className="max-h-[28rem] overflow-y-auto space-y-3">
        {plan && (
          <JournalBlock entry={plan}>
            {arch.overview && (
              <p className="text-slate-400 mt-1">{arch.overview}</p>
            )}
            {arch.data_flow && (
              <p className="text-[10px] text-slate-500 mt-2 font-mono">{arch.data_flow}</p>
            )}
            {arch.pipeline && arch.pipeline.length > 0 && (
              <details className="mt-2" open={isRunning}>
                <summary className="text-slate-200 cursor-pointer">审计流水线</summary>
                <ol className="list-decimal list-inside text-slate-400 space-y-0.5 mt-1">
                  {arch.pipeline.map((line, i) => (
                    <li key={`pipe-${i}`}>{line}</li>
                  ))}
                </ol>
              </details>
            )}
            {arch.layers && arch.layers.length > 0 && (
              <details className="mt-2">
                <summary className="text-slate-200 cursor-pointer">系统架构 / 分析层次</summary>
                <ul className="list-disc list-inside text-slate-500 space-y-0.5 mt-1">
                  {arch.layers.map((line, i) => (
                    <li key={`layer-${i}`}>{line}</li>
                  ))}
                </ul>
              </details>
            )}
            <ul className="list-disc list-inside text-slate-500 space-y-0.5 mt-2">
              {((plan.payload.methodology as string[]) || []).map((line, i) => (
                <li key={`m-${i}`}>{line}</li>
              ))}
            </ul>
          </JournalBlock>
        )}

        {inventory && (
          <JournalBlock entry={inventory}>
            <p className="text-slate-500 mt-1">
              共 {String(inventory.payload.controller_count ?? "?")} 个 Controller、
              {String(inventory.payload.endpoint_count ?? "?")} 个端点
            </p>
            {((inventory.payload.business_domains as Array<Record<string, unknown>>) || []).length > 0 && (
              <details className="mt-2" open={isRunning}>
                <summary className="text-slate-200 cursor-pointer">业务域聚类（Origin）</summary>
                <div className="mt-2 space-y-2">
                  {((inventory.payload.business_domains as Array<Record<string, unknown>>) || []).map((d, i) => (
                    <div key={`dom-${i}`} className="rounded border border-surface-border/70 bg-black/20 p-2">
                      <p className="text-slate-300">
                        {String(d.domain)}{" "}
                        <span className="text-slate-500">({String(d.endpoint_count)} 端点)</span>
                      </p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {((d.sample_endpoints as Array<Record<string, unknown>>) || []).slice(0, 4).map((ep, j) => (
                          <span key={`dom-ep-${i}-${j}`} className="text-[10px] font-mono text-slate-400">
                            {String(ep.method)} {String(ep.path)}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            )}
            <details className="mt-2">
              <summary className="text-slate-200 cursor-pointer">高敏端点</summary>
              <div className="mt-2 flex flex-wrap gap-1">
                {((inventory.payload.top_sensitive_endpoints as Array<Record<string, unknown>>) || []).map((ep, i) => (
                  <span key={`sen-${i}`} className="text-[10px] px-1 py-0.5 rounded bg-white/5 text-slate-200 font-mono">
                    {String(ep.http_method || ep.method)} {String(ep.path || ep.handler)}
                  </span>
                ))}
              </div>
            </details>
          </JournalBlock>
        )}

        {businessModel && (
          <JournalBlock entry={businessModel}>
            {Boolean(businessModel.payload.app_summary) && (
              <p className="text-slate-300 mt-1 leading-relaxed">{String(businessModel.payload.app_summary)}</p>
            )}
            {((businessModel.payload.investigation_priorities as Array<Record<string, unknown>>) || []).length > 0 && (
              <details className="mt-2" open={isRunning}>
                <summary className="text-slate-200 cursor-pointer">调查优先级（假设待验证）</summary>
                <ul className="mt-2 space-y-2">
                  {((businessModel.payload.investigation_priorities as Array<Record<string, unknown>>) || []).map((p, i) => (
                    <li key={`pri-${i}`} className="rounded border border-surface-border/70 bg-black/20 p-2 text-slate-400">
                      <p className="text-slate-200">{String(p.target)}</p>
                      {Boolean(p.hypothesis) && <p className="text-[11px] mt-0.5">假设：{String(p.hypothesis)}</p>}
                      {Boolean(p.reason) && <p className="text-[10px] text-slate-500">{String(p.reason)}</p>}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </JournalBlock>
        )}

        {settingsSnapshot && (
          <JournalBlock entry={settingsSnapshot}>
            <div className="mt-1 grid grid-cols-2 md:grid-cols-3 gap-2 text-[11px]">
              <InfoChip label="档位" value={String(settingsSnapshot.payload.profile || "balanced")} />
              <InfoChip
                label="强证据"
                value={settingsSnapshot.payload.stronger_evidence ? "开启" : "关闭"}
              />
              <InfoChip
                label="广假设"
                value={settingsSnapshot.payload.broader_hypotheses ? "开启" : "关闭"}
              />
              <InfoChip
                label="总轮次"
                value={String((settingsSnapshot.payload.config as Record<string, unknown>)?.max_iterations ?? "-")}
              />
              <InfoChip
                label="最大域"
                value={String((settingsSnapshot.payload.config as Record<string, unknown>)?.max_domains ?? "-")}
              />
              <InfoChip
                label="收束策略"
                value={String((settingsSnapshot.payload.config as Record<string, unknown>)?.finish_bias ?? "-")}
              />
              {Array.isArray(settingsSnapshot.payload.focus_labels) &&
                (settingsSnapshot.payload.focus_labels as unknown[]).length > 0 && (
                  <InfoChip
                    label="关注重点"
                    value={(settingsSnapshot.payload.focus_labels as string[]).join("、")}
                  />
                )}
            </div>
          </JournalBlock>
        )}

        {domainSelection && (
          <JournalBlock entry={domainSelection}>
            <p className="text-slate-400 mt-1">{String(domainSelection.payload.detail || "")}</p>
            <div className="mt-2 space-y-2">
              {((domainSelection.payload.ranked_domains as Array<Record<string, unknown>>) || []).slice(0, 6).map((d, i) => (
                <div key={`rank-${i}`} className="rounded border border-surface-border/70 bg-black/20 p-2">
                  <p className="text-slate-200">
                    {String(d.domain)} <span className="text-slate-500">score={String(d.score)}</span>
                  </p>
                  <p className="text-[10px] text-slate-500 mt-0.5">
                    高敏 {String(d.high_sensitivity_count)} · 端点 {String(d.endpoint_count)}
                    {Number(d.boost || 0) > 0 ? ` · boost ${String(d.boost)}` : ""}
                  </p>
                  {Array.isArray(d.reasons) && d.reasons.length > 0 && (
                    <p className="text-[10px] text-cyan-200/80 mt-1">{(d.reasons as string[]).join(" / ")}</p>
                  )}
                </div>
              ))}
            </div>
          </JournalBlock>
        )}

        {iterationLimit && !isRunning && (
          <JournalBlock entry={iterationLimit}>
            <p className="mt-1 text-orange-200/90 text-[11px] leading-relaxed">
              {String(iterationLimit.payload.detail || "验证迭代轮次已用尽")}
            </p>
            {Boolean(iterationLimit.payload.audit_summary) && (
              <p className="mt-2 text-slate-400 text-[11px] leading-relaxed">
                {String(iterationLimit.payload.audit_summary)}
              </p>
            )}
            {Number(iterationLimit.payload.findings_so_far) === 0 && (
              <p className="mt-2 text-slate-500 text-[10px]">
                建议在设置中提高「验证阶段安全上限」后重新审计。
              </p>
            )}
          </JournalBlock>
        )}

        {entries
          .filter((e) => !["plan", "inventory", "business_model", "iteration_limit", "settings_snapshot", "domain_selection"].includes(e.type))
          .map((entry) => (
            <JournalBlock key={entry.id} entry={entry}>
              {entry.type === "salvage_finish" && Boolean(entry.payload.audit_summary) && (
                <p className="mt-1 text-slate-300 text-[11px] leading-relaxed">
                  {String(entry.payload.audit_summary)}
                </p>
              )}
              {entry.type === "coverage_summary" && (
                <div className="mt-1 grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
                  <InfoChip label="域数" value={String(((entry.payload.domains_audited as string[]) || []).length)} />
                  <InfoChip label="总轮次" value={String(entry.payload.rounds_used || "-")} />
                  <InfoChip label="工具轮次" value={String(entry.payload.tool_rounds || "-")} />
                  <InfoChip label="候选数" value={String(entry.payload.candidate_count || 0)} />
                </div>
              )}
              {entry.type === "suppressed_findings_summary" && (
                <div className="mt-1 space-y-1">
                  <p className="text-orange-200/90 text-[11px]">{String(entry.payload.detail || "")}</p>
                  {((entry.payload.suppressed_titles as string[]) || []).map((t, i) => (
                    <p key={`sup-${i}`} className="text-[10px] text-slate-400">• {t}</p>
                  ))}
                </div>
              )}
              {entry.type === "finish_reason" && (
                <p className="mt-1 text-slate-300 text-[11px] leading-relaxed">{String(entry.payload.detail || "")}</p>
              )}
              {entry.type === "investigation_trace" && Array.isArray(entry.payload.files) && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {(entry.payload.files as string[]).slice(0, 8).map((f, i) => (
                    <span key={`trace-${i}`} className="text-[10px] px-1 py-0.5 rounded bg-white/5 text-slate-300 font-mono">
                      {f.split("/").pop()}
                    </span>
                  ))}
                </div>
              )}
              {entry.type === "tool_round" && (
                <p className="mt-1 text-[10px] text-slate-500 font-mono">
                  {String(entry.payload.tool)} {JSON.stringify(entry.payload.arguments || {})}
                </p>
              )}
              {entry.type === "findings_batch" && (
                <div className="mt-1 space-y-1">
                  {((entry.payload.finding_titles as string[]) || []).map((t, i) => (
                    <p key={`fb-${i}`} className="text-slate-200 text-[11px]">• {t}</p>
                  ))}
                </div>
              )}
              {entry.type === "candidate_batch" && (
                <div className="mt-1 space-y-1">
                  {((entry.payload.candidate_titles as string[]) || []).map((t, i) => (
                    <p key={`cb-${i}`} className="text-orange-200/90 text-[11px]">• {t}</p>
                  ))}
                </div>
              )}
              {entry.type === "controller_start" && (
                <div className="mt-1 space-y-1 text-slate-500">
                  <p className="text-[10px] text-slate-600">本批审计端点：</p>
                  {((entry.payload.endpoints as Array<Record<string, unknown>>) || []).map((ep, i) => (
                    <p key={`start-ep-${i}`} className="font-mono text-[10px]">
                      {String(ep.http_method || ep.method)} {String(ep.path)} → {String(ep.handler)}
                      {ep.line != null && <span className="text-slate-600"> :{String(ep.line)}</span>}
                    </p>
                  ))}
                  {((entry.payload.related_services as string[]) || []).length > 0 && (
                    <p className="text-[10px]">
                      关联 Service: {(entry.payload.related_services as string[]).join(", ")}
                    </p>
                  )}
                  {((entry.payload.sibling_refs as string[]) || []).length > 0 && (
                    <p className="text-[10px]">
                      跨模块对照: {(entry.payload.sibling_refs as string[]).join(", ")}
                    </p>
                  )}
                </div>
              )}
              {entry.type === "controller_done" && (
                <div className="mt-2 space-y-2">
                  <div className="rounded-md border border-surface-border/70 bg-white/5 px-2.5 py-2">
                    <p className="text-slate-200 leading-relaxed">
                      <span className="text-slate-400">审计思路：</span>
                      {String(entry.payload.audit_summary || "未发现明确漏洞")}
                    </p>
                  </div>

                  {Number(entry.payload.findings_count) > 0 && (
                    <div className="space-y-1.5">
                      {((entry.payload.finding_titles as string[]) || []).map((t, i) => (
                        <div
                          key={`ft-${i}`}
                          className="flex items-start gap-2 rounded-md border border-surface-border/70 bg-black/30 px-2.5 py-2"
                        >
                          <span className="mt-0.5 h-2 w-2 rounded-full bg-slate-200/70 shrink-0" />
                          <p className="text-slate-100 leading-relaxed">{t}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {entry.type === "controller_error" && Boolean(entry.payload.error) && (
                <p className="mt-1 text-red-300/90 text-[11px] leading-relaxed">
                  {String(entry.payload.error)}
                </p>
              )}
              {Boolean(entry.payload.detail) &&
                !["controller_done", "controller_start"].includes(entry.type) && (
                <p className="mt-1 text-slate-500">{String(entry.payload.detail)}</p>
              )}
            </JournalBlock>
          ))}
        </div>
      </div>
    </details>
  );
}

function InfoChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-surface-border/70 bg-black/20 px-2 py-1.5">
      <p className="text-[10px] text-slate-500">{label}</p>
      <p className="text-slate-200 font-mono">{value}</p>
    </div>
  );
}

function JournalBlock({ entry, children }: { entry: LlmAuditJournalEntry; children?: ReactNode }) {
  const label = TYPE_LABELS[entry.type] || entry.type;
  const time = entry.created_at
    ? new Date(entry.created_at).toLocaleTimeString("zh-CN", { hour12: false })
    : "";
  const levelClass =
    entry.level === "error"
      ? "border-red-400/40"
      : entry.level === "warning"
        ? "border-orange-300/35"
        : "border-surface-border/70";

  return (
    <div className={`rounded-lg border ${levelClass} bg-black/20 px-3 py-2`}>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] uppercase tracking-wide text-slate-300">{label}</span>
        {entry.title && <span className="text-slate-300">{entry.title}</span>}
        {entry.payload.progress != null && typeof entry.payload.progress === "object" && (
          <span className="text-[10px] text-slate-400 font-mono">
            {(entry.payload.progress as { current: number; total: number }).current}/
            {(entry.payload.progress as { current: number; total: number }).total}
          </span>
        )}
        <span className="text-[10px] text-slate-400 ml-auto">{time}</span>
      </div>
      {children}
    </div>
  );
}
