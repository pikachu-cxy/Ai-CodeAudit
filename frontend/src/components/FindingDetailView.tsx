import { useCallback, useEffect, useState } from "react";
import {
  api,
  type CodeLocation,
  type FileContent,
  type Finding,
  type PocExecuteResult,
  type ReviewStatus,
  type ScanSummary,
} from "../api";
import { CodeViewer } from "./CodeViewer";
import { DataFlowBar } from "./DataFlowBar";
import {
  buildFlowNodes,
  displayMessage,
  parseRiskTags,
  parseMetadata,
  parsePocContentToRequest,
  parseVerificationPoc,
  extractPropertyTuple,
  headersToText,
  requestToCurl,
  riskTagLabel,
  seedHttpRequest,
  shortPath,
  textToHeaders,
  type CodeTarget,
  type FlowNode,
  type PocHttpRequest,
  type VerificationPoc,
} from "../lib/findingUtils";
import { vulnDisplayId } from "../lib/auditUtils";
import { copyTextToClipboard } from "../lib/clipboard";
import {
  CategoryBadge,
  ExternalStatusBadge,
  OwaspBadge,
  ReviewBadge,
  ReviewMarkButtons,
  RiskTagBadge,
  SeverityBadge,
  SubtypeBadge,
  ToolbarButton,
  VerdictBadge,
} from "./ui";

interface Props {
  scanId: number;
  findingId: number;
  onBack: () => void;
  onReviewUpdated?: (finding: Finding) => void;
}

interface ViewerTarget {
  filePath: string;
  lineStart: number;
  lineEnd: number;
}

export function FindingDetailView({ scanId, findingId, onBack, onReviewUpdated }: Props) {
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [fileContent, setFileContent] = useState<FileContent | null>(null);
  const [viewerTarget, setViewerTarget] = useState<ViewerTarget | null>(null);
  const [scrollKey, setScrollKey] = useState(0);
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);
  const [resolvingNodeId, setResolvingNodeId] = useState<string | null>(null);
  const [locateError, setLocateError] = useState<string | null>(null);
  const [candidateLocations, setCandidateLocations] = useState<CodeLocation[]>([]);
  const [candidateNodeId, setCandidateNodeId] = useState<string | null>(null);
  const [locateInfo, setLocateInfo] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [loadingFile, setLoadingFile] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [generatePocOnConfirm, setGeneratePocOnConfirm] = useState(false);
  const [pocGenerating, setPocGenerating] = useState(false);
  const [pocNotice, setPocNotice] = useState<string | null>(null);
  const [copiedPoc, setCopiedPoc] = useState(false);
  const [externalLinkBusy, setExternalLinkBusy] = useState(false);
  const [externalLinkError, setExternalLinkError] = useState<string | null>(null);
  const [externalLinkCopied, setExternalLinkCopied] = useState(false);

  const load = async () => {
    const [s, f] = await Promise.all([api.getScan(scanId), api.getFinding(scanId, findingId)]);
    setScan(s);
    setFinding(f);
    setNote(f.review_note || "");
    setViewerTarget({
      filePath: f.file_path,
      lineStart: f.line_start || 1,
      lineEnd: f.line_end || f.line_start || 1,
    });
    setActiveNodeId("location");
    setScrollKey((k) => k + 1);
  };

  useEffect(() => {
    load().catch((e) => setError(String(e)));
  }, [scanId, findingId]);

  const loadFileContent = useCallback(async (target: ViewerTarget) => {
    setLoadingFile(true);
    try {
      const content = await api.getFileContent(scanId, {
        path: target.filePath,
        line_start: target.lineStart,
        line_end: target.lineEnd,
      });
      setFileContent(content);
    } catch {
      setFileContent(null);
    } finally {
      setLoadingFile(false);
    }
  }, [scanId]);

  useEffect(() => {
    if (!viewerTarget) return;
    loadFileContent(viewerTarget);
  }, [viewerTarget, loadFileContent]);

  const resolveTarget = async (target: CodeTarget): Promise<ViewerTarget | null> => {
    if (target.searchText) return null;
    if (!target.lineStart || target.lineStart < 1) return null;
    return {
      filePath: target.filePath,
      lineStart: target.lineStart,
      lineEnd: target.lineEnd,
    };
  };

  const handleFlowNodeClick = async (node: FlowNode) => {
    if (!node.target) return;
    setLocateError(null);
    setLocateInfo(null);
    setCandidateLocations([]);
    setCandidateNodeId(null);
    setActiveNodeId(node.id);
    setResolvingNodeId(node.id);
    try {
      if (node.target.searchText) {
        const hits = await api.locateFile(scanId, {
          q: node.target.searchText,
          file_hint: node.target.filePath,
          limit: 6,
        });
        if (hits.length === 0) {
          setLocateError(`未在项目中找到与「${node.detail}」匹配的代码位置`);
          return;
        }
        const top = hits[0];
        const topConfidence = top.confidence ?? 0;
        if (hits.length > 1 && topConfidence < 0.85) {
          setCandidateLocations(hits);
          setCandidateNodeId(node.id);
          setLocateInfo("存在多个候选位置，请选择最准确的一项");
          return;
        }
        setViewerTarget({
          filePath: top.file_path,
          lineStart: top.line_start,
          lineEnd: top.line_end,
        });
        setLocateInfo(
          `定位来源：${top.strategy || "symbol_search"} · 置信度 ${(Math.round((top.confidence ?? 0) * 100))}%`
        );
        setScrollKey((k) => k + 1);
        return;
      }
      const resolved = await resolveTarget(node.target);
      if (!resolved) {
        setLocateError(`未在项目中找到与「${node.detail}」匹配的代码位置`);
        return;
      }
      setViewerTarget(resolved);
      setLocateInfo(`定位来源：${node.target.searchText ? "符号搜索" : "明确行号"} · ${shortPath(resolved.filePath)}:${resolved.lineStart}`);
      setScrollKey((k) => k + 1);
    } catch (e) {
      setLocateError(String(e));
    } finally {
      setResolvingNodeId(null);
    }
  };

  const applyReview = async (status: ReviewStatus) => {
    if (!finding) return;
    if (status === "false_positive") {
      const trimmed = note.trim();
      if (trimmed.length < 10) {
        setReviewError("标记误报必须填写原因（至少10字），请在下方备注框填写");
        return;
      }
    }
    setSaving(true);
    setReviewError(null);
    setPocNotice(null);
    try {
      const updated = await api.reviewFinding(scanId, findingId, {
        review_status: status,
        review_note: note || undefined,
        generate_poc: generatePocOnConfirm && status === "confirmed",
      });
      setFinding(updated);
      onReviewUpdated?.(updated);
      if (generatePocOnConfirm && status === "confirmed") {
        const poc = parseVerificationPoc(updated.metadata_json);
        setPocNotice(poc ? "已确认漏洞并生成验证 PoC" : "已确认漏洞（PoC 生成失败或未配置 LLM，可稍后手动生成）");
      }
    } catch (e) {
      setReviewError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const runGeneratePoc = async (force = false) => {
    setPocGenerating(true);
    setPocNotice(null);
    setReviewError(null);
    try {
      const result = await api.generatePoc(scanId, findingId, { force });
      setPocNotice(result.message);
      await load();
    } catch (e) {
      setReviewError(String(e));
    } finally {
      setPocGenerating(false);
    }
  };

  const copyPoc = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedPoc(true);
      setTimeout(() => setCopiedPoc(false), 2000);
    } catch {
      setPocNotice("复制失败，请手动选择 PoC 内容");
    }
  };

  const createExternalLink = async () => {
    setExternalLinkBusy(true);
    setExternalLinkError(null);
    try {
      const result = await api.createExternalReviewLink(scanId, findingId);
      await load();
      if (result.url) {
        const copied = await copyTextToClipboard(result.url);
        if (copied) {
          setExternalLinkCopied(true);
          setExternalLinkError(null);
          setTimeout(() => setExternalLinkCopied(false), 2000);
        } else {
          setExternalLinkError("链接已生成，但自动复制失败，请手动复制下方链接");
        }
      }
    } catch (e) {
      setExternalLinkError(String(e));
    } finally {
      setExternalLinkBusy(false);
    }
  };

  const copyExternalLink = async () => {
    const url = finding?.external_review_url;
    if (!url) return;
    try {
      const copied = await copyTextToClipboard(url);
      if (copied) {
        setExternalLinkCopied(true);
        setExternalLinkError(null);
        setTimeout(() => setExternalLinkCopied(false), 2000);
      } else {
        setExternalLinkError("自动复制失败，请手动选择下方链接复制");
      }
    } catch {
      setExternalLinkError("自动复制失败，请手动选择下方链接复制");
    }
  };

  const revokeExternalLink = async () => {
    setExternalLinkBusy(true);
    setExternalLinkError(null);
    try {
      await api.revokeExternalReviewLink(scanId, findingId);
      await load();
    } catch (e) {
      setExternalLinkError(String(e));
    } finally {
      setExternalLinkBusy(false);
    }
  };

  if (error) {
    return (
      <div className="text-center py-20 text-danger">
        <p>{error}</p>
        <button className="btn-ghost mt-4" onClick={onBack}>返回</button>
      </div>
    );
  }

  if (!finding || !scan) {
    return <div className="text-center py-20 text-slate-400">加载中...</div>;
  }

  const md = parseMetadata(finding.metadata_json);
  const skillSources: Record<string, unknown>[] = Array.isArray(md.skill_sources)
    ? md.skill_sources.filter((s: unknown) => s && typeof s === "object") : [];
  const riskTags = parseRiskTags(finding.metadata_json);
  const verificationPoc = parseVerificationPoc(finding.metadata_json);
  const propertyTuple = extractPropertyTuple(finding);
  const flowNodes = buildFlowNodes(finding);
  const canGeneratePoc =
    finding.review_status === "confirmed" || finding.ai_verdict === "real_vuln";

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {skillSources.length > 0 && <section className="card p-4 space-y-3">
        <h2 className="font-medium">Skill 审计来源</h2>
        {skillSources.map((source, i) => <details key={i} className="text-sm">
          <summary className="cursor-pointer">运行 #{String(source.run_id ?? "")} · {String(source.skill_id ?? "")}@{String(source.version ?? "")}</summary>
          <p className="text-xs text-slate-500 break-all mt-2">SHA-256：{String(source.sha256 ?? "")}</p>
          <p className="text-xs text-slate-400">{String(source.risk_type ?? "")} {String(source.cwe ?? "")}</p>
          <p className="whitespace-pre-wrap mt-2">防护分析：{String(source.guard_analysis ?? "")}</p>
          <pre className="whitespace-pre-wrap overflow-auto max-h-48 text-xs mt-2">{String(source.evidence ?? "")}</pre>
        </details>)}
      </section>}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0 flex-1">
          <button className="text-xs font-mono text-cyan-500/70 hover:text-cyan-300 mb-3" onClick={onBack}>
            ← 返回审计报告
          </button>
          <p className="text-[10px] font-mono uppercase tracking-wider text-cyan-500/60 mb-2">
            {vulnDisplayId(finding.id)}
          </p>
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <SeverityBadge severity={finding.severity} />
            <OwaspBadge owaspId={finding.owasp_id} owaspName={finding.owasp_name} />
            {finding.vuln_subtype && (
              <SubtypeBadge subtype={finding.vuln_subtype} subtypeName={finding.vuln_subtype_name} />
            )}
            <CategoryBadge category={finding.category} />
            <ReviewBadge status={finding.review_status} />
            <ExternalStatusBadge status={finding.external_status} />
            {(finding.category === "sast" || finding.tool === "llm") && (
              <VerdictBadge verdict={finding.ai_verdict} />
            )}
            <span className="text-xs text-slate-500">{finding.tool}</span>
          </div>
          {riskTags.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap mb-3">
              {riskTags.map((tag) => (
                <RiskTagBadge key={tag} tag={riskTagLabel(tag)} />
              ))}
            </div>
          )}
          <h1 className="text-xl font-bold leading-snug">{displayMessage(finding)}</h1>
          <p className="text-sm text-slate-500 mt-1 font-mono truncate">
            {shortPath(finding.file_path)}:{finding.line_start}
            <span className="text-slate-600 mx-2">·</span>
            {scan.name}
          </p>
        </div>
        <div className="card p-4 shrink-0 w-full sm:w-auto space-y-3">
          <p className="text-xs text-slate-500">安全标记</p>
          {reviewError && (
            <p className="text-xs text-danger">{reviewError}</p>
          )}
          {pocNotice && (
            <p className="text-xs text-accent">{pocNotice}</p>
          )}
          <ReviewMarkButtons
            current={finding.review_status}
            disabled={saving || pocGenerating}
            onMark={applyReview}
          />
          <label className="flex items-start gap-2 text-xs text-slate-400 cursor-pointer">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={generatePocOnConfirm}
              onChange={(e) => setGeneratePocOnConfirm(e.target.checked)}
              disabled={saving || pocGenerating}
            />
            <span>确认真实漏洞时，同时生成验证 PoC</span>
          </label>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            安全标记由审计人员操作；外部确认为业务负责人通过链接提交，两者互不影响。
          </p>
          {canGeneratePoc && (
            <ToolbarButton
              className="w-full"
              disabled={pocGenerating || saving}
              running={pocGenerating}
              onClick={() => runGeneratePoc(Boolean(verificationPoc))}
            >
              {pocGenerating
                ? "生成 PoC 中..."
                : verificationPoc
                  ? "重新生成验证 PoC"
                  : "生成验证 PoC"}
            </ToolbarButton>
          )}
        </div>
        <div className="card p-4 shrink-0 w-full sm:w-auto space-y-3">
          <p className="text-xs text-slate-500">外部确认（临时链接）</p>
          <p className="text-xs text-slate-600 leading-relaxed">
            生成链接后转发给研发负责人，对方无需登录即可确认：漏洞存在 / 误报 / 修复完成。
          </p>
          {externalLinkError && <p className="text-xs text-danger">{externalLinkError}</p>}
          {externalLinkCopied && <p className="text-xs text-accent">链接已复制到剪贴板</p>}
          {finding.external_review_url && (
            <p className="text-[10px] font-mono text-slate-500 break-all">{finding.external_review_url}</p>
          )}
          {finding.external_review_expires_at && (
            <p className="text-xs text-slate-600">
              链接有效期至：{new Date(finding.external_review_expires_at).toLocaleString()}
            </p>
          )}
          {finding.external_status !== "unreviewed" && (
            <div className="text-xs text-slate-400 border border-surface-border rounded-lg p-2 space-y-1">
              <p>外部状态：<ExternalStatusBadge status={finding.external_status} /></p>
              {finding.external_updated_at && (
                <p>提交时间：{new Date(finding.external_updated_at).toLocaleString()}</p>
              )}
              {finding.external_updated_by && <p>确认人：{finding.external_updated_by}</p>}
              {finding.external_note && <p>备注：{finding.external_note}</p>}
            </div>
          )}
          <div className="flex flex-col gap-2">
            <ToolbarButton
              className="w-full"
              disabled={externalLinkBusy || saving}
              running={externalLinkBusy}
              onClick={createExternalLink}
            >
              {finding.external_review_url ? "重新生成临时链接" : "生成临时链接"}
            </ToolbarButton>
            {finding.external_review_url && (
              <>
                <ToolbarButton className="w-full" disabled={externalLinkBusy} onClick={copyExternalLink}>
                  复制链接
                </ToolbarButton>
                <ToolbarButton
                  className="w-full"
                  danger
                  disabled={externalLinkBusy}
                  onClick={revokeExternalLink}
                >
                  撤销链接
                </ToolbarButton>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="xl:col-span-2 space-y-4">
          <section className="card p-5 space-y-4">
            <h2 className="text-sm font-semibold text-slate-300">问题说明</h2>
            <div>
              <p className="text-sm leading-relaxed text-slate-200">{displayMessage(finding)}</p>
              {finding.message_zh && finding.message !== finding.message_zh && (
                <p className="text-xs text-slate-500 mt-2">原文: {finding.message}</p>
              )}
            </div>
            <div className="grid grid-cols-1 gap-3 text-sm">
              <InfoRow label="规则 ID" value={finding.rule_id} mono />
              <InfoRow label="文件" value={shortPath(finding.file_path)} mono />
              <InfoRow label="行号" value={`${finding.line_start}${finding.line_end && finding.line_end !== finding.line_start ? `–${finding.line_end}` : ""}`} />
            </div>
          </section>

          {finding.ai_reason && (
            <section className="card p-5">
              <h2 className="text-sm font-semibold text-slate-300 mb-2">
                {finding.category === "sast"
                  ? md.sast_deep_reviewed
                    ? md.flow_reconstructed
                      ? "AI 数据流追认"
                      : "SAST 数据流深度研判"
                    : "AI 误报审计"
                  : md.sast_deep_reviewed
                    ? md.flow_reconstructed
                      ? "AI 数据流追认"
                      : "LLM 数据流深度研判"
                    : md.ai_re_reviewed
                      ? "AI 复审"
                      : "LLM 深度分析"}
              </h2>
              <p className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">{finding.ai_reason}</p>
              {finding.ai_confidence != null && (
                <p className="text-xs text-slate-500 mt-2">
                  置信度 {(finding.ai_confidence * 100).toFixed(0)}%
                </p>
              )}
              {md.chained_risk && (
                <div className="mt-4 pt-4 border-t border-surface-border">
                  <h3 className="text-xs text-slate-500 mb-1">链式风险 / 未覆盖问题</h3>
                  <p className="text-xs text-slate-200/90 whitespace-pre-wrap leading-relaxed">
                    {md.chained_risk}
                  </p>
                </div>
              )}
              {riskTags.length > 0 && (
                <div className="mt-4 pt-4 border-t border-surface-border">
                  <h3 className="text-xs text-slate-500 mb-2">风险标签</h3>
                  <div className="flex flex-wrap gap-2">
                    {riskTags.map((tag) => (
                      <RiskTagBadge key={`detail-${tag}`} tag={riskTagLabel(tag)} />
                    ))}
                  </div>
                </div>
              )}
              {md.exploit_scenario_llm && (
                <div className="mt-4 pt-4 border-t border-surface-border">
                  <h3 className="text-xs text-slate-500 mb-1">攻击场景（研判）</h3>
                  <p className="text-xs text-slate-400 whitespace-pre-wrap leading-relaxed">
                    {md.exploit_scenario_llm}
                  </p>
                </div>
              )}
              {md.discovery_reason && md.ai_re_reviewed && (
                <div className="mt-4 pt-4 border-t border-surface-border">
                  <h3 className="text-xs text-slate-500 mb-1">深度审计初判</h3>
                  <p className="text-xs text-slate-400 whitespace-pre-wrap leading-relaxed">
                    {md.discovery_reason}
                  </p>
                </div>
              )}
            </section>
          )}

          {propertyTuple && (
            <section className="card p-5 space-y-3">
              <h2 className="text-sm font-semibold text-slate-300">风险四元组</h2>
              <TupleRow label="Source (可控输入)" value={propertyTuple.source} />
              <TupleRow label="Sink (危险能力)" value={propertyTuple.sink} />
              <TupleRow label="Missing Guard (缺失约束)" value={propertyTuple.missingGuard} />
              <TupleRow label="Impact (实际后果)" value={propertyTuple.impact} />
            </section>
          )}

          {(md.attack_scenario || md.recommendation) && (
            <section className="card p-5 space-y-4">
              {md.attack_scenario && (
                <div>
                  <h3 className="text-xs text-slate-500 mb-1">攻击场景</h3>
                  <p className="text-sm whitespace-pre-wrap">{md.attack_scenario}</p>
                </div>
              )}
              {md.recommendation && (
                <div>
                  <h3 className="text-xs text-slate-500 mb-1">修复建议</h3>
                  <p className="text-sm whitespace-pre-wrap text-emerald-300/90">{md.recommendation}</p>
                </div>
              )}
            </section>
          )}

          <PocVerifySection
            scanId={scanId}
            findingId={findingId}
            poc={verificationPoc}
            apiEndpoint={typeof md.api_endpoint === "string" ? md.api_endpoint : ""}
            copied={copiedPoc}
            onCopy={copyPoc}
            onSaved={load}
          />

          <section className="card p-5">
            <h2 className="text-sm font-semibold text-slate-300 mb-2">备注</h2>
            <textarea
              className="input min-h-[80px] resize-y"
              placeholder="记录审计结论、复现步骤等..."
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <button
              className="btn-ghost text-sm mt-2"
              disabled={saving}
              onClick={() => applyReview(finding.review_status || "unreviewed")}
            >
              保存备注
            </button>
          </section>
        </div>

        <div className="xl:col-span-3 space-y-4">
          <section className="card p-5">
            <DataFlowBar
              nodes={flowNodes}
              activeNodeId={activeNodeId}
              resolvingId={resolvingNodeId}
              onNodeClick={handleFlowNodeClick}
            />
            {locateError && (
              <p className="text-xs text-warning mt-3">{locateError}</p>
            )}
            {locateInfo && !locateError && (
              <p className="text-xs text-slate-500 mt-3">{locateInfo}</p>
            )}
            {candidateLocations.length > 0 && (
              <div className="mt-3 rounded-lg border border-surface-border p-3 bg-surface space-y-2">
                <p className="text-xs text-slate-400">候选定位（{candidateNodeId ? `节点: ${candidateNodeId}` : "自动搜索"}）</p>
                {candidateLocations.map((c, idx) => (
                  <button
                    key={`${c.file_path}:${c.line_start}:${idx}`}
                    className="w-full text-left px-3 py-2 rounded border border-surface-border hover:border-accent/60 hover:bg-surface-raised transition-colors"
                    onClick={() => {
                      setViewerTarget({
                        filePath: c.file_path,
                        lineStart: c.line_start,
                        lineEnd: c.line_end,
                      });
                      setScrollKey((k) => k + 1);
                      setLocateInfo(
                        `定位来源：${c.strategy || "symbol_search"} · 置信度 ${(Math.round((c.confidence ?? 0) * 100))}%`
                      );
                      setCandidateLocations([]);
                      setCandidateNodeId(null);
                    }}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-slate-300 break-all">
                        {shortPath(c.file_path)}:{c.line_start}
                      </span>
                      <span className="text-[10px] text-slate-500">
                        {(Math.round((c.confidence ?? 0) * 100))}% {c.language_matched ? "同语言" : "跨语言"}
                      </span>
                    </div>
                    {c.matched_text && (
                      <p className="text-xs text-slate-500 mt-1 line-clamp-1">{c.matched_text}</p>
                    )}
                  </button>
                ))}
              </div>
            )}
          </section>

          <section className="card p-5">
            <div className="flex items-center justify-between mb-3 gap-2 flex-wrap">
              <h2 className="text-sm font-semibold text-slate-300">源代码</h2>
              {viewerTarget && (
                <span className="text-xs font-mono text-slate-500">
                  {shortPath(viewerTarget.filePath)}:{viewerTarget.lineStart}
                </span>
              )}
              {viewerTarget && viewerTarget.lineStart > 0 && (
                <button
                  className="text-xs text-accent hover:underline"
                  onClick={() => setScrollKey((k) => k + 1)}
                >
                  跳转到第 {viewerTarget.lineStart} 行
                </button>
              )}
            </div>
            {loadingFile ? (
              <p className="text-sm text-slate-500 py-8 text-center">加载代码中...</p>
            ) : fileContent ? (
              <CodeViewer
                content={fileContent.content}
                windowStart={fileContent.line_start}
                highlightStart={fileContent.highlight_start}
                highlightEnd={fileContent.highlight_end}
                scrollToLine={viewerTarget?.lineStart ?? null}
                scrollKey={scrollKey}
                fileLabel={shortPath(fileContent.relative_path)}
              />
            ) : finding.code_snippet ? (
              <div>
                <p className="text-xs text-slate-500 mb-2">无法读取完整文件，显示扫描器提取的片段</p>
                <pre className="text-xs font-mono bg-[#0d1117] p-4 rounded-xl overflow-x-auto border border-surface-border">
                  {finding.code_snippet}
                </pre>
              </div>
            ) : (
              <p className="text-sm text-slate-500 py-8 text-center">无可用代码内容</p>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs text-slate-500 mb-0.5">{label}</p>
      <p className={`text-sm break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</p>
    </div>
  );
}

function TupleRow({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <div>
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">{value}</p>
    </div>
  );
}

const POC_TYPE_LABELS: Record<string, string> = {
  curl: "cURL",
  httpie: "HTTPie",
  python: "Python",
  burp: "Burp Suite",
  manual: "手工步骤",
};

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function PocVerifySection({
  scanId,
  findingId,
  poc,
  apiEndpoint,
  copied,
  onCopy,
  onSaved,
}: {
  scanId: number;
  findingId: number;
  poc: VerificationPoc | null;
  apiEndpoint: string;
  copied: boolean;
  onCopy: (text: string) => void;
  onSaved: () => Promise<void>;
}) {
  const [req, setReq] = useState<PocHttpRequest>(() => seedHttpRequest(poc, apiEndpoint));
  const [headerText, setHeaderText] = useState(() => headersToText(seedHttpRequest(poc, apiEndpoint).headers));
  const [rawText, setRawText] = useState(() => poc?.poc_content || requestToCurl(seedHttpRequest(poc, apiEndpoint)));
  const [sending, setSending] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PocExecuteResult | null>(null);

  useEffect(() => {
    const next = seedHttpRequest(poc, apiEndpoint);
    setReq(next);
    setHeaderText(headersToText(next.headers));
    setRawText(poc?.poc_content || requestToCurl(next));
    setResult(null);
    setError(null);
    setNotice(null);
  }, [findingId, poc?.updated_at, poc?.generated_at, poc?.poc_content, apiEndpoint]);

  const patchReq = (patch: Partial<PocHttpRequest>, syncRaw = true) => {
    setReq((prev) => {
      const next = { ...prev, ...patch };
      if (syncRaw) setRawText(requestToCurl(next));
      return next;
    });
  };

  const applyHeadersFromText = (text: string) => {
    setHeaderText(text);
    patchReq({ headers: textToHeaders(text) });
  };

  const applyRawText = (text: string) => {
    setRawText(text);
    const parsed = parsePocContentToRequest(text);
    if (!parsed) return;
    setReq(parsed);
    setHeaderText(headersToText(parsed.headers));
  };

  const payload = (): PocHttpRequest => ({
    method: req.method,
    url: req.url,
    headers: textToHeaders(headerText),
    body: req.body,
    poc_content: rawText,
  });

  const saveDraft = async () => {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const out = await api.savePocDraft(scanId, findingId, payload());
      setNotice(out.message || "验证请求已保存");
      await onSaved();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const send = async () => {
    setSending(true);
    setError(null);
    setNotice(null);
    setResult(null);
    try {
      const out = await api.executePoc(scanId, findingId, payload());
      setResult(out);
      if (!out.ok && out.error) setError(out.error);
    } catch (e) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  };

  const typeLabel = POC_TYPE_LABELS[poc?.poc_type || ""] || poc?.poc_type || "手工";

  return (
    <section className="card p-5 space-y-4 border border-red-500/20 bg-red-500/5">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-red-300">验证 PoC</h2>
          <p className="text-xs text-slate-400 mt-1">
            {poc?.title || "手动编辑 HTTP 请求并由后端代发，对照返回包判断漏洞是否可复现。"}
          </p>
        </div>
        <span className="badge bg-red-500/20 text-red-300 border border-red-500/30 text-[10px]">
          {typeLabel}
        </span>
      </div>

      <p className="text-xs text-slate-400 bg-white/5 border border-surface-border/70 rounded-lg px-3 py-2">
        仅允许向已获授权的公网目标发包；localhost、内网与云 metadata 地址会被拦截。请勿对未授权系统使用。
      </p>

      {poc?.safety_note && (
        <p className="text-xs text-slate-200/90 bg-white/5 border border-surface-border/70 rounded-lg px-3 py-2">
          {poc.safety_note}
        </p>
      )}

      {poc?.prerequisites && (
        <div>
          <h3 className="text-xs text-slate-500 mb-1">前置条件</h3>
          <p className="text-sm whitespace-pre-wrap text-slate-300">{poc.prerequisites}</p>
        </div>
      )}

      {poc?.steps && (
        <div>
          <h3 className="text-xs text-slate-500 mb-1">验证步骤</h3>
          <p className="text-sm whitespace-pre-wrap text-slate-300">{poc.steps}</p>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-[7rem_1fr] gap-2">
        <select
          className="input text-sm"
          value={req.method}
          onChange={(e) => patchReq({ method: e.target.value })}
        >
          {HTTP_METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
        <input
          className="input font-mono text-sm"
          placeholder="https://example.com/api/vulnerable"
          value={req.url}
          onChange={(e) => patchReq({ url: e.target.value })}
        />
      </div>

      <div>
        <h3 className="text-xs text-slate-500 mb-1">Headers（每行 Name: value）</h3>
        <textarea
          className="input min-h-[72px] resize-y font-mono text-xs"
          placeholder={"Content-Type: application/json\nAuthorization: Bearer ..."}
          value={headerText}
          onChange={(e) => applyHeadersFromText(e.target.value)}
        />
      </div>

      <div>
        <h3 className="text-xs text-slate-500 mb-1">Body</h3>
        <textarea
          className="input min-h-[80px] resize-y font-mono text-xs"
          placeholder="请求体（GET/HEAD 可留空）"
          value={req.body}
          onChange={(e) => patchReq({ body: e.target.value })}
        />
      </div>

      <div>
        <div className="flex items-center justify-between mb-2 gap-2">
          <h3 className="text-xs text-slate-500">原始 PoC 文本（可编辑；失焦时尝试解析 curl）</h3>
          <button
            type="button"
            className="btn-ghost text-xs py-1 px-2"
            onClick={() => onCopy(rawText)}
          >
            {copied ? "已复制" : "复制 PoC"}
          </button>
        </div>
        <textarea
          className="input min-h-[96px] resize-y font-mono text-xs"
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          onBlur={(e) => applyRawText(e.target.value)}
        />
      </div>

      {poc?.expected_result && (
        <div>
          <h3 className="text-xs text-slate-500 mb-1">预期结果</h3>
          <p className="text-sm whitespace-pre-wrap text-slate-300">{poc.expected_result}</p>
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <button type="button" className="btn-primary text-sm" disabled={sending || !req.url.trim()} onClick={send}>
          {sending ? "发送中…" : "发送验证"}
        </button>
        <button type="button" className="btn-ghost text-sm" disabled={saving} onClick={saveDraft}>
          {saving ? "保存中…" : "保存请求"}
        </button>
      </div>

      {notice && <p className="text-xs text-accent">{notice}</p>}
      {error && <p className="text-xs text-danger">{error}</p>}

      {result && (
        <div className="rounded-xl border border-surface-border bg-[#0d1117] p-4 space-y-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <p className="text-sm font-mono text-slate-200">
              {result.status_code != null ? `HTTP ${result.status_code}` : "无响应"}
              <span className="text-slate-500 ml-2">{result.elapsed_ms} ms</span>
            </p>
            {result.truncated && (
              <span className="text-[10px] text-amber-300">响应体已截断（64KB）</span>
            )}
          </div>
          {result.final_url && (
            <p className="text-[11px] font-mono text-slate-500 break-all">最终 URL：{result.final_url}</p>
          )}
          {result.error && <p className="text-xs text-danger">{result.error}</p>}
          <pre className="text-[11px] font-mono text-slate-400 whitespace-pre-wrap max-h-40 overflow-auto">
            {Object.entries(result.headers || {})
              .map(([k, v]) => `${k}: ${v}`)
              .join("\n") || "(无响应头)"}
          </pre>
          <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap max-h-80 overflow-auto border-t border-surface-border pt-2">
            {result.body || "(空响应体)"}
          </pre>
        </div>
      )}
    </section>
  );
}
