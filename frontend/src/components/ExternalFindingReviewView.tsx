import { useEffect, useState } from "react";
import { api, type ExternalReviewOut, type ExternalReviewStatus } from "../api";
import { vulnDisplayId } from "../lib/auditUtils";
import { shortPath } from "../lib/findingUtils";
import { CodeViewer } from "./CodeViewer";
import {
  CategoryBadge,
  ExternalStatusBadge,
  OwaspBadge,
  SeverityBadge,
  SubtypeBadge,
} from "./ui";

interface Props {
  token: string;
}

const STATUS_OPTIONS: { status: ExternalReviewStatus; label: string; hint: string }[] = [
  { status: "vuln_exists", label: "漏洞存在", hint: "确认该问题真实存在，需要修复" },
  { status: "false_positive", label: "漏洞误报", hint: "认为该问题不是真实漏洞" },
  { status: "fixed_claimed", label: "漏洞修复完成", hint: "声称已修复，等待安全复测" },
];

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-0.5">{label}</p>
      <p className={`text-sm text-slate-200 ${mono ? "font-mono break-all" : ""}`}>{value}</p>
    </div>
  );
}

export function ExternalFindingReviewView({ token }: Props) {
  const [data, setData] = useState<ExternalReviewOut | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actor, setActor] = useState("");
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg, setSubmitMsg] = useState<string | null>(null);
  const [submitErr, setSubmitErr] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const out = await api.getExternalReview(token);
      setData(out);
      if (out.external_note) setNote(out.external_note);
      if (out.external_updated_by && out.external_updated_by !== "external") {
        setActor(out.external_updated_by);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [token]);

  const submit = async (status: ExternalReviewStatus) => {
    if (status === "false_positive" && note.trim().length < 10) {
      setSubmitErr("标记误报必须填写原因（至少10字）");
      return;
    }
    setSubmitting(true);
    setSubmitMsg(null);
    setSubmitErr(null);
    try {
      const result = await api.submitExternalReview(token, {
        status,
        note: note || undefined,
        actor: actor || undefined,
      });
      setSubmitMsg(result.message || "已提交");
      await load();
    } catch (e) {
      setSubmitErr(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen grid-bg flex items-center justify-center text-slate-400">
        加载漏洞信息…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen grid-bg flex items-center justify-center p-6">
        <div className="audit-panel max-w-lg w-full p-8 text-center space-y-3">
          <p className="text-danger text-sm">无法打开确认链接</p>
          <p className="text-xs text-slate-500">{error || "链接无效"}</p>
          <p className="text-xs text-slate-600">链接可能已过期、被撤销，或地址不正确。请联系安全人员重新获取。</p>
        </div>
      </div>
    );
  }

  const alreadySubmitted = data.external_status !== "unreviewed";
  const description = data.message_zh || data.title || data.message;
  const lineLabel =
    data.line_end && data.line_end !== data.line_start
      ? `${data.line_start}–${data.line_end}`
      : String(data.line_start);

  return (
    <div className="min-h-screen grid-bg p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <div className="text-center space-y-2">
          <p className="text-[10px] font-mono tracking-[0.3em] text-cyan-500 uppercase">Vulnerability Review</p>
          <h1 className="text-xl font-bold">漏洞确认</h1>
          <p className="text-sm text-slate-500">请根据下方漏洞详情进行确认，无需登录。</p>
        </div>

        <section className="card p-5 space-y-4">
          <p className="text-[10px] font-mono text-cyan-500/70">{vulnDisplayId(data.finding_id)}</p>
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={data.severity} />
            {data.owasp_id && (
              <OwaspBadge owaspId={data.owasp_id} owaspName={data.owasp_name} />
            )}
            {data.vuln_subtype && (
              <SubtypeBadge subtype={data.vuln_subtype} subtypeName={data.vuln_subtype_name} />
            )}
            <CategoryBadge category={data.category} />
            <ExternalStatusBadge status={data.external_status} />
            <span className="text-xs text-slate-500">{data.tool}</span>
          </div>
          <h2 className="text-lg font-semibold leading-snug">{data.title}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <InfoRow label="文件位置" value={`${shortPath(data.relative_path)}:${lineLabel}`} mono />
            <InfoRow label="规则 ID" value={data.rule_id || "—"} mono />
          </div>
          {data.expires_at && (
            <p className="text-xs text-slate-600">链接有效期至：{new Date(data.expires_at).toLocaleString()}</p>
          )}
        </section>

        <section className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-slate-300">问题说明</h3>
          <p className="text-sm leading-relaxed text-slate-200 whitespace-pre-wrap">{description}</p>
          {data.message_zh && data.message !== data.message_zh && (
            <p className="text-xs text-slate-500 border-t border-surface-border pt-3">
              原文：{data.message}
            </p>
          )}
        </section>

        {data.ai_reason && (
          <section className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-300">AI 分析说明</h3>
            <p className="text-sm leading-relaxed text-slate-300 whitespace-pre-wrap">{data.ai_reason}</p>
          </section>
        )}

        <section className="card p-5 space-y-3">
          <h3 className="text-sm font-semibold text-slate-300">相关代码</h3>
          {data.code_context ? (
            <CodeViewer
              content={data.code_context.content}
              windowStart={data.code_context.line_start}
              highlightStart={data.code_context.highlight_start}
              highlightEnd={data.code_context.highlight_end}
              scrollToLine={data.line_start}
              fileLabel={`${shortPath(data.code_context.relative_path)}:${lineLabel}`}
            />
          ) : data.code_snippet ? (
            <div className="rounded-xl border border-surface-border overflow-hidden bg-[#0d1117]">
              <div className="px-4 py-2 text-xs font-mono text-slate-400 border-b border-surface-border bg-surface">
                {shortPath(data.relative_path)}:{lineLabel}
              </div>
              <pre className="p-4 text-xs font-mono text-slate-200 whitespace-pre-wrap overflow-x-auto max-h-[420px]">
                {data.code_snippet}
              </pre>
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              暂无代码片段。请根据上方问题说明与文件位置，在本地仓库中查看对应代码。
            </p>
          )}
        </section>

        {alreadySubmitted && (
          <section className="card p-5 space-y-2">
            <h3 className="text-sm font-semibold text-slate-300">已提交的确认</h3>
            <div className="text-xs text-slate-400 space-y-1">
              <p>状态：<ExternalStatusBadge status={data.external_status} /></p>
              <p>提交时间：{data.external_updated_at ? new Date(data.external_updated_at).toLocaleString() : "—"}</p>
              {data.external_updated_by && <p>确认人：{data.external_updated_by}</p>}
              {data.external_note && <p>备注：{data.external_note}</p>}
            </div>
          </section>
        )}

        <section className="card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-slate-300">确认结果</h3>
          <label className="text-sm text-slate-400 block">
            姓名/工号（可选）
            <input
              className="input mt-1"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="便于安全人员追溯"
              disabled={submitting}
            />
          </label>
          <label className="text-sm text-slate-400 block">
            备注（选择「漏洞误报」时必填，至少10字）
            <textarea
              className="input mt-1 min-h-[90px]"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="补充说明、修复方案、误报理由等"
              disabled={submitting}
            />
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {STATUS_OPTIONS.map((opt) => (
              <button
                key={opt.status}
                type="button"
                disabled={submitting}
                onClick={() => submit(opt.status)}
                className={`text-left p-3 rounded-lg border transition-colors disabled:opacity-50 ${
                  data.external_status === opt.status
                    ? "border-accent/60 bg-accent/10"
                    : "border-surface-border hover:border-accent/40 hover:bg-surface"
                }`}
              >
                <p className="text-sm font-medium text-slate-200">{opt.label}</p>
                <p className="text-xs text-slate-500 mt-1">{opt.hint}</p>
              </button>
            ))}
          </div>

          {submitMsg && <p className="text-xs text-success">{submitMsg}</p>}
          {submitErr && <p className="text-xs text-danger">{submitErr}</p>}
          <p className="text-xs text-slate-600">
            提交后状态会同步给安全人员。若选择「漏洞修复完成」，将进入待安全复测流程。
          </p>
        </section>
      </div>
    </div>
  );
}
