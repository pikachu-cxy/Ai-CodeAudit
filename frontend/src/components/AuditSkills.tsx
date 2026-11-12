import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { api, type AuditSkill, type SkillAuditOptions, type SkillAuditRun } from "../api";

const button = "rounded border border-slate-600 px-3 py-1.5 text-sm disabled:opacity-40";
const input = "rounded border border-slate-600 bg-slate-900 p-2 text-sm";
const states: Record<string, string> = {
  queued: "等待调查", running: "调查中", completed: "已完成", partial: "部分完成",
  cancelled: "已取消", failed: "失败", interrupted: "已中断", not_applicable: "不适用",
};

export function AuditSkillManager() {
  const [skills, setSkills] = useState<AuditSkill[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [defaults, setDefaults] = useState<{id: string; version: string}[]>([]);
  const [preview, setPreview] = useState<Awaited<ReturnType<typeof api.validateSkillBundle>> | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const [detail, setDetail] = useState<AuditSkill | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const load = async () => { const [rows, saved] = await Promise.all([api.listAuditSkills(), api.getSkillDefaults()]); setSkills(rows); setDefaults(saved.skills); };
  useEffect(() => { void load().catch(e => setMessage(String(e))); }, []);
  const act = async (work: () => Promise<unknown>) => {
    setBusy(true); setMessage("");
    try { await work(); } catch (e) { setMessage(String(e)); } finally { setBusy(false); }
  };
  return <div className="space-y-4">
    <p className="text-sm text-slate-400">安装不同审计方法，在扫描详情中选择 Skill 开展深度调查。安装后需启用；更新请使用新版本号，历史运行保留原内容。</p>
    <div className="rounded border border-slate-700 p-3 space-y-3">
      <label className="block text-sm">上传 Skill ZIP 或 SKILL.md（默认最大 20 MiB，可由管理员配置）
        <input type="file" accept=".zip,.md" disabled={busy} className="block mt-2" onChange={e => { setFile(e.target.files?.[0] || null); setPreview(null); setMessage(""); }} />
      </label>
      <p className="text-xs text-slate-500">包内需有 SKILL.md；没有 audit.yaml 时自动生成配置。附件会被保存，脚本不会执行。可下载内置 Skill 作为模板。</p>
      <button type="button" className={button} disabled={!file || busy} onClick={() => void act(async () => { if (file) { const result = await api.validateSkillBundle(file); setPreview(result); setSelectedPaths(result.skills.map(s => s.path)); } })}>校验并预览</button>
      {preview && <div className="space-y-2">
        {preview.skills.map(item => <div key={item.path} className="rounded border border-slate-700 p-2">
          <label><input type="checkbox" checked={selectedPaths.includes(item.path)} onChange={e => setSelectedPaths(old => e.target.checked ? [...old, item.path] : old.filter(p => p !== item.path))} /> {item.manifest.name} · {item.manifest.id}@{item.manifest.version}</label>
          <p className="text-xs">目录：{item.path || "根目录"} · 文本文件 {Object.keys(item.references).length} · 二进制文件 {item.binary_files.length} · 工具：{item.manifest.tools.join("、")}</p>
          {Object.keys(item.references).some(p => /\.(py|sh|js|ps1|bat)$/i.test(p)) && <p className="text-xs text-amber-300">包含脚本；脚本仅保存，不会执行。</p>}
          <details><summary className="text-xs">查看方法及文件</summary><pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs">{item.instructions}</pre><p className="text-xs break-all">{[...Object.keys(item.references), ...item.binary_files].join("、")}</p></details>
        </div>)}
        <button type="button" className={button} disabled={busy || !file || !selectedPaths.length} onClick={() => void act(async () => {
          if (file) { await api.installSkillBundle(file, selectedPaths); setPreview(null); setMessage("已安装，请在列表中启用相应版本。"); await load(); }
        })}>安装所选版本</button>
      </div>}
    </div>
    {message && <p role="status" className="text-sm text-amber-300">{message}</p>}
    {skills.map(skill => <div key={`${skill.id}@${skill.version}`} className="rounded border border-slate-700 p-3 space-y-2">
      <p className="font-medium">{skill.name} <span className="text-xs text-slate-400">{skill.version} · {skill.enabled ? "已启用" : "未启用"}</span></p>
      <p className="text-xs text-slate-400">{skill.manifest.description}</p>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={button} disabled={busy} onClick={() => void act(async () => { await api.setAuditSkillEnabled(skill.id, skill.version, !skill.enabled); await load(); })}>{skill.enabled ? "停用" : "启用"}</button>
        <button type="button" className={button} disabled={busy || !skill.enabled} onClick={() => void act(async () => { const exists = defaults.some(d => d.id === skill.id && d.version === skill.version); const next = defaults.filter(d => d.id !== skill.id); if (!exists) next.push({id: skill.id, version: skill.version}); await api.setSkillDefaults(next); await load(); })}>{defaults.some(d => d.id === skill.id && d.version === skill.version) ? "取消默认" : "设为默认"}</button>
        <button type="button" className={button} disabled={busy} onClick={() => void act(async () => setDetail(await api.auditSkillDetail(skill.id, skill.version)))}>查看方法</button>
        <button type="button" className={button} disabled={busy} onClick={() => void act(() => api.downloadAuditSkill(skill.id, skill.version))}>下载包 / 模板</button>
      </div>
    </div>)}
    {detail && <div className="rounded border border-slate-600 p-3 space-y-2">
      <div className="flex justify-between"><strong>{detail.name} · {detail.version}</strong><button type="button" onClick={() => setDetail(null)}>关闭详情</button></div>
      <p className="break-all text-xs text-slate-400">SHA-256：{detail.sha256}</p>
      <p className="text-xs">工具：{detail.manifest.tools.join("、")}</p>
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap text-xs">{detail.instructions}</pre>
      {Object.entries(detail.references || {}).map(([path, content]) => <details key={path}><summary>{path}</summary><pre className="max-h-60 overflow-auto whitespace-pre-wrap text-xs">{content}</pre></details>)}
    </div>}
  </div>;
}

export function SkillAuditDialog({ scanId, projectId, onClose, onStarted }: { scanId: number; projectId: number | null; onClose: () => void; onStarted: () => Promise<void> }) {
  const [skills, setSkills] = useState<AuditSkill[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [defaultSource, setDefaultSource] = useState<"system" | "project">("system");
  const [profile, setProfile] = useState<SkillAuditOptions["profile"]>("balanced");
  const [rounds, setRounds] = useState(30);
  const [seconds, setSeconds] = useState(900);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [plan, setPlan] = useState<Awaited<ReturnType<typeof api.skillAuditPlan>> | null>(null);
  const options: SkillAuditOptions = { skills: skills.filter(s => selected.includes(`${s.id}@${s.version}`)).map(s => ({ id: s.id, version: s.version })), profile, budget: { max_iterations: rounds, timeout_seconds: seconds } };
  useEffect(() => { void Promise.all([api.listAuditSkills(), projectId ? api.getProjectSkillDefaults(projectId) : api.getSkillDefaults().then(r => ({...r, source: "system" as const}))]).then(([rows, saved]) => { const enabled = rows.filter(s => s.enabled); setSkills(enabled); setDefaultSource(saved.source); setSelected(saved.skills.filter(d => enabled.some(s => s.id === d.id && s.version === d.version)).map(d => `${d.id}@${d.version}`)); setLoaded(true); }).catch(e => setError(String(e))); }, [projectId]);
  useEffect(() => { const escape = (e: KeyboardEvent) => { if (e.key === "Escape" && !busy) { e.stopPropagation(); onClose(); } }; window.addEventListener("keydown", escape); return () => window.removeEventListener("keydown", escape); }, [busy, onClose]);
  const validBudget = Number.isInteger(rounds) && rounds >= 3 && rounds <= 80 && Number.isInteger(seconds) && seconds >= 30 && seconds <= 3600;
  const start = async () => {
    setBusy(true); setError("");
    try { await api.llmAudit(scanId, undefined, selected.length ? options : undefined); await onStarted(); onClose(); }
    catch (e) { setError(String(e)); } finally { setBusy(false); }
  };
  return createPortal(<div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4">
    <div role="dialog" aria-modal="true" aria-labelledby="skill-audit-title" className="w-full max-w-2xl max-h-[90vh] overflow-auto rounded-xl border border-slate-700 bg-slate-950 p-5 text-slate-200 space-y-4">
      <div className="flex justify-between"><h2 id="skill-audit-title" className="text-lg font-semibold">深度审计</h2><button type="button" disabled={busy} onClick={onClose}>关闭</button></div>
      <p className="text-sm text-slate-400">选择最多 4 个审计方向，各 Skill 独立调查并共享总预算。不选择时沿用默认审计流程。</p>
      {skills.map(s => { const key = `${s.id}@${s.version}`; return <label key={key} className="flex gap-3 rounded border border-slate-700 p-3">
        <input type="checkbox" checked={selected.includes(key)} disabled={busy || (!selected.includes(key) && selected.length >= 4)} onChange={e => {
          setPlan(null); setSelected(prev => e.target.checked ? [...prev.filter(k => !k.startsWith(`${s.id}@`)), key] : prev.filter(k => k !== key));
        }} />
        <span><span>{s.name} · {s.version}</span><span className="block text-xs text-slate-400 mt-1">{s.manifest.description}</span></span>
      </label>; })}
      {loaded && skills.length === 0 && <p className="text-sm">暂无已启用 Skill，可由管理员在设置中安装。</p>}
      {projectId && <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400"><span>当前默认来源：{defaultSource === "project" ? "项目" : "系统"}</span><button type="button" className={button} disabled={busy || !loaded} onClick={() => void (async () => { setBusy(true); setError(""); try { await api.setProjectSkillDefaults(projectId, options.skills); setDefaultSource("project"); } catch (e) { setError(String(e)); } finally { setBusy(false); } })()}>保存当前选择为项目默认</button><button type="button" className={button} disabled={busy || !loaded} onClick={() => void (async () => { setBusy(true); setError(""); try { const saved = await api.setProjectSkillDefaults(projectId, null); setDefaultSource(saved.source); setSelected(saved.skills.filter(d => skills.some(s => s.id === d.id && s.version === d.version)).map(d => `${d.id}@${d.version}`)); setPlan(null); } catch (e) { setError(String(e)); } finally { setBusy(false); } })()}>使用系统默认</button></div>}
      {selected.length > 0 && <div className="flex flex-wrap gap-3">
        <label className="text-sm">审计风格<select className={`${input} block mt-1`} disabled={busy} value={profile} onChange={e => { setPlan(null); setProfile(e.target.value as SkillAuditOptions["profile"]); }}><option value="stable">严谨</option><option value="balanced">均衡</option><option value="broad">探索</option></select></label>
        <label className="text-sm">总轮数<input className={`${input} block mt-1 w-28`} type="number" min={3} max={80} disabled={busy} value={rounds} onChange={e => { setPlan(null); setRounds(Number(e.target.value)); }} /></label>
        <label className="text-sm">总时间（秒）<input className={`${input} block mt-1 w-32`} type="number" min={30} max={3600} disabled={busy} value={seconds} onChange={e => { setPlan(null); setSeconds(Number(e.target.value)); }} /></label>
      </div>}
      {plan && <p className="text-sm text-slate-400">模型：{plan.model} · 总预算 {plan.budget.max_iterations} 轮 / {plan.budget.timeout_seconds} 秒。实际适用性在项目形态识别后记录。</p>}
      {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      <div className="flex gap-2 justify-end">
        {selected.length > 0 && <button type="button" className={button} disabled={busy || !validBudget} onClick={async () => { setBusy(true); setError(""); try { setPlan(await api.skillAuditPlan(scanId, options)); } catch (e) { setError(String(e)); } finally { setBusy(false); } }}>预览配置</button>}
        <button type="button" className={`${button} bg-indigo-600`} disabled={busy || !loaded || (selected.length > 0 && !validBudget)} onClick={() => void start()}>{busy ? "处理中…" : selected.length ? "开始 Skill 审计" : "开始默认审计"}</button>
      </div>
    </div>
  </div>, document.body);
}

export function SkillAuditHistory({ scanId, running }: { scanId: number; running: boolean }) {
  const [runs, setRuns] = useState<SkillAuditRun[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    const load = async () => { try { const data = await api.auditRuns(scanId); if (live) { setRuns(data); setError(""); } } catch (e) { if (live) setError(String(e)); } };
    setRuns([]); void load();
    const timer = running ? window.setInterval(() => void load(), 3000) : undefined;
    return () => { live = false; if (timer) window.clearInterval(timer); };
  }, [scanId, running]);
  if (!runs.length && !error) return null;
  return <section className="rounded-lg border border-slate-700 p-4 space-y-3">
    <h3 className="font-medium">Skill 审计运行记录</h3>
    {error && <p className="text-xs text-amber-300">运行记录加载失败：{error}</p>}
    {runs.map(run => <details key={run.id} className="rounded border border-slate-700 p-3" open={run.status === "running" || run.status === "queued"}>
      <summary className="cursor-pointer text-sm">#{run.id} · {states[run.status] || run.status} · {run.skills.map(s => `${s.name} ${s.version}`).join(" / ")} · {new Date(run.created_at).toLocaleString()}</summary>
      <p className="text-xs text-slate-400 mt-2">风格 {run.profile} · 模型 {run.model}。完成表示本次方法调查结束，不代表全项目无风险。</p>
      {run.error_message && <p className="text-xs text-amber-300">{run.error_message}</p>}
      {run.skills.map(s => <p key={s.id} className="text-xs text-slate-500 break-all">{s.id}@{s.version} · SHA-256 {s.sha256}</p>)}
      {run.results.map(result => <div key={result.id} className="mt-3 border-t border-slate-700 pt-2 text-xs space-y-1">
        <p>{result.id} · {states[result.status] || result.status} · {result.rounds} 轮 / {result.tools} 次工具调查 / {result.added} 条新增 / {result.candidates.length} 条候选</p>
        <p className="whitespace-pre-wrap text-slate-400">{result.summary}</p>
        <p className="break-all text-slate-500">已读取文件：{result.files_read.join("、") || "无"}</p>
        {result.candidates.length > 0 && <details><summary>待验证候选（不计入漏洞评分）</summary><pre className="max-h-64 overflow-auto whitespace-pre-wrap">{JSON.stringify(result.candidates, null, 2)}</pre></details>}
      </div>)}
    </details>)}
  </section>;
}
