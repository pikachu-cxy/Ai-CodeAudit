import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  type AgentChatMessage,
  type AgentAction,
  type AgentTaskItem,
  type AgentTaskMode,
  type DiffStatus,
  type LlmAuditJournalEntry,
  api,
  type CodeqlFlowGraph,
  type Finding,
  type FindingCategory,
  type ProjectSummary,
  type ReviewStatus,
  type ScanDiffSummary,
  type ScanEvent,
  type ScanScore,
  type ScanStats,
  type ScanSummary,
  type RetestResultsSummary,
} from "../api";
import { INJECTION_SUBTYPES, OWASP_SUBTYPES } from "../lib/owaspUtils";
import {
  capabilityStatusLabel,
  coverageSummaryLine,
  LIST_CAPABILITY_IDS,
  llmFocusStatusLabel,
  owaspStatusLabel,
  resolveScanCoverage,
  scannerStatusLabel,
  shouldShowCoveragePanel,
} from "../lib/scanCoverageUtils";
import { copyTextToClipboard } from "../lib/clipboard";
import { FindingClassificationFilter } from "./FindingClassificationFilter";
import { LlmAuditJournalPanel } from "./LlmAuditJournalPanel";
import { SkillAuditDialog, SkillAuditHistory } from "./AuditSkills";
import { SastDeepProgressPanel, type SastDeepJob } from "./SastDeepProgressPanel";
import { AgentPanel } from "./AgentPanel";
import { AuditChatBar } from "./AuditChatBar";
import { AuditReportHeader } from "./AuditReportHeader";
import { ProjectSettingsModal } from "./ProjectSettingsModal";
import { RetestResultsPanel } from "./RetestResultsPanel";
import { ScanDiffPanel } from "./ScanDiffPanel";
import { DIFF_STATUS_LABELS, ScanHistoryPanel } from "./ScanHistoryPanel";
import { VulnerabilityAuditTable } from "./VulnerabilityAuditTable";
import { FalsePositiveNoteModal } from "./FalsePositiveNoteModal";
import { ProjectWhitelistModal } from "./ProjectWhitelistModal";
import { RetestOptionsModal } from "./RetestOptionsModal";
import { WhitelistReasonModal } from "./WhitelistReasonModal";
import { StatsCharts } from "./StatsCharts";
import {
  AlertTriangle,
  Trash2,
  ToolbarButton,
} from "./ui";

type TabKey = "all" | "sast" | "llm";

interface Props {
  scanId: number;
  /** Bumped when global data should refresh (e.g. score rules saved). */
  refreshKey?: number;
  /** When false, view stays mounted but hidden (e.g. while viewing a finding). */
  isActive?: boolean;
  onDeleted: () => void;
  onScanUpdated?: () => void;
  onOpenFinding: (findingId: number) => void;
  onSelectScan?: (scanId: number, projectId?: number | null) => void;
  onOpenScanFinding?: (scanId: number, findingId: number, projectId?: number | null) => void;
  onAppendVersion?: (projectId: number) => void;
}

const TABS: { key: TabKey; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "sast", label: "SAST" },
  { key: "llm", label: "LLM发现漏洞" },
];

function tabToFindingCategories(tab: TabKey): FindingCategory[] | undefined {
  if (tab === "all") return undefined;
  if (tab === "llm") return ["business_logic", "authorization"];
  return [tab];
}

function llmFindingCount(byCategory?: Record<string, number>): number {
  if (!byCategory) return 0;
  if (byCategory.llm != null) return byCategory.llm;
  return (byCategory.business_logic ?? 0) + (byCategory.authorization ?? 0);
}

function tabFindingCount(tab: TabKey, byCategory?: Record<string, number>): number {
  if (tab === "llm") return llmFindingCount(byCategory);
  return byCategory?.[tab] ?? 0;
}

const PHASE_LABELS: Record<string, string> = {
  prepare: "解压/准备",
  scan: "扫描",
  persist: "入库",
  llm_fp: "LLM误报审计",
  llm: "LLM深度审计",
  done: "完成",
  error: "错误",
};

function isActiveSastDeepJob(job: SastDeepJob | null | undefined): job is SastDeepJob {
  return Boolean(job?.status);
}

function isDeepAuditUi(scan: ScanSummary | null, job: SastDeepJob | null | undefined): boolean {
  if (isActiveSastDeepJob(job) && (job.status === "running" || job.status === "queued")) {
    return true;
  }
  return Boolean(scan?.progress_message?.includes("深度研判"));
}

export function ScanDetailView({
  scanId,
  refreshKey = 0,
  isActive = true,
  onDeleted,
  onScanUpdated,
  onOpenFinding,
  onSelectScan,
  onOpenScanFinding,
  onAppendVersion,
}: Props) {
  const mainScrollRef = useRef<HTMLDivElement>(null);
  const savedScrollTop = useRef(0);
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [project, setProject] = useState<ProjectSummary | null>(null);
  const [projectScans, setProjectScans] = useState<ScanSummary[]>([]);
  const [scanDiff, setScanDiff] = useState<ScanDiffSummary | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [filterDiff, setFilterDiff] = useState<DiffStatus | "">("");
  const [retesting, setRetesting] = useState(false);
  const [fullScanning, setFullScanning] = useState(false);
  const [retestResults, setRetestResults] = useState<RetestResultsSummary | null>(null);
  const [retestLoading, setRetestLoading] = useState(false);
  const [retestError, setRetestError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalFiltered, setTotalFiltered] = useState(0);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [scanScore, setScanScore] = useState<ScanScore | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [codeqlGraph, setCodeqlGraph] = useState<CodeqlFlowGraph | null>(null);
  const [agentMessages, setAgentMessages] = useState<AgentChatMessage[]>([]);
  const [agentActions, setAgentActions] = useState<AgentAction[]>([]);
  const [lastAgentAction, setLastAgentAction] = useState<string | null>(null);
  const [lastAgentActionResult, setLastAgentActionResult] = useState<string | null>(null);
  const [chatting, setChatting] = useState(false);
  const [activeTab, setActiveTab] = useState<TabKey>("all");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterVerdict, setFilterVerdict] = useState("");
  const [filterReview, setFilterReview] = useState("");
  const [filterExternal, setFilterExternal] = useState("");
  const [filterTool, setFilterTool] = useState("");
  const [filterOwasp, setFilterOwasp] = useState("");
  const [filterSubtype, setFilterSubtype] = useState("");
  const [filterQ, setFilterQ] = useState("");
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState(1);
  const [analyzing, setAnalyzing] = useState(false);
  const [sastDeepAuditing, setSastDeepAuditing] = useState(false);
  const [sastDeepJob, setSastDeepJob] = useState<SastDeepJob | null>(null);
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<number>>(() => new Set());
  const [exploitabilityModeOpen, setExploitabilityModeOpen] = useState(false);
  const [llmReviewing, setLlmReviewing] = useState(false);
  const [llmPausing, setLlmPausing] = useState(false);
  const [scanPausing, setScanPausing] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startNotice, setStartNotice] = useState<string | null>(null);
  const [llmAuditNotice, setLlmAuditNotice] = useState<string | null>(null);
  const [skillDialogOpen, setSkillDialogOpen] = useState(false);
  const [llmJournal, setLlmJournal] = useState<LlmAuditJournalEntry[]>([]);
  const [rerunning, setRerunning] = useState(false);
  const [reviewingId, setReviewingId] = useState<number | null>(null);
  const [fpModalFindingId, setFpModalFindingId] = useState<number | null>(null);
  const [fpNotice, setFpNotice] = useState<string | null>(null);
  const [whitelistModalOpen, setWhitelistModalOpen] = useState(false);
  const [whitelisting, setWhitelisting] = useState(false);
  const [whitelistNotice, setWhitelistNotice] = useState<string | null>(null);
  const [projectWhitelistOpen, setProjectWhitelistOpen] = useState(false);
  /** 打开复测弹窗时记录本次是定向还是全量。 */
  const [retestMode, setRetestMode] = useState<"targeted" | "full" | null>(null);
  const [taskNotice, setTaskNotice] = useState<string | null>(null);
  const [taskItems, setTaskItems] = useState<AgentTaskItem[]>([]);
  const [taskMode, setTaskMode] = useState<AgentTaskMode | null>(null);
  const [highlightedFindingIds, setHighlightedFindingIds] = useState<Set<number>>(new Set());
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [projectLinkUrl, setProjectLinkUrl] = useState<string | null>(null);
  const [projectLinkActive, setProjectLinkActive] = useState(false);
  const [projectLinkExpires, setProjectLinkExpires] = useState<string | null>(null);
  const [projectLinkBusy, setProjectLinkBusy] = useState(false);
  const [projectLinkNotice, setProjectLinkNotice] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [archiving, setArchiving] = useState(false);

  useLayoutEffect(() => {
    const el = mainScrollRef.current;
    if (!el) return;
    if (!isActive) return;
    const top = savedScrollTop.current;
    if (top <= 0) return;
    el.scrollTop = top;
    // Re-apply after layout/paint in case child content reflows.
    const t1 = requestAnimationFrame(() => {
      if (mainScrollRef.current) mainScrollRef.current.scrollTop = top;
    });
    const t2 = window.setTimeout(() => {
      if (mainScrollRef.current) mainScrollRef.current.scrollTop = top;
    }, 50);
    return () => {
      cancelAnimationFrame(t1);
      window.clearTimeout(t2);
    };
  }, [isActive]);

  const openFindingKeepingScroll = (findingId: number) => {
    savedScrollTop.current = mainScrollRef.current?.scrollTop ?? savedScrollTop.current;
    onOpenFinding(findingId);
  };

  const findingParams = {
    category: activeTab === "all" ? undefined : activeTab,
    severity: filterSeverity || undefined,
    verdict: filterVerdict || undefined,
    review: filterReview || undefined,
    external: filterExternal || undefined,
    tool: filterTool || undefined,
    owasp: filterOwasp || undefined,
    subtype: filterSubtype || undefined,
    q: filterQ || undefined,
  };

  const loadJournal = async () => {
    try {
      const journal = await api.getLlmAuditJournal(scanId, 300);
      setLlmJournal(journal);
    } catch {
      /* ignore */
    }
  };

  const loadProjectLink = async () => {
    try {
      const link = await api.getProjectReviewLink(scanId);
      setProjectLinkActive(link.token_active);
      setProjectLinkExpires(link.expires_at || null);
      setProjectLinkUrl(link.token_active && link.url ? link.url : null);
    } catch {
      setProjectLinkActive(false);
      setProjectLinkUrl(null);
      setProjectLinkExpires(null);
    }
  };

  const createProjectLink = async () => {
    setProjectLinkBusy(true);
    setProjectLinkNotice(null);
    try {
      const link = await api.createProjectReviewLink(scanId, { expires_hours: 168 });
      setProjectLinkActive(link.token_active);
      setProjectLinkExpires(link.expires_at || null);
      setProjectLinkUrl(link.url || null);
      if (link.url) {
        const ok = await copyTextToClipboard(link.url);
        setProjectLinkNotice(
          ok ? "项目确认链接已生成并复制到剪贴板（默认 7 天有效）" : "项目确认链接已生成，请手动复制下方链接"
        );
      }
    } catch (e) {
      setProjectLinkNotice(String(e));
    } finally {
      setProjectLinkBusy(false);
    }
  };

  const copyProjectLink = async () => {
    if (!projectLinkUrl) return;
    const ok = await copyTextToClipboard(projectLinkUrl);
    setProjectLinkNotice(ok ? "链接已复制到剪贴板" : "复制失败，请手动选择下方链接");
  };

  const revokeProjectLink = async () => {
    if (!confirm("确定撤销项目确认链接？已发出的链接将立即失效。")) return;
    setProjectLinkBusy(true);
    setProjectLinkNotice(null);
    try {
      await api.revokeProjectReviewLink(scanId);
      setProjectLinkActive(false);
      setProjectLinkUrl(null);
      setProjectLinkNotice("项目确认链接已撤销");
    } catch (e) {
      setProjectLinkNotice(String(e));
    } finally {
      setProjectLinkBusy(false);
    }
  };

  const load = async () => {
    setLoadError(null);
    const [s, f, st, ev, graph, chatHistory, chatActions, score] = await Promise.all([
      api.getScan(scanId),
      api.getFindingsPage(scanId, {
        ...findingParams,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      }),
      api.getStats(scanId),
      api.getEvents(scanId, 300),
      api.getCodeqlFlowGraph(scanId).catch(() => null),
      api.getAgentChatHistory(scanId, 30).catch(() => []),
      api.getAgentChatActions(scanId, 12).catch(() => []),
      api.getScanScore(scanId).catch(() => null),
    ]);
    setScan(s);
    setFindings(f.items);
    setTotalFiltered(f.total);
    setStats(st);
    setScanScore(score);
    setEvents(ev);
    setCodeqlGraph(graph);
    setAgentMessages(chatHistory);
    setAgentActions(chatActions);
    await loadJournal();
    await loadProjectLink();
  };

  /** Light progress poll: summary only (no findings dump / heavy panels). */
  const pollProgress = async () => {
    const s = await api.getScan(scanId);
    setScan((prev) => {
      const prevStatus = prev?.status;
      const prevFindings = prev?.total_findings;
      if (prevStatus && prevStatus !== s.status && ["completed", "failed"].includes(s.status)) {
        // Full hydrate after terminal transition (async, outside setState).
        queueMicrotask(() => {
          load().catch((e) => setLoadError(String(e)));
        });
      } else if (prevFindings != null && prevFindings !== s.total_findings) {
        queueMicrotask(() => {
          Promise.all([
            api.getFindingsPage(scanId, {
              ...findingParams,
              limit: pageSize,
              offset: (page - 1) * pageSize,
            }),
            api.getStats(scanId),
          ])
            .then(([f, st]) => {
              setFindings(f.items);
              setTotalFiltered(f.total);
              setStats(st);
              if (st.security_score != null) {
                setScanScore((sc) =>
                  sc
                    ? { ...sc, score: st.security_score as number }
                    : sc
                );
              }
            })
            .catch(() => {});
        });
      }
      return s;
    });
    if (s.security_score != null) {
      const cachedScore = s.security_score;
      setScanScore((sc) =>
        sc
          ? { ...sc, score: cachedScore }
          : {
              scan_id: s.id,
              project_id: s.project_id,
              score: cachedScore,
              max_score: 100,
              by_severity: {},
              counted_findings: s.total_findings,
              excluded_findings: 0,
              weights: {},
              has_critical: false,
              deduction: 0,
              deduction_detail: [],
              exclude_ai_fp: true,
              status: s.status,
              completed_at: s.completed_at,
              branch: s.branch,
              source_url: s.source_url,
            }
      );
    }
  };

  const loadProjectContext = async (s: ScanSummary) => {
    if (!s.project_id) {
      setProject(null);
      setProjectScans([]);
      setScanDiff(null);
      setDiffError(null);
      return;
    }
    try {
      const [p, scans] = await Promise.all([
        api.getProject(s.project_id),
        api.listProjectScans(s.project_id),
      ]);
      setProject(p);
      setProjectScans(scans);
    } catch {
      setProject(null);
      setProjectScans([]);
    }

    const shouldDiff =
      s.scan_kind === "retest" ||
      s.parent_scan_id != null ||
      Boolean(s.project_id);
    if (!shouldDiff || s.status === "pending") {
      setScanDiff(null);
      setDiffError(null);
    } else {
      setDiffLoading(true);
      setDiffError(null);
      try {
        let diff = null as Awaited<ReturnType<typeof api.getScanDiff>> | null;
        for (let attempt = 0; attempt < 2; attempt++) {
          try {
            diff = await api.getScanDiff(s.id, s.parent_scan_id ?? undefined);
            break;
          } catch (e) {
            const msg = String(e);
            if (/baseline scan not found/i.test(msg)) {
              diff = null;
              break;
            }
            if (attempt === 0 && /Failed to fetch|无法连接后端/i.test(msg)) {
              await new Promise((resolve) => setTimeout(resolve, 800));
              continue;
            }
            throw e;
          }
        }
        setScanDiff(diff);
        setDiffError(null);
      } catch (e) {
        setScanDiff(null);
        const msg = String(e);
        if (/baseline scan not found/i.test(msg)) {
          setDiffError(null);
        } else if (/Failed to fetch|无法连接后端/i.test(msg) && s.status !== "completed" && s.status !== "failed") {
          // Backend may be reloading while scan is still running; polling will retry.
          setDiffError(null);
        } else {
          setDiffError(`对比不可用: ${msg}`);
        }
      } finally {
        setDiffLoading(false);
      }
    }

    const shouldRetest = s.scan_kind === "retest" || s.parent_scan_id != null;
    if (!shouldRetest || s.status === "pending") {
      setRetestResults(null);
      setRetestError(null);
      return;
    }
    setRetestLoading(true);
    setRetestError(null);
    try {
      const results = await api.getRetestResults(s.id);
      setRetestResults(results);
    } catch (e) {
      setRetestResults(null);
      const msg = String(e);
      if (/not a retest scan/i.test(msg)) {
        setRetestError(null);
      } else {
        setRetestError(`定向复测结果不可用: ${msg}`);
      }
    } finally {
      setRetestLoading(false);
    }
  };

  useEffect(() => {
    if (!scan) return;
    loadProjectContext(scan).catch(() => {});
    // Omit total_findings — progress ticks must not re-fetch heavy diff/history.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.id, scan?.project_id, scan?.parent_scan_id, scan?.scan_kind, scan?.status]);

  useEffect(() => {
    setFilterDiff('');
  }, [scanId]);

  const diffFilteredFindings = useMemo(() => {
    if (!filterDiff) return findings;
    if (!scanDiff) return [];
    if (filterDiff === 'fixed') {
      return scanDiff.items
        .filter((i) => i.status === 'fixed' && i.baseline)
        .map((i) => i.baseline!) as Finding[];
    }
    return scanDiff.items
      .filter((i) => i.status === filterDiff && i.current)
      .map((i) => i.current!) as Finding[];
  }, [findings, filterDiff, scanDiff]);

  const effectiveTotal = filterDiff ? diffFilteredFindings.length : totalFiltered;
  const totalPages = Math.max(1, Math.ceil(effectiveTotal / pageSize));
  const from = effectiveTotal === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(effectiveTotal, page * pageSize);
  const displayedFindings = useMemo(() => {
    if (!filterDiff) return findings;
    const start = (page - 1) * pageSize;
    return diffFilteredFindings.slice(start, start + pageSize);
  }, [filterDiff, findings, diffFilteredFindings, page, pageSize]);

  useEffect(() => {
    loadProjectLink().catch(() => {});
  }, [scanId]);

  // Full hydrate on open / settings refresh; pause while inactive (finding detail overlay).
  useEffect(() => {
    if (!isActive) return;
    load().catch((e) => setLoadError(String(e)));
  }, [scanId, refreshKey, isActive]);

  // Light progress polling only while running and view is active.
  useEffect(() => {
    if (!isActive) return;
    if (!scan?.status || ['completed', 'failed', 'pending'].includes(scan.status)) {
      return;
    }
    const ms =
      scan.status === 'llm_auditing' || scan.status === 'scanning' || scan.status === 'analyzing'
        ? 2000
        : 4000;
    const timer = setInterval(() => {
      pollProgress().catch((e) => setLoadError(String(e)));
    }, ms);
    return () => clearInterval(timer);
  }, [scanId, scan?.status, isActive]);

  // 启动瞬间若网络闪断，可能留下 Failed to fetch 提示；任务实际在跑时清掉误报。
  useEffect(() => {
    if (!scan || !startNotice) return;
    if (['scanning', 'analyzing', 'llm_auditing', 'cloning'].includes(scan.status)) {
      if (/Failed to fetch|无法连接后端/i.test(startNotice)) {
        setStartNotice(null);
      }
    }
  }, [scan?.status, startNotice]);

  useEffect(() => {
    if (!isActive) return;
    if (scan?.status !== 'llm_auditing') return;
    loadJournal();
    const timer = setInterval(() => {
      loadJournal();
    }, 3000);
    return () => clearInterval(timer);
  }, [scanId, scan?.status, isActive]);

  useEffect(() => {
    if (!isActive) return;
    const shouldPoll =
      sastDeepAuditing ||
      sastDeepJob?.status === 'running' ||
      Boolean(scan?.progress_message?.includes('深度研判'));
    if (!shouldPoll) return;

    let cancelled = false;
    const tick = async () => {
      try {
        const prog = await api.getSastDeepProgress(scanId);
        if (cancelled) return;
        if (isActiveSastDeepJob(prog.job)) {
          setSastDeepJob(prog.job);
          const st = prog.job.status;
          if (st === 'running') {
            setSastDeepAuditing(true);
          } else if (st === 'done' || st === 'failed' || st === 'cancelled') {
            setSastDeepAuditing(false);
            setFpNotice(prog.job.message || (st === 'done' ? '深度研判完成' : '深度研判已结束'));
            await load();
          }
        } else if (prog.scan_status !== 'analyzing' && sastDeepAuditing) {
          // 后台已结束但内存进度已清
          setSastDeepAuditing(false);
          await load();
        }
      } catch {
        /* ignore transient poll errors */
      }
    };
    tick();
    const timer = setInterval(tick, 1500);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [scanId, scan?.status, scan?.progress_message, sastDeepAuditing, sastDeepJob?.status, isActive]);

  useEffect(() => {
    if (!filterOwasp) {
      if (filterSubtype) setFilterSubtype("");
      return;
    }
    if (!filterSubtype) return;
    const allowed = OWASP_SUBTYPES[filterOwasp] || [];
    if (!allowed.includes(filterSubtype)) setFilterSubtype("");
  }, [filterOwasp, filterSubtype]);

  useEffect(() => {
    setPage(1);
  }, [scanId, activeTab, filterSeverity, filterVerdict, filterReview, filterExternal, filterTool, filterOwasp, filterSubtype, filterQ, pageSize]);

  useEffect(() => {
    api
      .getFindingsPage(scanId, {
        ...findingParams,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      })
      .then((r) => {
        setFindings(r.items);
        setTotalFiltered(r.total);
      })
      .catch((e) => setLoadError(String(e)));
  }, [scanId, activeTab, filterSeverity, filterVerdict, filterReview, filterExternal, filterTool, filterOwasp, filterSubtype, filterQ, page, pageSize]);

  useEffect(() => {
    setSelectedFindingIds(new Set());
  }, [scanId]);

  const toggleSelectFinding = (id: number) => {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectPage = (ids: number[], selected: boolean) => {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (selected) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  };

  const selectHighOnPage = () => {
    const ids = findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").map((f) => f.id);
    toggleSelectPage(ids, true);
  };

  const clearSelection = () => setSelectedFindingIds(new Set());

  const runFpAnalyze = async (findingIds?: number[]) => {
    const ids = findingIds?.length ? findingIds : Array.from(selectedFindingIds);
    if (!ids.length) {
      setFpNotice("请先勾选要研判的漏洞");
      return;
    }
    setAnalyzing(true);
    setFpNotice(null);
    try {
      const result = await api.analyze(scanId, {
        finding_ids: ids,
        max_findings: ids.length,
        force: true,
      });
      setFpNotice(result.message || `已对 ${ids.length} 条完成快速研判`);
      await load();
    } catch (e) {
      setFpNotice(String(e));
    } finally {
      setAnalyzing(false);
    }
  };

  const runSastDeepAudit = async (findingIds?: number[]) => {
    const ids = findingIds?.length ? findingIds : Array.from(selectedFindingIds);
    if (!ids.length) {
      setFpNotice("请先勾选要研判的漏洞");
      setSastDeepJob(null);
      return;
    }
    setSastDeepAuditing(true);
    setFpNotice(null);
    setSastDeepJob({
      status: "running",
      message: `正在启动深度研判（已选 ${ids.length} 条）…`,
      percent: 1,
      tasks: [],
    });
    try {
      const result = await api.sastDeepAudit(scanId, {
        finding_ids: ids,
        max_findings: ids.length,
        force: true,
      });
      setFpNotice(result.message);
      await load();
      if (result.started === false) {
        setSastDeepJob(null);
        setSastDeepAuditing(false);
      }
    } catch (e) {
      setFpNotice(String(e));
      setSastDeepJob(null);
      setSastDeepAuditing(false);
    }
  };

  const runExploitabilityAudit = async (mode: "fast" | "deep") => {
    const ids = Array.from(selectedFindingIds);
    if (!ids.length) {
      setFpNotice("请先在列表勾选要研判的漏洞，再选择模式");
      return;
    }
    setExploitabilityModeOpen(false);
    if (mode === "deep") {
      await runSastDeepAudit(ids);
      return;
    }
    await runFpAnalyze(ids);
  };

  const runLlmReview = async () => {
    setLlmReviewing(true);
    setFpNotice(null);
    try {
      const result = await api.llmReview(scanId, { max_findings: 50 });
      setFpNotice(result.message);
      await load();
    } catch (e) {
      setFpNotice(String(e));
    } finally {
      setLlmReviewing(false);
    }
  };

  const runLlmAudit = async () => {
    setLlmAuditNotice(null);
    setLlmJournal([]);
    const verifyOnly = scan?.scan_kind === "retest" && scan.parent_scan_id != null;
    try {
      await api.llmAudit(scanId);
      setLlmAuditNotice(
        verifyOnly
          ? "已改为核实上次 LLM 发现是否修复，不会重新发现新漏洞。"
          : "LLM 端点审计已启动：业务理解 → 预调查 → 自主验证（LLM 自行决定何时结束）。"
      );
      await load();
      await loadJournal();
    } catch (e) {
      setLlmAuditNotice(String(e));
      await load();
    }
  };

  const pauseScan = async () => {
    const setNotice = scan?.status === "llm_auditing" ? setLlmAuditNotice : setStartNotice;
    if (scan?.status === "llm_auditing") setLlmPausing(true);
    else setScanPausing(true);
    try {
      const r =
        scan?.status === "llm_auditing"
          ? await api.cancelLlmAudit(scanId)
          : await api.cancelScan(scanId);
      // Optimistic feedback so users immediately see pause-in-progress.
      if (scan?.status === "llm_auditing") {
        setScan((prev) =>
          prev ? { ...prev, progress_message: "正在暂停 LLM 端点审计…" } : prev
        );
      }
      setNotice(r.message);
      await load();
      if (scan?.status === "llm_auditing") {
        await loadJournal();
      }
    } catch (e) {
      setNotice(String(e));
    } finally {
      setScanPausing(false);
      setLlmPausing(false);
    }
  };

  const startScan = async () => {
    setStarting(true);
    setStartNotice(null);
    // Optimistic UI: show scanning immediately so a slow/interrupted HTTP reply
    // does not look like a total backend outage.
    setScan((prev) =>
      prev
        ? {
            ...prev,
            status: "scanning",
            progress: Math.max(prev.progress || 0, 5),
            progress_message: "SAST 扫描启动中…",
          }
        : prev
    );
    try {
      await api.startScan(scanId);
      setStartNotice("扫描已启动");
      await load();
    } catch (e) {
      // 启动接口偶发断连时，后端任务可能已经起来了——用状态兜底，避免误报 Failed to fetch。
      try {
        const latest = await api.getScan(scanId);
        setScan(latest);
        if (["scanning", "analyzing", "cloning"].includes(latest.status)) {
          setStartNotice("扫描已在后台启动（网络响应中断，任务仍在进行）");
          await load();
          return;
        }
        setStartNotice(String(e));
      } catch {
        setStartNotice(String(e));
      }
    } finally {
      setStarting(false);
    }
  };

  const runRerun = async () => {
    if (
      !confirm(
        "确定清空并重置此任务？\n\n将删除全部发现（含 LLM）与审计日志，恢复为「等待扫描」状态。\n不会自动开始扫描；若只想重跑 Semgrep/CodeQL 并保留 LLM 结果，请改用「重新跑 SAST」。"
      )
    ) {
      return;
    }
    setRerunning(true);
    setStartNotice(null);
    setLlmAuditNotice(null);
    setFpNotice(null);
    try {
      const summary = await api.rerun(scanId);
      setScan(summary);
      setFindings([]);
      setTotalFiltered(0);
      setStats(null);
      setScanScore(null);
      setEvents([]);
      setLlmJournal([]);
      setCodeqlGraph(null);
      setStartNotice("已清空并重置，可点击「开始 SAST 扫描」重新开始");
      await load();
    } catch (e) {
      setStartNotice(`清空并重置失败: ${e}`);
    } finally {
      setRerunning(false);
    }
  };

  /** 打开复测弹窗；真正的创建在 submitRetest 里（需要先选分支）。 */
  const openRetest = (mode: "targeted" | "full") => {
    if (!scan?.project_id) {
      alert(
        mode === "full" ? "当前扫描未归属项目，无法全量扫描" : "当前扫描未归属项目，无法复测"
      );
      return;
    }
    setRetestMode(mode);
  };

  const retestScopeHint = () => {
    if (retestMode === "full") {
      return "将重新运行完整 SAST/SCA 流水线，耗时较长。不会覆盖本轮结果。";
    }
    return selectedFindingIds.size > 0
      ? `将仅核实已勾选的 ${selectedFindingIds.size} 条漏洞（含未确认与误报，以你的勾选为准）。`
      : "将核实基线全部非误报漏洞（含 LLM 与 SAST），已标记误报的不包含。";
  };

  const submitRetest = async (branch: string | null) => {
    const mode = retestMode;
    if (!scan?.project_id || !mode) return;
    const selectedIds =
      selectedFindingIds.size > 0 ? Array.from(selectedFindingIds) : undefined;
    const setBusy = mode === "full" ? setFullScanning : setRetesting;
    setRetestMode(null);
    setBusy(true);
    try {
      const created = await api.retestScan(scanId, {
        auto_start: true,
        strategy: mode,
        branch: branch ?? undefined,
        finding_ids: mode === "targeted" ? selectedIds : undefined,
      });
      onScanUpdated?.();
      onSelectScan?.(created.id, created.project_id);
    } catch (e) {
      const msg = String(e);
      if (
        /重新上传|upload|新版本|上传型项目无法直接复测|追加新版本/i.test(msg) &&
        scan.project_id
      ) {
        alert(msg);
        onAppendVersion?.(scan.project_id);
      } else {
        alert(`${mode === "full" ? "全量扫描" : "定向复测"}失败: ${msg}`);
      }
    } finally {
      setBusy(false);
    }
  };

  const runRetest = () => openRetest("targeted");

  const runFullScan = () => openRetest("full");

  const openWhitelistModal = () => {
    if (!scan?.project_id) {
      alert("当前扫描未归属项目，无法加白");
      return;
    }
    if (selectedFindingIds.size === 0) {
      alert("请先勾选要加入白名单的漏洞");
      return;
    }
    setWhitelistNotice(null);
    setWhitelistModalOpen(true);
  };

  const confirmWhitelist = async (reason: string) => {
    if (!scan?.project_id) return;
    const ids = Array.from(selectedFindingIds);
    setWhitelistModalOpen(false);
    setWhitelisting(true);
    setWhitelistNotice(null);
    try {
      for (const id of ids) {
        await api.addProjectWhitelist(scan.project_id, { finding_id: id, reason });
      }
      setWhitelistNotice(`已加入白名单 ${ids.length} 条，后续扫描不再上报`);
      clearSelection();
      await load();
      onScanUpdated?.();
    } catch (e) {
      alert(`加入白名单失败: ${String(e)}`);
    } finally {
      setWhitelisting(false);
    }
  };

  const handleReview = async (findingId: number, status: ReviewStatus, reviewNote?: string) => {
    if (status === "false_positive" && !reviewNote) {
      setFpModalFindingId(findingId);
      return;
    }
    setReviewingId(findingId);
    setReviewError(null);
    try {
      await api.reviewFinding(scanId, findingId, {
        review_status: status,
        review_note: reviewNote,
      });
    } catch (e) {
      setReviewError(String(e));
      return;
    } finally {
      // Re-enable buttons as soon as the review mutation finishes.
      // Loading the whole findings page can be slow; we don't want the UI to feel "stuck".
      setReviewingId(null);
    }
    try {
      await load();
    } catch (e) {
      setReviewError(String(e));
    }
  };

  const confirmFalsePositive = async (note: string) => {
    if (fpModalFindingId == null) return;
    const findingId = fpModalFindingId;
    setFpModalFindingId(null);
    await handleReview(findingId, "false_positive", note);
  };

  const handleDelete = async () => {
    if (!confirm("确定删除此扫描任务？此操作不可恢复。")) return;
    setDeleteError(null);
    try {
      await api.deleteScan(scanId);
      onDeleted();
    } catch (e) {
      setDeleteError(String(e));
    }
  };

  const handleArchive = async () => {
    if (!scan) return;
    const label = project?.name || scan.name;
    if (!confirm(`归档项目「${label}」？归档后将从主列表隐藏。`)) return;
    setArchiving(true);
    try {
      if (scan.project_id) {
        await api.archiveProject(scan.project_id);
        onScanUpdated?.();
        onDeleted();
      } else {
        const updated = await api.archiveScan(scanId);
        setScan(updated);
        onScanUpdated?.();
      }
    } catch (e) {
      alert(String(e));
    } finally {
      setArchiving(false);
    }
  };

  const handleUnarchive = async () => {
    if (!scan) return;
    setArchiving(true);
    try {
      if (scan.project_id) {
        await api.unarchiveProject(scan.project_id);
        const p = await api.getProject(scan.project_id);
        setProject(p);
        onScanUpdated?.();
      } else {
        const updated = await api.unarchiveScan(scanId);
        setScan(updated);
        onScanUpdated?.();
      }
    } catch (e) {
      alert(String(e));
    } finally {
      setArchiving(false);
    }
  };

  const handleChat = async (text: string) => {
    setChatting(true);
    try {
      const result = await api.agentChat(scanId, { message: text, max_history: 16 });
      setAgentMessages(result.messages || []);
      setLastAgentAction(result.action || null);
      setLastAgentActionResult(result.action_result || null);
      if (result.action_history) {
        setAgentActions(result.action_history);
      }
      if (result.action_result) {
        setFpNotice(result.action_result);
      }
      await load();
    } catch (e) {
      setFpNotice(`Agent 对话失败: ${e}`);
    } finally {
      setChatting(false);
    }
  };

  const handleRunTask = async (mode: AgentTaskMode) => {
    setChatting(true);
    setTaskNotice(null);
    setTaskMode(mode);
    try {
      const result = await api.runAgentTask(scanId, {
        mode,
        scope: {
          max_items: 12,
          categories: tabToFindingCategories(activeTab),
        },
        options: { top_n: 12 },
      });
      const items = result.items || [];
      setTaskItems(items);
      setTaskNotice(result.summary || "任务已完成");
      const ids = new Set(
        items.map((item) => item.finding_id).filter((id): id is number => typeof id === "number"),
      );
      setHighlightedFindingIds(ids);
    } catch (e) {
      setTaskNotice(`任务执行失败: ${e}`);
      setTaskItems([]);
      setHighlightedFindingIds(new Set());
    } finally {
      setChatting(false);
    }
  };

  const clearTaskResults = () => {
    setTaskNotice(null);
    setTaskItems([]);
    setTaskMode(null);
    setHighlightedFindingIds(new Set());
  };

  const highlightedCount = useMemo(() => highlightedFindingIds.size, [highlightedFindingIds]);
  const llmAuditSummary = useMemo(() => {
    const settings = llmJournal.find((e) => e.type === "settings_snapshot");
    const domains = llmJournal.find((e) => e.type === "domain_selection");
    const coverage = [...llmJournal].reverse().find((e) => e.type === "coverage_summary");
    const finish = [...llmJournal].reverse().find((e) => e.type === "finish_reason");
    return { settings, domains, coverage, finish };
  }, [llmJournal]);

  // 报告生成器需要的选择状态与筛选快照。必须 memo，
  // 否则每次渲染都会产生新引用，导致弹窗内的范围预览反复请求。
  // 注意：必须放在 `if (!scan)` 提前返回之前，否则 Hook 数量会在
  // 首屏（scan 为 null）与数据到达后发生变化，触发 Rules of Hooks 报错。
  const selectedIdsArray = useMemo(() => Array.from(selectedFindingIds), [selectedFindingIds]);
  const reportFilterDraft = useMemo(
    () => ({
      category: activeTab,
      severity: filterSeverity,
      verdict: filterVerdict,
      review: filterReview,
      external: filterExternal,
      tool: filterTool,
      owasp: filterOwasp,
      subtype: filterSubtype,
      keyword: filterQ,
    }),
    [
      activeTab,
      filterSeverity,
      filterVerdict,
      filterReview,
      filterExternal,
      filterTool,
      filterOwasp,
      filterSubtype,
      filterQ,
    ]
  );

  if (!scan) {
    return (
      <div className="text-center py-20 text-slate-400 space-y-3">
        <p>加载中...</p>
        {loadError && (
          <p className="text-sm text-red-300">加载失败: {loadError}</p>
        )}
        <button className="btn-ghost text-sm" onClick={() => onDeleted()}>返回</button>
      </div>
    );
  }

  const scanCoverage = resolveScanCoverage(scan);
  const shownCapabilityIds = new Set<string>([
    ...LIST_CAPABILITY_IDS,
    ...INJECTION_SUBTYPES,
    "path_traversal",
    "ssrf",
    "hardcoded_secret",
    "deserialization",
    "python_security",
  ]);
  const injectionCapIds = new Set<string>([
    ...INJECTION_SUBTYPES,
    "path_traversal",
    "ssrf",
  ]);
  const otherCapIds = new Set(
    [...shownCapabilityIds].filter((id) => !injectionCapIds.has(id)),
  );

  const toolOptions = stats ? Object.keys(stats.by_tool) : [];
  const isPending = scan.status === "pending";
  const canPause = ["scanning", "analyzing", "llm_auditing"].includes(scan.status);
  const isRunning = !["completed", "failed", "pending"].includes(scan.status);
  const isPausing = scanPausing || llmPausing;
  const showDeepAudit = isDeepAuditUi(scan, sastDeepJob);
  // LLM 端点审计可先于 SAST；结束后状态为 completed，仍应能单独启动 SAST。
  const hasSastRun =
    Boolean(scan.scanner_summary && scan.scanner_summary !== "[]") ||
    (stats?.by_category?.sast ?? 0) > 0;
  const canStartSast = isPending || ["completed", "failed"].includes(scan.status);
  const clearFilters = () => {
    setFilterTool("");
    setFilterReview("");
    setFilterExternal("");
    setFilterSeverity("");
    setFilterVerdict("");
    setFilterOwasp("");
    setFilterSubtype("");
    setFilterQ("");
    setFilterDiff("");
  };

  const canArchive =
    !["scanning", "analyzing", "llm_auditing"].includes(scan.status) &&
    !scan.archived_at &&
    !project?.archived_at;
  const canUnarchive = Boolean(scan.archived_at || project?.archived_at);
  const hasActiveFilters = Boolean(
    filterTool ||
      filterReview ||
      filterExternal ||
      filterSeverity ||
      filterVerdict ||
      filterOwasp ||
      filterSubtype ||
      filterQ ||
      filterDiff
  );

  const handleOwaspChange = (id: string) => {
    setFilterOwasp(id);
    setFilterSubtype("");
  };

  const handleSubtypeChange = (_owaspId: string, subtypeId: string) => {
    setFilterSubtype(subtypeId);
  };

  return (
    <div className="flex flex-1 min-h-0 h-full">
      {skillDialogOpen && <SkillAuditDialog scanId={scanId} projectId={scan.project_id} onClose={() => setSkillDialogOpen(false)} onStarted={async () => {
        setLlmAuditNotice("深度审计已启动，可在运行记录查看实际进度与覆盖范围。");
        setLlmJournal([]); await load(); await loadJournal();
      }} />}
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <div
          ref={mainScrollRef}
          className="flex-1 overflow-auto p-5 space-y-4"
          onScroll={(e) => {
            savedScrollTop.current = e.currentTarget.scrollTop;
          }}
        >
          {scan && stats && (
            <AuditReportHeader
              scan={scan}
              stats={stats}
              score={scanScore}
              project={project}
              onEdit={() => setSettingsOpen(true)}
              selectedFindingIds={selectedIdsArray}
              reportFilterDraft={reportFilterDraft}
            />
          )}

          {scan.project_id && (
            <ScanHistoryPanel
              scans={projectScans}
              currentScanId={scanId}
              onSelectScan={(id) => onSelectScan?.(id, scan.project_id)}
              onRetest={runRetest}
              onAppendVersion={
                scan.project_id ? () => onAppendVersion?.(scan.project_id!) : undefined
              }
              retesting={retesting}
            />
          )}

          {(retestResults || retestLoading || retestError) && (
            <RetestResultsPanel
              results={retestResults}
              loading={retestLoading}
              error={retestError}
              onOpenBaselineFinding={(baselineScanId, findingId) =>
                onOpenScanFinding?.(baselineScanId, findingId, scan.project_id)
              }
              onOpenCurrentFinding={(currentScanId, findingId) =>
                onOpenScanFinding?.(currentScanId, findingId, scan.project_id)
              }
            />
          )}

          {(scanDiff || diffLoading || diffError) && (
            <ScanDiffPanel
              diff={scanDiff}
              loading={diffLoading}
              error={diffError}
              filterDiff={filterDiff}
              onFilterDiff={setFilterDiff}
              onOpenBaselineFinding={(baselineScanId, findingId) =>
                onOpenScanFinding?.(baselineScanId, findingId, scan.project_id)
              }
              onOpenCurrentFinding={(currentScanId, findingId) =>
                onOpenScanFinding?.(currentScanId, findingId, scan.project_id)
              }
            />
          )}

          <div className="flex gap-2 flex-wrap justify-end">
            {scan.project_id && (
              <>
                <ToolbarButton onClick={runRetest} disabled={retesting || fullScanning || isRunning} running={retesting}>
                  {retesting
                    ? "定向复测中…"
                    : selectedFindingIds.size > 0
                      ? `定向复测（已选 ${selectedFindingIds.size}）`
                      : "定向复测"}
                </ToolbarButton>
                <ToolbarButton
                  onClick={runFullScan}
                  disabled={fullScanning || retesting || isRunning}
                  running={fullScanning}
                >
                  {fullScanning ? "全量扫描中…" : "全量扫描"}
                </ToolbarButton>
                <ToolbarButton
                  onClick={openWhitelistModal}
                  disabled={whitelisting || isRunning}
                  running={whitelisting}
                  title="把勾选的漏洞加入项目白名单，该项目后续扫描不再上报它们"
                >
                  {whitelisting
                    ? "加白中…"
                    : selectedFindingIds.size > 0
                      ? `加入白名单（已选 ${selectedFindingIds.size}）`
                      : "加入白名单"}
                </ToolbarButton>
                <ToolbarButton
                  onClick={() => setProjectWhitelistOpen(true)}
                  disabled={isRunning}
                  running={false}
                  title="查看 / 移除本项目的白名单条目"
                >
                  项目白名单
                </ToolbarButton>
              </>
            )}
            {canStartSast ? (
              <ToolbarButton onClick={startScan} disabled={starting || isRunning} running={starting} className="!bg-accent !text-white">
                {starting
                  ? "启动中…"
                  : hasSastRun
                    ? "重新跑 SAST"
                    : "开始 SAST 扫描"}
              </ToolbarButton>
            ) : canPause ? (
              <ToolbarButton onClick={pauseScan} disabled={isPausing} running={isPausing} danger>
                {isPausing ? "暂停中…" : "暂停扫描"}
              </ToolbarButton>
            ) : null}
            <ToolbarButton onClick={runRerun} disabled={rerunning || isRunning} running={rerunning}>
              {rerunning ? "重置中…" : "清空并重置"}
            </ToolbarButton>
            <ToolbarButton
              onClick={() => setExploitabilityModeOpen(true)}
              disabled={analyzing || sastDeepAuditing || isRunning}
              running={analyzing || sastDeepAuditing || showDeepAudit}
            >
              {analyzing || sastDeepAuditing || showDeepAudit
                ? "研判中…"
                : selectedFindingIds.size > 0
                  ? `漏洞研判（已选 ${selectedFindingIds.size}）`
                  : "漏洞研判"}
            </ToolbarButton>
            <ToolbarButton
              onClick={() => scan.scan_kind === "retest" ? void runLlmAudit() : setSkillDialogOpen(true)}
              disabled={isRunning}
              running={false}
              title={
                scan.scan_kind === "retest"
                  ? "复测任务只会核实上次 LLM 发现是否已修复，不会重新发现新漏洞"
                  : "选择 Skill 和执行风格开展深度审计"
              }
            >
              {scan.scan_kind === "retest" ? "核实上次 LLM 漏洞" : "深度审计"}
            </ToolbarButton>
            <ToolbarButton
              onClick={projectLinkActive ? copyProjectLink : createProjectLink}
              disabled={projectLinkBusy || isRunning}
              running={projectLinkBusy}
            >
              {projectLinkBusy
                ? "处理中…"
                : projectLinkActive
                  ? "复制项目确认链接"
                  : "生成项目确认链接"}
            </ToolbarButton>
            {projectLinkActive && (
              <ToolbarButton onClick={revokeProjectLink} disabled={projectLinkBusy} danger>
                撤销链接
              </ToolbarButton>
            )}
            {canUnarchive ? (
              <ToolbarButton onClick={handleUnarchive} disabled={archiving} running={archiving}>
                {archiving ? "处理中…" : "取消归档"}
              </ToolbarButton>
            ) : canArchive ? (
              <ToolbarButton onClick={handleArchive} disabled={archiving || isRunning} running={archiving}>
                {archiving ? "归档中…" : "归档项目"}
              </ToolbarButton>
            ) : null}
            <ToolbarButton danger onClick={handleDelete} className="inline-flex items-center">
              <Trash2 className="w-3.5 h-3.5" />
            </ToolbarButton>
          </div>

          {projectLinkNotice && (
            <div className="audit-panel p-3 text-sm text-cyan-200/90">{projectLinkNotice}</div>
          )}

          {projectLinkActive && projectLinkUrl && (
            <div className="card p-4 border border-cyan-500/20 bg-cyan-500/5 space-y-2">
              <p className="text-sm font-medium text-slate-200">项目确认链接（发给业务负责人）</p>
              <p className="text-xs text-slate-400">
                负责人可查看全部漏洞并提交存在/误报/已修复确认，无需登录。
                {projectLinkExpires && (
                  <> 有效期至 {new Date(projectLinkExpires).toLocaleString()}。</>
                )}
              </p>
              <p className="text-xs font-mono text-slate-300 break-all select-all">{projectLinkUrl}</p>
            </div>
          )}

          {fpNotice && (
            <div className="audit-panel p-3 text-sm text-cyan-200/90">{fpNotice}</div>
          )}

          {whitelistNotice && (
            <div className="audit-panel p-3 text-sm text-cyan-200/90">{whitelistNotice}</div>
          )}

          <SkillAuditHistory scanId={scanId} running={scan.status === "llm_auditing"} />
          {llmAuditNotice && (
            <div
              className={`audit-panel p-3 text-sm ${
                llmAuditNotice.includes("失败") || llmAuditNotice.toLowerCase().includes("error")
                  ? "text-red-300"
                  : "text-cyan-200/90"
              }`}
            >
              {llmAuditNotice}
            </div>
          )}

          {llmAuditSummary.settings && (
            <div className="audit-panel p-4">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                  <p className="text-sm font-medium text-slate-100">本次 LLM 审计策略</p>
                  <p className="text-xs text-slate-400 mt-1">
                    {String(llmAuditSummary.settings.payload.profile || "balanced")} ·
                    强证据 {llmAuditSummary.settings.payload.stronger_evidence ? "开启" : "关闭"} ·
                    广假设 {llmAuditSummary.settings.payload.broader_hypotheses ? "开启" : "关闭"}
                  </p>
                  {Array.isArray(llmAuditSummary.settings.payload.focus_labels) &&
                    (llmAuditSummary.settings.payload.focus_labels as unknown[]).length > 0 && (
                      <p className="text-xs text-cyan-400/80 mt-1">
                        关注重点：{(llmAuditSummary.settings.payload.focus_labels as string[]).join("、")}
                      </p>
                    )}
                  {!Array.isArray(llmAuditSummary.settings.payload.focus_labels) &&
                    Array.isArray(llmAuditSummary.settings.payload.focus_areas) &&
                    (llmAuditSummary.settings.payload.focus_areas as unknown[]).length > 0 && (
                      <p className="text-xs text-cyan-400/80 mt-1">
                        关注重点：{(llmAuditSummary.settings.payload.focus_areas as string[]).join("、")}
                      </p>
                    )}
                </div>
                {Boolean(llmAuditSummary.finish?.payload?.detail) && (
                  <p className="text-xs text-slate-400 max-w-[520px] leading-relaxed">
                    结束原因：{String(llmAuditSummary.finish?.payload?.detail ?? "")}
                  </p>
                )}
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-3 text-xs">
                <div className="rounded-lg border border-surface-border/70 bg-black/20 px-3 py-2">
                  <p className="text-slate-500">轮次上限</p>
                  <p className="text-slate-200 font-mono">
                    {String((llmAuditSummary.settings.payload.config as Record<string, unknown>)?.max_iterations ?? "-")}
                  </p>
                </div>
                <div className="rounded-lg border border-surface-border/70 bg-black/20 px-3 py-2">
                  <p className="text-slate-500">业务域上限</p>
                  <p className="text-slate-200 font-mono">
                    {String((llmAuditSummary.settings.payload.config as Record<string, unknown>)?.max_domains ?? "-")}
                  </p>
                </div>
                <div className="rounded-lg border border-surface-border/70 bg-black/20 px-3 py-2">
                  <p className="text-slate-500">Controller 上限</p>
                  <p className="text-slate-200 font-mono">
                    {String((llmAuditSummary.settings.payload.config as Record<string, unknown>)?.max_controllers ?? "-")}
                  </p>
                </div>
                <div className="rounded-lg border border-surface-border/70 bg-black/20 px-3 py-2">
                  <p className="text-slate-500">关联文件上限</p>
                  <p className="text-slate-200 font-mono">
                    {String((llmAuditSummary.settings.payload.config as Record<string, unknown>)?.max_related_files ?? "-")}
                  </p>
                </div>
              </div>
              {llmAuditSummary.domains && (
                <p className="text-xs text-slate-400 mt-3 leading-relaxed">
                  域选择：{((llmAuditSummary.domains.payload.selected_domains as string[]) || []).join(" / ") || "无"}
                </p>
              )}
              {llmAuditSummary.coverage && (
                <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                  覆盖摘要：累计 {String(llmAuditSummary.coverage.payload.tool_rounds || 0)} 次工具调查，
                  findings 去重前 {String(llmAuditSummary.coverage.payload.findings_before_dedupe || 0)} 条，
                  去重后 {String(llmAuditSummary.coverage.payload.findings_after_dedupe || 0)} 条，
                  候选 {String(llmAuditSummary.coverage.payload.candidate_count || 0)} 条。
                </p>
              )}
            </div>
          )}

          {startNotice && (
            <div
              className={`audit-panel p-3 text-sm ${
                startNotice.includes("失败") || startNotice.toLowerCase().includes("error")
                  ? "text-red-300"
                  : "text-cyan-200/90"
              }`}
            >
              {startNotice}
            </div>
          )}

          {(scan.status === "llm_auditing" || llmJournal.length > 0) && (
            <LlmAuditJournalPanel
              scan={scan}
              entries={llmJournal}
              onPause={scan.status === "llm_auditing" ? pauseScan : undefined}
              pausing={llmPausing}
            />
          )}

      {deleteError && (
        <div className="card p-3 text-sm text-red-300 border border-danger/40 bg-danger/10">
          删除失败: {deleteError}
        </div>
      )}

      {reviewError && (
        <div className="card p-3 text-sm text-red-300 border border-danger/40 bg-danger/10">
          标记失败: {reviewError}
        </div>
      )}

      {(isPending || (canStartSast && !hasSastRun && !isRunning)) && (
        <div className="card p-5 border border-accent/30 bg-accent/5">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-white">
                {isPending ? "代码已就绪" : "尚未运行 SAST"}
              </p>
              <p className="text-sm text-slate-400 mt-1">
                {isPending
                  ? scan.progress_message ||
                    "请点击「开始 SAST 扫描」运行 Semgrep/CodeQL 等静态分析；LLM 端点审计需单独点击工具栏按钮。"
                  : "已完成 LLM 端点审计或其他步骤，但还没跑过 Semgrep/CodeQL。可直接点「开始 SAST 扫描」，不会清空已有 LLM 发现；「清空并重置」才会整单清空。"}
              </p>
            </div>
          </div>
        </div>
      )}

      {isRunning && !showDeepAudit && (
        <div className="card p-4">
          <div className="flex justify-between items-center gap-3 text-sm mb-2 flex-wrap">
            <span>{scan.progress_message || (scan.status === "analyzing" ? "正在进行 AI 误报审计…" : "处理中...")}</span>
            <div className="flex items-center gap-3">
              <span>{scan.progress}%</span>
              {canPause && (
                <button
                  className="text-xs px-2.5 py-1 rounded border border-danger/40 text-red-300 hover:bg-danger/10 disabled:opacity-50"
                  onClick={pauseScan}
                  disabled={isPausing}
                >
                  {isPausing ? "暂停中…" : "暂停扫描"}
                </button>
              )}
            </div>
          </div>
          <div className="h-2 bg-surface rounded-full overflow-hidden">
            <div
              className="h-full bg-accent transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {showDeepAudit && (
        <SastDeepProgressPanel
          job={
            isActiveSastDeepJob(sastDeepJob)
              ? sastDeepJob
              : {
                  status: "running",
                  message: scan?.progress_message || "深度研判进行中…",
                  percent: scan?.progress ?? 1,
                  tasks: [],
                }
          }
          scanProgress={scan?.progress}
          scanMessage={scan?.progress_message}
          onPause={pauseScan}
          pausing={isPausing}
        />
      )}

      {scan.status === "failed" && scan.error_message && (
        <div className="card p-4 border-danger/50 bg-danger/10 flex gap-3">
          <AlertTriangle className="w-5 h-5 text-danger shrink-0" />
          <p className="text-sm text-red-300">{scan.error_message}</p>
        </div>
      )}

      {scan.status === "llm_auditing" && llmFindingCount(stats?.by_category) === 0 && (
        <div className="card p-3 text-xs text-cyan-200/90 border border-cyan-500/25 bg-cyan-500/5">
          LLM 端点审计进行中，发现会在审计完成后写入「LLM发现漏洞」标签页；下方日志可查看实时进度。
        </div>
      )}

      {stats && stats.total > 0 && <StatsCharts stats={stats} />}

      {codeqlGraph && codeqlGraph.codeql_path_total > 0 && (
        <details className="audit-panel p-4">
          <summary className="text-sm font-medium text-slate-300 cursor-pointer">
            CodeQL 项目级数据流图谱（供 LLM 深度审计）
          </summary>
          <div className="mt-3 space-y-3 text-xs">
            <div className="flex gap-3 flex-wrap text-slate-400">
              <span>paths: {codeqlGraph.codeql_path_total}</span>
              <span>nodes: {codeqlGraph.node_count}</span>
              <span>edges: {codeqlGraph.edge_count}</span>
            </div>
            {codeqlGraph.hub_nodes.length > 0 && (
              <div>
                <p className="text-slate-500 mb-1">Top hubs</p>
                <ul className="space-y-1 text-slate-300">
                  {codeqlGraph.hub_nodes.slice(0, 8).map((line, idx) => (
                    <li key={`hub-${idx}`} className="font-mono break-all">
                      {line}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {codeqlGraph.path_summaries.length > 0 && (
              <div>
                <p className="text-slate-500 mb-1">Top source → sink paths</p>
                <ul className="space-y-1 text-slate-300">
                  {codeqlGraph.path_summaries.slice(0, 8).map((line, idx) => (
                    <li key={`path-${idx}`} className="font-mono break-all">
                      {line}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </details>
      )}

      <div className="flex gap-2 flex-wrap">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className={activeTab === tab.key ? "tab-chip tab-chip-active" : "tab-chip"}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
            {tab.key !== "all" && (
              <span className="ml-2 opacity-70">({tabFindingCount(tab.key, stats?.by_category)})</span>
            )}
          </button>
        ))}
      </div>

      <div className="card overflow-hidden">
        {highlightedCount > 0 && (
          <div className="px-4 py-2 border-b border-cyan-500/20 bg-cyan-500/5 flex items-center justify-between gap-2 flex-wrap">
            <p className="text-xs text-cyan-200/90">
              Agent 已在列表中高亮 {highlightedCount} 条相关漏洞（青色左边框）
            </p>
            <button type="button" className="btn-ghost text-xs" onClick={clearTaskResults}>
              清除高亮
            </button>
          </div>
        )}
        <div className="px-4 py-2.5 border-b border-surface-border bg-black/20 flex items-center justify-between gap-3 flex-wrap">
          <p className="text-xs text-slate-400">
            {selectedFindingIds.size > 0 ? (
              <>
                已选 <span className="text-cyan-300 font-medium">{selectedFindingIds.size}</span> 条，可用于
                「漏洞研判」或「定向复测」
                <span className="text-slate-600 ml-2">（可跨页勾选）</span>
              </>
            ) : (
              <>未勾选时复测全部非误报漏洞；勾选后严格按所选条目复测（含误报）</>
            )}
          </p>
          <div className="flex items-center gap-2 flex-wrap">
            <button type="button" className="btn-ghost text-xs" onClick={selectHighOnPage} disabled={findings.length === 0}>
              勾选本页高危
            </button>
            <button
              type="button"
              className="btn-ghost text-xs"
              onClick={() => toggleSelectPage(findings.map((f) => f.id), true)}
              disabled={findings.length === 0}
            >
              全选本页
            </button>
            <button
              type="button"
              className="btn-ghost text-xs"
              onClick={clearSelection}
              disabled={selectedFindingIds.size === 0}
            >
              清空选择
            </button>
          </div>
        </div>
        <div className="px-4 border-b border-surface-border">
          {stats && stats.total > 0 && (
            <FindingClassificationFilter
              stats={stats}
              filterOwasp={filterOwasp}
              filterSubtype={filterSubtype}
              onOwaspChange={handleOwaspChange}
              onSubtypeChange={handleSubtypeChange}
            />
          )}
        </div>
        <div className="p-4 border-b border-surface-border space-y-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="min-w-0">
              <span className="font-medium">漏洞列表</span>
              <span className="text-xs text-slate-500 ml-2">
                {from}–{to} / {effectiveTotal}
              </span>
              {filterDiff && (
                <span className="text-[11px] text-slate-600 ml-2">
                  （对比筛选为去重唯一漏洞口径）
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <select
                className="input w-auto text-sm py-1"
                value={pageSize}
                onChange={(e) => setPageSize(parseInt(e.target.value, 10))}
                title="每页条数"
              >
                {[20, 50, 100].map((n) => (
                  <option key={n} value={n}>{n}/页</option>
                ))}
              </select>
              <button
                className="btn-ghost text-sm"
                onClick={clearFilters}
                disabled={!hasActiveFilters}
              >
                清空筛选
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6 gap-2 items-end">
            <label className="text-xs text-slate-500">
              关键词
              <input
                className="input mt-1"
                value={filterQ}
                onChange={(e) => setFilterQ(e.target.value)}
                placeholder="规则/描述/文件…"
              />
            </label>
            <label className="text-xs text-slate-500">
              工具
              <select className="input mt-1" value={filterTool} onChange={(e) => setFilterTool(e.target.value)}>
                <option value="">全部</option>
                {toolOptions.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </label>
            <label className="text-xs text-slate-500">
              安全标记
              <select className="input mt-1" value={filterReview} onChange={(e) => setFilterReview(e.target.value)}>
                <option value="">全部</option>
                <option value="unreviewed">未标记</option>
                <option value="confirmed">确认</option>
                <option value="false_positive">误报</option>
                <option value="fixed">已修复</option>
              </select>
            </label>
            <label className="text-xs text-slate-500">
              外部确认
              <select className="input mt-1" value={filterExternal} onChange={(e) => setFilterExternal(e.target.value)}>
                <option value="">全部</option>
                <option value="unreviewed">外部未确认</option>
                <option value="vuln_exists">漏洞存在</option>
                <option value="false_positive">漏洞误报</option>
                <option value="fixed_claimed">漏洞修复完成</option>
              </select>
            </label>
            <label className="text-xs text-slate-500">
              可利用性
              <select className="input mt-1" value={filterVerdict} onChange={(e) => setFilterVerdict(e.target.value)}>
                <option value="">全部</option>
                <option value="real_vuln">AI: 真实漏洞</option>
                <option value="false_positive">AI: 误报</option>
                <option value="uncertain">AI: 待确认</option>
                <option value="pending">未研判</option>
              </select>
            </label>
            <label className="text-xs text-slate-500">
              严重度
              <select className="input mt-1" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
                <option value="">全部</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </label>
            {scanDiff && (
              <label className="text-xs text-slate-500">
                对比状态
                <select
                  className="input mt-1"
                  value={filterDiff}
                  onChange={(e) => setFilterDiff((e.target.value || "") as DiffStatus | "")}
                >
                  <option value="">全部</option>
                  <option value="new">{DIFF_STATUS_LABELS.new}</option>
                  <option value="regressed">{DIFF_STATUS_LABELS.regressed}</option>
                  <option value="fixed">{DIFF_STATUS_LABELS.fixed}</option>
                </select>
              </label>
            )}
          </div>
          <div className="flex items-center justify-end gap-2 pt-1">
            <button className="btn-ghost text-sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
              上一页
            </button>
            <span className="text-xs text-slate-500">
              {page} / {totalPages}
            </span>
            <button className="btn-ghost text-sm" disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
              下一页
            </button>
          </div>
        </div>
        <VulnerabilityAuditTable
          findings={displayedFindings}
          onOpen={(f) => {
            if (filterDiff === "fixed" && scanDiff) {
              onOpenScanFinding?.(scanDiff.baseline_scan_id, f.id, scan?.project_id);
              return;
            }
            openFindingKeepingScroll(f.id);
          }}
          onReview={handleReview}
          reviewingId={reviewingId}
          highlightedIds={highlightedFindingIds}
          selectedIds={selectedFindingIds}
          onToggleSelect={toggleSelectFinding}
          onToggleSelectPage={toggleSelectPage}
        />
        {totalPages > 1 && (
          <div className="p-4 border-t border-surface-border flex items-center justify-between gap-2 flex-wrap text-sm">
            <span className="text-xs text-slate-500">显示 {from}–{to} / {effectiveTotal}</span>
            <div className="flex items-center gap-2">
              <button className="btn-ghost text-sm" disabled={page <= 1} onClick={() => setPage(1)}>
                首页
              </button>
              <button className="btn-ghost text-sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                上一页
              </button>
              <button className="btn-ghost text-sm" disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
                下一页
              </button>
              <button className="btn-ghost text-sm" disabled={page >= totalPages} onClick={() => setPage(totalPages)}>
                末页
              </button>
            </div>
          </div>
        )}
      </div>

      <details className="audit-panel p-4">
        <summary className="text-sm font-medium text-slate-400 cursor-pointer">运行日志</summary>
        <div className="mt-3 max-h-48 overflow-y-auto rounded-lg border border-cyan-500/10 bg-black/30 p-2 text-xs font-mono space-y-1">
          {events.length === 0 ? (
            <p className="text-slate-500">暂无日志</p>
          ) : (
            events.map((e) => (
              <div
                key={e.id}
                className={`rounded border px-2 py-1 ${
                  e.level === "error" ? "border-danger/40 bg-danger/10" : "border-surface-border"
                }`}
              >
                <span className="text-slate-500">
                  {new Date(e.created_at).toLocaleTimeString("zh-CN", { hour12: false })}
                </span>
                <span className="text-slate-400 ml-2">[{PHASE_LABELS[e.phase || ""] || e.phase}]</span>
                <span className="ml-2 text-slate-200">{e.message}</span>
              </div>
            ))
          )}
        </div>
      </details>

      {shouldShowCoveragePanel(scanCoverage) && (
        <div className="audit-panel p-4 space-y-3">
          <div>
            <h3 className="text-sm font-medium text-slate-400 mb-1">漏洞扫描清单</h3>
            <p className="text-xs text-cyan-200/80 font-mono mb-1">{coverageSummaryLine(scanCoverage)}</p>
            <p className="text-[10px] text-slate-600">
              「已检测」= Semgrep 规则清单中存在对应 CWE/子类型规则（实锤）；0 条发现不代表未扫描。
              CodeQL / 依赖扫描仍为工具级。「部分」表示规则包不完整或仅工具级覆盖。
            </p>
          </div>

          <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2" open={Boolean(scanCoverage.semgrep_rule_evidence?.inventory_error)}>
            <summary className="text-[10px] text-slate-400 cursor-pointer select-none">
              Semgrep 规则包与规则清单实锤
            </summary>
            <div className="mt-2 space-y-3">
              {scanCoverage.semgrep_configs.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {scanCoverage.semgrep_configs.map((cfg) => (
                    <span
                      key={cfg}
                      className="text-[10px] px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/5 text-cyan-200/90 font-mono"
                    >
                      {cfg}
                    </span>
                  ))}
                </div>
              )}

              {scanCoverage.semgrep_rule_evidence ? (
                <div>
                  <p className="text-xs text-slate-300 mb-2">
                    共{" "}
                    <span className="text-cyan-300 font-mono">
                      {scanCoverage.semgrep_rule_evidence.total_rules}
                    </span>{" "}
                    条规则
                    {scanCoverage.semgrep_rule_evidence.source
                      ? ` · 来源 ${scanCoverage.semgrep_rule_evidence.source}`
                      : ""}
                    {scanCoverage.semgrep_rule_evidence.resolved_at
                      ? ` · ${new Date(scanCoverage.semgrep_rule_evidence.resolved_at).toLocaleString("zh-CN")}`
                      : ""}
                  </p>
                  {scanCoverage.semgrep_rule_evidence.filtered ? (
                    <p className="text-[10px] text-cyan-400/90 mb-2">
                      已按项目语言过滤：
                      {(scanCoverage.semgrep_rule_evidence.project_languages || []).join(", ") || "—"}
                      {typeof scanCoverage.semgrep_rule_evidence.unfiltered_total_rules === "number"
                        ? ` · 过滤前 ${scanCoverage.semgrep_rule_evidence.unfiltered_total_rules} / 过滤后 ${scanCoverage.semgrep_rule_evidence.total_rules}`
                        : ""}
                      。样例仅展示与本仓语言相关的规则（通用规则保留）。
                    </p>
                  ) : null}
                  {scanCoverage.semgrep_rule_evidence.inventory_error ? (
                    <p className="text-[10px] text-amber-400 mb-2">
                      部分规则包未解析：{scanCoverage.semgrep_rule_evidence.inventory_error}
                    </p>
                  ) : null}
                  <details className="rounded border border-surface-border/40 px-2 py-1.5">
                    <summary className="text-[10px] text-slate-500 cursor-pointer">按子类型样例</summary>
                    <div className="mt-2 space-y-2 max-h-40 overflow-y-auto">
                      {Object.entries(scanCoverage.semgrep_rule_evidence.by_subtype || {})
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 24)
                        .map(([subtype, count]) => {
                          const samples =
                            scanCoverage.semgrep_rule_evidence?.sample_rules_by_subtype?.[subtype] || [];
                          return (
                            <div key={subtype} className="text-[10px]">
                              <span className="text-slate-300">
                                {subtype} · {count}
                              </span>
                              {samples.length > 0 && (
                                <p className="font-mono text-slate-500 mt-0.5 break-all">
                                  {samples.slice(0, 5).join(" · ")}
                                  {samples.length > 5 ? " …" : ""}
                                </p>
                              )}
                            </div>
                          );
                        })}
                    </div>
                  </details>
                  {(Object.keys(scanCoverage.semgrep_rule_evidence.by_owasp || {}).length > 0) && (
                    <details className="rounded border border-surface-border/40 px-2 py-1.5 mt-2">
                      <summary className="text-[10px] text-slate-500 cursor-pointer">按 OWASP 样例</summary>
                      <div className="mt-2 space-y-2 max-h-40 overflow-y-auto">
                        {Object.entries(scanCoverage.semgrep_rule_evidence.by_owasp || {})
                          .sort((a, b) => b[1] - a[1])
                          .map(([oid, count]) => {
                            const samples =
                              scanCoverage.semgrep_rule_evidence?.sample_rules_by_owasp?.[oid] || [];
                            return (
                              <div key={oid} className="text-[10px]">
                                <span className="text-slate-300">
                                  {oid} · {count}
                                </span>
                                {samples.length > 0 && (
                                  <p className="font-mono text-slate-500 mt-0.5 break-all">
                                    {samples.slice(0, 5).join(" · ")}
                                    {samples.length > 5 ? " …" : ""}
                                  </p>
                                )}
                              </div>
                            );
                          })}
                      </div>
                    </details>
                  )}
                </div>
              ) : (
                <p className="text-[10px] text-amber-400/90">
                  {scanCoverage.sast_checked
                    ? "该扫描早于规则清单能力，或规则清单未生成；OWASP/注入类无法实锤，仅可参考工具是否执行。"
                    : "尚未生成 Semgrep 规则清单。完成 SAST 后将在此展示实锤规则数。"}
                </p>
              )}
            </div>
          </details>

          {(scanCoverage.owasp_categories?.length ?? 0) > 0 && (
            <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2">
              <summary className="text-[10px] text-slate-400 cursor-pointer select-none">
                OWASP Top 10（Semgrep 规则实锤 / 其它工具级）
              </summary>
              <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {scanCoverage.owasp_categories!.map((cat) => (
                  <div
                    key={cat.id}
                    className={`text-xs px-3 py-2 rounded-lg border ${
                      cat.status === "checked"
                        ? "border-success/30 text-success bg-success/5"
                        : cat.status === "partial"
                          ? "border-amber-500/30 text-amber-300 bg-amber-500/5"
                          : "border-surface-border text-slate-500 bg-black/20"
                    }`}
                    title={cat.note || undefined}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span>
                        <span className="font-mono text-[10px] text-slate-500">{cat.id}</span>
                        <span className="ml-1.5">{cat.label}</span>
                      </span>
                      <span className="text-[10px] shrink-0">{owaspStatusLabel(cat.status)}</span>
                    </div>
                    {typeof cat.rule_count === "number" && cat.rule_count > 0 && (
                      <p className="text-[10px] text-cyan-400/80 mt-1">规则数：{cat.rule_count}</p>
                    )}
                    {cat.sources.length > 0 && (
                      <p className="text-[10px] text-slate-500 mt-1">来源：{cat.sources.join(", ")}</p>
                    )}
                    {cat.note && (
                      <p className="text-[10px] text-slate-600 mt-1">{cat.note}</p>
                    )}
                  </div>
                ))}
              </div>
            </details>
          )}

          <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2">
            <summary className="text-[10px] text-slate-400 cursor-pointer select-none">扫描工具</summary>
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="text-slate-500 border-b border-surface-border/60">
                    <th className="py-1.5 pr-3 font-medium">工具</th>
                    <th className="py-1.5 pr-3 font-medium">状态</th>
                    <th className="py-1.5 pr-3 font-medium">发现</th>
                    <th className="py-1.5 font-medium">说明</th>
                  </tr>
                </thead>
                <tbody>
                  {scanCoverage.scanners.map((s) => {
                    const detail = s.detail as {
                      query_suite?: string;
                      build_mode?: string;
                      configs?: string[];
                    } | null | undefined;
                    const extra = [
                      detail?.query_suite ? `suite=${detail.query_suite}` : "",
                      detail?.build_mode ? `mode=${detail.build_mode}` : "",
                      detail?.configs?.length ? detail.configs.join(", ") : "",
                    ].filter(Boolean).join(" · ");
                    const note = s.reason || extra || "—";
                    return (
                      <tr key={s.id} className="border-b border-surface-border/30 text-slate-300">
                        <td className="py-1.5 pr-3 font-mono">{s.name}</td>
                        <td className="py-1.5 pr-3">{scannerStatusLabel(s.status)}</td>
                        <td className="py-1.5 pr-3">{s.findings}</td>
                        <td className="py-1.5 text-slate-500 max-w-md truncate" title={note}>
                          {note}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </details>

          <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2">
            <summary className="text-[10px] text-slate-400 cursor-pointer select-none">
              注入与路径类能力（规则实锤）
            </summary>
            <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {scanCoverage.capabilities
                .filter((c) => injectionCapIds.has(c.id))
                .map((cap) => (
                  <div
                    key={cap.id}
                    className={`text-xs px-3 py-2 rounded-lg border ${
                      cap.status === "checked"
                        ? "border-success/30 text-success bg-success/5"
                        : cap.status === "partial"
                          ? "border-amber-500/30 text-amber-300 bg-amber-500/5"
                          : "border-surface-border text-slate-500 bg-black/20"
                    }`}
                    title={cap.note || undefined}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span>{cap.label}</span>
                      <span className="text-[10px] shrink-0">{capabilityStatusLabel(cap.status)}</span>
                    </div>
                    {typeof cap.rule_count === "number" && cap.rule_count > 0 && (
                      <p className="text-[10px] text-cyan-400/80 mt-1">规则数：{cap.rule_count}</p>
                    )}
                    {cap.sources.length > 0 && (
                      <p className="text-[10px] text-slate-500 mt-1">来源：{cap.sources.join(", ")}</p>
                    )}
                    {cap.note && (
                      <p className="text-[10px] text-slate-600 mt-1">{cap.note}</p>
                    )}
                  </div>
                ))}
            </div>
          </details>

          <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2">
            <summary className="text-[10px] text-slate-400 cursor-pointer select-none">
              其它能力（密钥 / 依赖 / 反序列化等）
            </summary>
            <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {scanCoverage.capabilities
                .filter((c) => otherCapIds.has(c.id))
                .map((cap) => (
                  <div
                    key={cap.id}
                    className={`text-xs px-3 py-2 rounded-lg border ${
                      cap.status === "checked"
                        ? "border-success/30 text-success bg-success/5"
                        : cap.status === "partial"
                          ? "border-amber-500/30 text-amber-300 bg-amber-500/5"
                          : "border-surface-border text-slate-500 bg-black/20"
                    }`}
                    title={cap.note || undefined}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span>{cap.label}</span>
                      <span className="text-[10px] shrink-0">{capabilityStatusLabel(cap.status)}</span>
                    </div>
                    {typeof cap.rule_count === "number" && cap.rule_count > 0 && (
                      <p className="text-[10px] text-cyan-400/80 mt-1">规则数：{cap.rule_count}</p>
                    )}
                    {cap.sources.length > 0 && (
                      <p className="text-[10px] text-slate-500 mt-1">来源：{cap.sources.join(", ")}</p>
                    )}
                    {cap.note && (
                      <p className="text-[10px] text-slate-600 mt-1">{cap.note}</p>
                    )}
                  </div>
                ))}
            </div>
          </details>

          {scanCoverage.llm_audit && (
            <details className="rounded-lg border border-surface-border/60 bg-black/20 px-3 py-2">
              <summary className="text-[10px] text-slate-400 cursor-pointer select-none">
                LLM 深度审计（关注重点）
              </summary>
              <div className="mt-2">
                <p className="text-[10px] text-slate-600 mb-2">
                  与「设置 → LLM 深度审计 → 审计风格与关注重点」一致。「已审计」表示端点驱动审计已覆盖该类型，不等于发现漏洞。
                </p>
                <div className="flex items-center gap-2 mb-2 text-[10px] text-slate-500">
                  <span>
                    状态：
                    {scanCoverage.llm_audit.status === "running"
                      ? "审计中"
                      : scanCoverage.llm_audit.status === "completed"
                        ? "已完成"
                        : scanCoverage.llm_audit.status === "cancelled"
                          ? "已暂停"
                          : "未运行"}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {(scanCoverage.llm_audit.focus_areas || []).map((focus) => (
                    <div
                      key={focus.id}
                      className={`text-xs px-3 py-2 rounded-lg border ${
                        focus.status === "audited"
                          ? "border-cyan-500/30 text-cyan-200 bg-cyan-500/5"
                          : focus.status === "configured"
                            ? "border-surface-border text-slate-400 bg-black/20"
                            : "border-surface-border text-slate-600 bg-black/10"
                      }`}
                      title={focus.note || undefined}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span>{focus.label}</span>
                        <span className="text-[10px] shrink-0">{llmFocusStatusLabel(focus.status)}</span>
                      </div>
                      {focus.note && (
                        <p className="text-[10px] text-slate-600 mt-1">{focus.note}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </details>
          )}
        </div>
      )}
        </div>

        <AuditChatBar
          disabled={isRunning || chatting}
          onCommand={handleChat}
          onRunTask={handleRunTask}
          messages={agentMessages}
          lastAction={lastAgentAction}
          lastActionResult={lastAgentActionResult}
          actions={agentActions}
          taskNotice={taskNotice}
          taskItems={taskItems}
          taskMode={taskMode}
          onOpenFinding={openFindingKeepingScroll}
          onReviewFinding={handleReview}
          reviewingId={reviewingId}
          onClearTaskResults={clearTaskResults}
        />
      </div>

      <AgentPanel scan={scan} stats={stats} events={events} highlightedCount={highlightedCount} />

      {exploitabilityModeOpen &&
        createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
            onClick={() => setExploitabilityModeOpen(false)}
          >
          <div className="card w-full max-w-md shadow-2xl overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between gap-3 px-5 pt-5 pb-4 border-b border-surface-border">
              <div>
                <h3 className="text-base font-semibold text-white">漏洞研判</h3>
                <p className="text-sm text-slate-500 mt-1">
                  {selectedFindingIds.size > 0
                    ? `可对已勾选的 ${selectedFindingIds.size} 条漏洞做快速/深度研判，也可直接做 LLM 发现复核`
                    : "可先勾选漏洞做定向研判，或直接运行 LLM 发现复核"}
                </p>
              </div>
              <button type="button" className="btn-ghost text-sm" onClick={() => setExploitabilityModeOpen(false)}>
                取消
              </button>
            </div>

            <div className="p-5 space-y-3">
              {selectedFindingIds.size === 0 ? (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 space-y-2">
                  <p className="text-sm text-amber-100">尚未勾选漏洞</p>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    在表格左侧勾选即可；也可用「勾选本页高危 / 全选本页」。快速/深度模式只处理已选中的漏洞。
                  </p>
                  <div className="flex gap-2 flex-wrap pt-1">
                    <button
                      type="button"
                      className="btn-ghost text-xs"
                      onClick={() => {
                        selectHighOnPage();
                      }}
                    >
                      勾选本页高危
                    </button>
                    <button
                      type="button"
                      className="btn-ghost text-xs"
                      onClick={() => toggleSelectPage(findings.map((f) => f.id), true)}
                    >
                      全选本页
                    </button>
                  </div>
                </div>
              ) : null}

              <button
                type="button"
                disabled={selectedFindingIds.size === 0}
                className="w-full text-left rounded-xl border border-surface-border bg-black/20 hover:bg-white/[0.04] px-4 py-3 transition-colors disabled:opacity-40 disabled:pointer-events-none"
                onClick={() => runExploitabilityAudit("fast")}
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-slate-100">快速模式</p>
                  <span className="badge bg-slate-500/15 text-slate-200 border border-slate-500/25 text-[10px]">
                    推荐先用
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                  对已选漏洞做快速真假筛选，适合先筛掉明显误报
                </p>
              </button>

              <button
                type="button"
                disabled={selectedFindingIds.size === 0}
                className="w-full text-left rounded-xl border border-surface-border bg-black/20 hover:bg-white/[0.04] px-4 py-3 transition-colors disabled:opacity-40 disabled:pointer-events-none"
                onClick={() => runExploitabilityAudit("deep")}
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-slate-100">深度模式</p>
                  <span className="badge bg-cyan-500/10 text-cyan-200 border border-cyan-500/25 text-[10px]">
                    含数据流追认
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                  对已选 SAST 与 LLM 发现做深入分析；无工具数据流时会反向追认，条数少更快
                </p>
              </button>

              <button
                type="button"
                disabled={llmReviewing}
                className="w-full text-left rounded-xl border border-surface-border bg-black/20 hover:bg-white/[0.04] px-4 py-3 transition-colors disabled:opacity-40 disabled:pointer-events-none"
                onClick={runLlmReview}
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-slate-100">
                    {llmReviewing ? "复核中…" : "LLM 发现复核"}
                  </p>
                  <span className="badge bg-purple-500/10 text-purple-200 border border-purple-500/25 text-[10px]">
                    整批
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                  不依赖勾选，统一复核当前扫描里的 LLM 发现，适合批量纠正已有判断
                </p>
              </button>
            </div>
          </div>
        </div>,
          document.body
        )}

      {scan && (
        <ProjectSettingsModal
          open={settingsOpen}
          scan={scan}
          project={project}
          onClose={() => setSettingsOpen(false)}
          onSaved={(updated, nextProject) => {
            setScan(updated);
            if (nextProject) setProject(nextProject);
            onScanUpdated?.();
          }}
        />
      )}

      <FalsePositiveNoteModal
        open={fpModalFindingId != null}
        onCancel={() => setFpModalFindingId(null)}
        onConfirm={confirmFalsePositive}
        submitting={reviewingId != null}
      />

      <WhitelistReasonModal
        open={whitelistModalOpen}
        count={selectedFindingIds.size}
        onCancel={() => setWhitelistModalOpen(false)}
        onConfirm={confirmWhitelist}
        submitting={whitelisting}
      />

      <ProjectWhitelistModal
        open={projectWhitelistOpen}
        projectId={scan?.project_id ?? null}
        projectName={project?.name ?? scan?.name ?? null}
        onClose={() => setProjectWhitelistOpen(false)}
        onChanged={() => {
          load().catch(() => {
            /* 列表刷新失败不阻塞白名单面板 */
          });
          onScanUpdated?.();
        }}
      />

      <RetestOptionsModal
        open={retestMode != null}
        mode={retestMode ?? "targeted"}
        baselineBranch={scan?.branch ?? project?.default_branch ?? null}
        branchEditable={scan?.source !== "upload"}
        scopeHint={retestScopeHint()}
        submitting={retesting || fullScanning}
        onCancel={() => setRetestMode(null)}
        onConfirm={submitRetest}
      />
    </div>
  );
}
