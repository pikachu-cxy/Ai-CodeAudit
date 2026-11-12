import {
  Bar,
  BarChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ScanStats } from "../api";
import { OWASP_CHART_COLORS, OWASP_ORDER, OWASP_TOP10 } from "../lib/owaspUtils";

const SEVERITY_CHART_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFO: "#64748b",
  UNKNOWN: "#475569",
};

const VERDICT_CHART_COLORS: Record<string, string> = {
  real_vuln: "#ef4444",
  false_positive: "#22c55e",
  uncertain: "#eab308",
  pending: "#64748b",
  skipped: "#475569",
};

const VERDICT_NAMES: Record<string, string> = {
  real_vuln: "真实漏洞",
  false_positive: "误报",
  uncertain: "待确认",
  pending: "待分析",
  skipped: "已跳过",
};

const CATEGORY_CHART_COLORS: Record<string, string> = {
  sast: "#3b82f6",
  llm: "#a855f7",
};

interface Props {
  stats: ScanStats;
}

export function StatsCharts({ stats }: Props) {
  const severityData = Object.entries(stats.by_severity).map(([name, value]) => ({ name, value }));
  const verdictData = Object.entries(stats.by_verdict).map(([name, value]) => ({
    name: VERDICT_NAMES[name] || name,
    key: name,
    value,
  }));
  const byCategory = stats.by_category || {};
  const categoryData = [
    { name: "SAST", key: "sast", value: byCategory.sast || 0 },
    {
      name: "LLM发现漏洞",
      key: "llm",
      value: byCategory.llm ?? (byCategory.business_logic || 0) + (byCategory.authorization || 0),
    },
  ].filter((d) => d.value > 0);
  const toolData = Object.entries(stats.by_tool || {}).map(([name, count]) => ({ name, count }));
  const owaspData = OWASP_ORDER.map((id) => ({
    id,
    name: `${id} ${OWASP_TOP10[id]}`,
    shortName: id,
    value: stats.by_owasp?.[id] || 0,
  })).filter((d) => d.value > 0);

  return (
    <div className="space-y-4">
    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-4">
      <div className="card p-4">
        <h3 className="text-sm font-medium text-slate-400 mb-4">审计类型分布</h3>
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={categoryData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label>
              {categoryData.map((entry) => (
                <Cell key={entry.key} fill={CATEGORY_CHART_COLORS[entry.key] || "#64748b"} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="card p-4">
        <h3 className="text-sm font-medium text-slate-400 mb-4">严重程度分布</h3>
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label>
              {severityData.map((entry) => (
                <Cell key={entry.name} fill={SEVERITY_CHART_COLORS[entry.name] || "#64748b"} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="card p-4">
        <h3 className="text-sm font-medium text-slate-400 mb-4">SAST 误报审计</h3>
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={verdictData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label>
              {verdictData.map((entry) => (
                <Cell key={entry.key} fill={VERDICT_CHART_COLORS[entry.key] || "#64748b"} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="card p-4">
        <h3 className="text-sm font-medium text-slate-400 mb-4">扫描工具分布</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={toolData} layout="vertical" margin={{ left: 10, right: 10 }}>
            <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <YAxis type="category" dataKey="name" width={80} tick={{ fill: "#94a3b8", fontSize: 10 }} />
            <Tooltip />
            <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>

      {owaspData.length > 0 && (
        <div className="card p-4">
          <h3 className="text-sm font-medium text-slate-400 mb-4">OWASP Top 10 分类分布</h3>
          <ResponsiveContainer width="100%" height={Math.max(220, owaspData.length * 36)}>
            <BarChart data={owaspData} layout="vertical" margin={{ left: 8, right: 16 }}>
              <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="name"
                width={200}
                tick={{ fill: "#94a3b8", fontSize: 10 }}
              />
              <Tooltip
                formatter={(value: number) => [`${value} 条`, "数量"]}
                labelFormatter={(label) => label}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {owaspData.map((entry) => (
                  <Cell key={entry.id} fill={OWASP_CHART_COLORS[entry.id] || "#64748b"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
