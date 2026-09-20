import React from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend,
} from "recharts";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#38bdf8",
};

function StatCard({ label, value, sublabel, accent }) {
  return (
    <div className="bg-cg-panel border border-cg-border rounded-lg p-5 flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-slate-500">{label}</span>
      <span className={`font-mono text-3xl font-semibold ${accent || "text-slate-100"}`}>
        {value}
      </span>
      {sublabel && <span className="text-xs text-slate-500">{sublabel}</span>}
    </div>
  );
}

export default function Dashboard({ summary, loading }) {
  if (loading || !summary) {
    return <div className="text-slate-500 text-sm p-6">Loading dashboard…</div>;
  }

  const severityData = [
    { name: "Critical", value: summary.critical_count, color: SEVERITY_COLORS.critical },
    { name: "High", value: summary.high_count, color: SEVERITY_COLORS.high },
    { name: "Medium", value: summary.medium_count, color: SEVERITY_COLORS.medium },
    { name: "Low", value: summary.low_count, color: SEVERITY_COLORS.low },
  ].filter((d) => d.value > 0);

  const categoryData = (summary.top_categories || []).map((c) => ({
    name: c.category, count: c.count,
  }));

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Cloud Resources" value={summary.total_resources} />
        <StatCard
          label="Overall Risk Score"
          value={summary.overall_risk_score}
          sublabel="out of 100"
          accent={summary.overall_risk_score >= 60 ? "text-red-400" : "text-cg-accent"}
        />
        <StatCard
          label="Critical Attack Paths"
          value={summary.critical_attack_paths}
          sublabel={`of ${summary.total_attack_paths} total paths`}
          accent="text-red-400"
        />
        <StatCard
          label="Quick-Win Fixes"
          value={summary.quick_wins}
          sublabel="low effort, high impact"
          accent="text-emerald-400"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        <div className="lg:col-span-2 bg-cg-panel border border-cg-border rounded-lg p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Findings by severity
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityData}
                dataKey="value"
                nameKey="name"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
              >
                {severityData.map((entry, idx) => (
                  <Cell key={idx} fill={entry.color} stroke="none" />
                ))}
              </Pie>
              <Legend
                verticalAlign="bottom"
                height={24}
                formatter={(value) => <span className="text-xs text-slate-400">{value}</span>}
              />
              <Tooltip
                contentStyle={{ background: "#161d2b", border: "1px solid #232c3d", borderRadius: 8 }}
                itemStyle={{ color: "#e2e8f0" }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="lg:col-span-3 bg-cg-panel border border-cg-border rounded-lg p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">
            Top vulnerability categories
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={categoryData} layout="vertical" margin={{ left: 12 }}>
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="name"
                width={170}
                tick={{ fill: "#94a3b8", fontSize: 12 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "rgba(255,255,255,0.03)" }}
                contentStyle={{ background: "#161d2b", border: "1px solid #232c3d", borderRadius: 8 }}
                itemStyle={{ color: "#e2e8f0" }}
              />
              <Bar dataKey="count" fill="#f0b429" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {summary.source === "mock" && (
        <div className="text-xs text-slate-500 border border-cg-border rounded-lg px-4 py-2 bg-cg-panel/60">
          Showing sample data. Connect live AWS credentials and trigger a scan to analyze your
          own account.
        </div>
      )}
    </div>
  );
}
