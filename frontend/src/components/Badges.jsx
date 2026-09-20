import React from "react";

const SEVERITY_STYLES = {
  critical: "bg-red-500/15 text-red-400 border border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  low: "bg-sky-500/15 text-sky-400 border border-sky-500/30",
  info: "bg-slate-500/15 text-slate-400 border border-slate-500/30",
};

export function SeverityBadge({ severity }) {
  const cls = SEVERITY_STYLES[severity] || SEVERITY_STYLES.info;
  return <span className={`badge ${cls}`}>{severity}</span>;
}

const EFFORT_STYLES = {
  low: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  high: "bg-red-500/15 text-red-400 border border-red-500/30",
};

export function EffortBadge({ effort }) {
  const cls = EFFORT_STYLES[effort] || EFFORT_STYLES.medium;
  return <span className={`badge ${cls}`}>{effort} effort</span>;
}

export function QuickWinBadge() {
  return (
    <span className="badge bg-cg-accent/15 text-cg-accent border border-cg-accent/30">
      quick win
    </span>
  );
}

export function RiskMeter({ score }) {
  const pct = Math.max(0, Math.min(100, score));
  let color = "bg-sky-400";
  if (pct >= 75) color = "bg-red-500";
  else if (pct >= 50) color = "bg-orange-500";
  else if (pct >= 25) color = "bg-yellow-500";

  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-1.5 rounded-full bg-cg-border overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-xs text-slate-400 w-9 text-right">{pct.toFixed(0)}</span>
    </div>
  );
}
