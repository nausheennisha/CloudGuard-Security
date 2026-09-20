import React, { useState } from "react";
import { SeverityBadge, EffortBadge, QuickWinBadge, RiskMeter } from "./Badges";

export default function RemediationPanel({ plan, loading }) {
  const [showQuickWinsOnly, setShowQuickWinsOnly] = useState(false);

  if (loading) {
    return <div className="text-slate-500 text-sm p-6">Building remediation plan…</div>;
  }

  const items = showQuickWinsOnly ? plan.filter((p) => p.quick_win) : plan;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-400">
          Ranked by risk reduction per unit of effort — fix from the top down.
        </p>
        <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showQuickWinsOnly}
            onChange={(e) => setShowQuickWinsOnly(e.target.checked)}
            className="accent-cg-accent"
          />
          Quick wins only
        </label>
      </div>

      <ol className="flex flex-col gap-3">
        {items.map((item) => (
          <li
            key={item.id}
            className="bg-cg-panel border border-cg-border rounded-lg p-4 flex items-start gap-4"
          >
            <div className="font-mono text-lg text-slate-600 w-8 text-right shrink-0">
              {item.priority_rank}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <SeverityBadge severity={item.severity} />
                <EffortBadge effort={item.effort} />
                {item.quick_win && <QuickWinBadge />}
              </div>
              <h4 className="text-sm font-medium text-slate-100">{item.title}</h4>
              <p className="text-xs text-slate-500 mt-0.5">
                Affects: {item.affected_resources.join(", ")}
              </p>
              <p className="text-sm text-slate-300 mt-2">{item.recommended_action}</p>
            </div>
            <div className="w-36 shrink-0 flex flex-col gap-1 items-end">
              <span className="text-[11px] text-slate-500">risk score</span>
              <RiskMeter score={item.risk_score} />
              <span className="text-[11px] text-emerald-400 mt-1">
                −{item.estimated_risk_reduction} if fixed
              </span>
            </div>
          </li>
        ))}
        {items.length === 0 && (
          <p className="text-sm text-slate-500 text-center py-8">
            No quick wins remaining — nice work.
          </p>
        )}
      </ol>
    </div>
  );
}
