"""
Risk scoring and remediation prioritization.

Risk score model (0-100):
    risk_score = (impact * 0.45 + exploitability * 0.35 + exposure * 0.20) * severity_weight * 10

Where impact/exploitability/exposure are each on a 0-10 scale supplied by the
scanner/mock data, and severity_weight nudges the score to keep severity
bands intuitively ordered (a "low" finding should never outrank a "high" one
purely on exposure).

Remediation priority additionally rewards "quick wins": low-effort fixes
that remove a disproportionate amount of risk are surfaced first, since
they give security teams the fastest measurable risk reduction.
"""
from __future__ import annotations

from typing import List, Dict, Any

SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.55,
    "low": 0.3,
    "info": 0.1,
}

EFFORT_WEIGHT = {  # lower effort = higher priority multiplier
    "low": 1.25,
    "medium": 1.0,
    "high": 0.75,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def compute_risk_score(vuln: Dict[str, Any]) -> float:
    impact = vuln.get("impact", 0)
    exploitability = vuln.get("exploitability", 0)
    exposure = vuln.get("exposure", 0)
    weight = SEVERITY_WEIGHT.get(vuln.get("severity", "low"), 0.3)
    raw = (impact * 0.45 + exploitability * 0.35 + exposure * 0.20) * weight * 10
    return round(min(raw, 100.0), 1)


def enrich_vulnerabilities(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach a computed risk_score to every finding, sorted highest-risk first."""
    enriched = []
    for v in vulns:
        v = dict(v)
        v["risk_score"] = compute_risk_score(v)
        enriched.append(v)
    enriched.sort(key=lambda v: v["risk_score"], reverse=True)
    return enriched


def build_remediation_plan(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Produces a prioritized remediation list. Priority combines raw risk with
    an effort multiplier so that a "low effort / high risk reduction" item
    can outrank a slightly higher-risk item that requires a large effort,
    surfacing genuine quick wins near the top.
    """
    enriched = enrich_vulnerabilities(vulns)

    scored = []
    for v in enriched:
        effort = v.get("remediation_effort", "medium")
        priority_score = v["risk_score"] * EFFORT_WEIGHT.get(effort, 1.0)
        quick_win = effort == "low" and v["risk_score"] >= 40
        scored.append((priority_score, quick_win, v))

    scored.sort(key=lambda t: t[0], reverse=True)

    plan = []
    for rank, (priority_score, quick_win, v) in enumerate(scored, start=1):
        plan.append({
            "id": f"remediation-{v['id']}",
            "vulnerability_id": v["id"],
            "title": v["title"],
            "priority_rank": rank,
            "risk_score": v["risk_score"],
            "severity": v["severity"],
            "effort": v.get("remediation_effort", "medium"),
            "quick_win": quick_win,
            "affected_resources": [v["resource_name"]],
            "recommended_action": v["remediation"],
            "estimated_risk_reduction": round(v["risk_score"] * 0.85, 1),
        })
    return plan


def compute_dashboard_summary(resources: List[Dict[str, Any]],
                               vulns: List[Dict[str, Any]],
                               attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
    enriched = enrich_vulnerabilities(vulns)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for v in enriched:
        counts[v.get("severity", "low")] = counts.get(v.get("severity", "low"), 0) + 1

    plan = build_remediation_plan(vulns)
    quick_wins = sum(1 for p in plan if p["quick_win"])

    categories: Dict[str, int] = {}
    for v in enriched:
        categories[v["category"]] = categories.get(v["category"], 0) + 1
    top_categories = sorted(
        ({"category": k, "count": v} for k, v in categories.items()),
        key=lambda x: x["count"], reverse=True,
    )[:5]

    overall_risk = round(sum(v["risk_score"] for v in enriched) / max(len(enriched), 1), 1)
    critical_paths = sum(1 for p in attack_paths if p.get("severity") == "critical")

    return {
        "total_resources": len(resources),
        "total_vulnerabilities": len(enriched),
        "critical_count": counts.get("critical", 0),
        "high_count": counts.get("high", 0),
        "medium_count": counts.get("medium", 0),
        "low_count": counts.get("low", 0),
        "total_attack_paths": len(attack_paths),
        "critical_attack_paths": critical_paths,
        "overall_risk_score": overall_risk,
        "quick_wins": quick_wins,
        "top_categories": top_categories,
    }
