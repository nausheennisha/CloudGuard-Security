"""
CloudGuard API — FastAPI application entrypoint.

Endpoints:
    GET  /api/health
    GET  /api/resources
    GET  /api/vulnerabilities
    GET  /api/attack-graph
    GET  /api/remediation
    GET  /api/dashboard
    POST /api/scan
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.models.schemas import ScanRequest
from app.services.aws_scanner import AWSScanner
from app.services.graph_builder import build_graph, find_attack_paths
from app.services.risk_engine import (
    enrich_vulnerabilities,
    build_remediation_plan,
    compute_dashboard_summary,
)

app = FastAPI(
    title="CloudGuard API",
    description="Cloud security analysis: attack path visualization, "
                "vulnerability detection, and remediation prioritization.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production to the deployed frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------- #
# In-memory cache of the "current" scan. A real deployment would persist
# this per-account/per-scan in a database (see README for suggested schema).
# ---------------------------------------------------------------------- #
_state = {
    "resources": [],
    "vulnerabilities": [],
    "graph": None,
    "edges": [],
    "attack_paths": [],
    "source": None,
    "last_scan_at": None,
    "scan_id": None,
}


def _run_scan(regions, account_id, use_live_aws) -> dict:
    scanner = AWSScanner(regions=regions, account_id=account_id)
    result = scanner.scan(use_live_aws=use_live_aws)

    resources = result["resources"]
    vulnerabilities = enrich_vulnerabilities(result["vulnerabilities"])
    graph, edges = build_graph(resources, vulnerabilities)
    attack_paths = find_attack_paths(graph)

    _state.update({
        "resources": resources,
        "vulnerabilities": vulnerabilities,
        "graph": graph,
        "edges": edges,
        "attack_paths": attack_paths,
        "source": result["source"],
        "last_scan_at": datetime.utcnow().isoformat() + "Z",
        "scan_id": str(uuid.uuid4()),
    })
    return _state


@app.on_event("startup")
def _seed_initial_scan():
    """Run an initial mock scan on boot so the frontend has data immediately."""
    _run_scan(regions=["us-east-1"], account_id=None, use_live_aws=False)


# ---------------------------------------------------------------------- #
# Routes
# ---------------------------------------------------------------------- #
@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    if not _state.get("resources") and not req:
        raise HTTPException(status_code=400, detail="Invalid scan request")
    _run_scan(regions=req.regions, account_id=req.account_id, use_live_aws=req.use_live_aws)
    return {
        "scan_id": _state["scan_id"],
        "status": "completed",
        "resources_scanned": len(_state["resources"]),
        "findings_count": len(_state["vulnerabilities"]),
        "started_at": _state["last_scan_at"],
        "completed_at": _state["last_scan_at"],
        "source": _state["source"],
    }


@app.get("/api/resources")
def get_resources(type: Optional[str] = Query(None, description="Filter by resource type")):
    resources = _state["resources"]
    if type:
        resources = [r for r in resources if r["type"] == type]
    return {"resources": resources, "total": len(resources), "source": _state["source"]}


@app.get("/api/vulnerabilities")
def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by category"),
):
    vulns = _state["vulnerabilities"]
    if severity:
        vulns = [v for v in vulns if v["severity"] == severity]
    if category:
        vulns = [v for v in vulns if v["category"] == category]
    return {"vulnerabilities": vulns, "total": len(vulns)}


@app.get("/api/attack-graph")
def get_attack_graph():
    graph = _state["graph"]
    if graph is None:
        raise HTTPException(status_code=404, detail="No scan has been run yet")

    nodes = [
        {
            "id": n,
            "label": data.get("name", n),
            "type": data.get("type"),
            "is_entry_point": data.get("is_entry_point", False),
            "is_crown_jewel": data.get("is_crown_jewel", False),
            "data": {"public_exposure": data.get("public_exposure", False),
                     "region": data.get("region"), "tags": data.get("tags", {})},
        }
        for n, data in graph.nodes(data=True)
    ]
    return {
        "nodes": nodes,
        "edges": _state["edges"],
        "attack_paths": _state["attack_paths"],
    }


@app.get("/api/remediation")
def get_remediation():
    plan = build_remediation_plan(_state["vulnerabilities"])
    return {"remediation_plan": plan, "total": len(plan)}


@app.get("/api/dashboard")
def get_dashboard():
    summary = compute_dashboard_summary(
        _state["resources"], _state["vulnerabilities"], _state["attack_paths"]
    )
    summary["source"] = _state["source"]
    summary["last_scan_at"] = _state["last_scan_at"]
    return summary


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
