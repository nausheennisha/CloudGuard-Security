"""
Builds the cloud attack graph and enumerates attack paths.

Nodes  = cloud resources (plus a synthetic "internet" node as the universal
         entry point).
Edges  = a possible attacker transition between two resources ("lateral
         movement" or "privilege escalation"), inferred from resource
         configuration (public exposure, IAM trust relationships, security
         group rules, attached roles, etc).

Attack paths are computed as the highest-risk simple paths from any entry
point (internet-reachable / low-privilege node) to any "crown jewel" node
(a resource holding sensitive data: RDS instances, S3 buckets tagged
sensitive, etc). Path risk is the product of per-edge traversal likelihood
combined with the value of the target, so shorter/likelier/higher-impact
paths naturally rank first.
"""
from __future__ import annotations

from typing import List, Dict, Any, Tuple
import itertools

import networkx as nx

CROWN_JEWEL_TYPES = {"rds_instance", "s3_bucket"}


def _is_crown_jewel(resource: Dict[str, Any]) -> bool:
    if resource["type"] not in CROWN_JEWEL_TYPES:
        return False
    md = resource.get("metadata", {})
    tags = resource.get("tags", {})
    if resource["type"] == "rds_instance":
        return True
    if resource["type"] == "s3_bucket":
        return md.get("contains_pii") or tags.get("data_classification") == "sensitive"
    return False


def _is_entry_point(resource: Dict[str, Any]) -> bool:
    if resource["id"] == "internet":
        return True
    if resource.get("public_exposure"):
        return True
    if resource["type"] == "iam_user" and not resource.get("metadata", {}).get("mfa_enabled", True):
        return True
    return False


def build_graph(resources: List[Dict[str, Any]],
                 vulns: List[Dict[str, Any]]) -> Tuple[nx.DiGraph, List[Dict[str, Any]]]:
    """Returns (networkx DiGraph, list of edge dicts) built from resource config."""
    g = nx.DiGraph()
    by_id = {r["id"]: r for r in resources}

    for r in resources:
        g.add_node(r["id"], **r, is_entry_point=_is_entry_point(r),
                   is_crown_jewel=_is_crown_jewel(r))

    edges: List[Dict[str, Any]] = []

    def add_edge(src, tgt, label, technique, weight):
        if src not in by_id or tgt not in by_id or src == tgt:
            return
        eid = f"edge-{src}-{tgt}"
        if g.has_edge(src, tgt):
            return
        g.add_edge(src, tgt, id=eid, label=label, technique=technique, weight=weight)
        edges.append({"id": eid, "source": src, "target": tgt, "label": label,
                       "technique": technique, "weight": weight})

    # Internet -> anything publicly exposed
    for r in resources:
        if r["id"] != "internet" and r.get("public_exposure"):
            add_edge("internet", r["id"], "Direct internet access",
                      "Public exposure", weight=0.9)

    # Public security group -> EC2 instances that use it
    for r in resources:
        if r["type"] == "ec2_instance":
            for sg_id in r.get("metadata", {}).get("security_groups", []):
                if sg_id in by_id:
                    add_edge(sg_id, r["id"], "Permits inbound network access",
                              "Network exposure via security group", weight=0.85)
                    # also connect internet directly if the SG allows 0.0.0.0/0
                    if by_id[sg_id].get("public_exposure"):
                        add_edge("internet", sg_id, "Unrestricted ingress (0.0.0.0/0)",
                                  "Open security group", weight=0.9)

    # EC2 / Lambda -> attached IAM role (compromise instance => assume role)
    for r in resources:
        if r["type"] in ("ec2_instance", "lambda_function"):
            role_ref = r.get("metadata", {}).get("iam_role") or r.get("metadata", {}).get("execution_role")
            if role_ref:
                role_id = role_ref if role_ref in by_id else _match_role_id(role_ref, by_id)
                if role_id:
                    add_edge(r["id"], role_id, "Assumes attached IAM role",
                              "Credential access via instance metadata", weight=0.8)

    # IAM role with broad policy -> S3 / RDS / KMS it can reach
    for r in resources:
        if r["type"] == "iam_role":
            policies = r.get("metadata", {}).get("attached_policies", [])
            broad = any(p in ("AdministratorAccess", "S3FullAccess", "SecretsManagerReadWrite")
                        for p in policies)
            if broad:
                for target in resources:
                    if target["type"] in ("s3_bucket", "rds_instance", "kms_key") and target["id"] != r["id"]:
                        add_edge(r["id"], target["id"], f"Uses over-privileged policy ({', '.join(policies)})",
                                  "Privilege escalation via IAM policy", weight=0.6)

    # IAM user without MFA -> roles they could assume / resources they can reach directly
    for r in resources:
        if r["type"] == "iam_user" and not r.get("metadata", {}).get("mfa_enabled", True):
            for target in resources:
                if target["type"] == "iam_role":
                    add_edge(r["id"], target["id"], "Weak credential hygiene (no MFA)",
                              "Credential compromise", weight=0.5)

    # Vulnerability-driven edges: a critical/high finding on a resource increases
    # likelihood of that resource being a pivot point, so connect it forward to
    # anything it has network/IAM reach to (already captured above); here we
    # additionally connect internet -> resource for any internet-facing high-severity vuln
    for v in vulns:
        if v["severity"] in ("critical", "high") and v["resource_id"] in by_id:
            res = by_id[v["resource_id"]]
            if res.get("public_exposure") or res["id"] == "internet":
                add_edge("internet", res["id"], f"Exploit: {v['title']}",
                          v["category"], weight=0.95)

    return g, edges


def _match_role_id(role_ref: str, by_id: Dict[str, Dict[str, Any]]):
    """Handle ARNs vs plain role ids depending on data source (mock vs live)."""
    for rid, r in by_id.items():
        if r["type"] != "iam_role":
            continue
        if role_ref == rid or role_ref == r.get("name") or role_ref.endswith(r.get("name", "\0")):
            return rid
    return None


def find_attack_paths(g: nx.DiGraph, max_paths: int = 8, max_length: int = 5) -> List[Dict[str, Any]]:
    """
    Enumerates simple paths from entry points to crown jewels, scores each by
    cumulative traversal likelihood x target value, and returns the top
    `max_paths` distinct paths.
    """
    entry_points = [n for n, d in g.nodes(data=True) if d.get("is_entry_point")]
    crown_jewels = [n for n, d in g.nodes(data=True) if d.get("is_crown_jewel")]

    candidates = []
    for src, tgt in itertools.product(entry_points, crown_jewels):
        if src == tgt:
            continue
        try:
            for path in nx.all_simple_paths(g, src, tgt, cutoff=max_length):
                if len(path) < 2:
                    continue
                edge_weights = [g[path[i]][path[i + 1]]["weight"] for i in range(len(path) - 1)]
                likelihood = 1.0
                for w in edge_weights:
                    likelihood *= w
                target_value = 10.0 if g.nodes[tgt]["type"] == "rds_instance" else 8.5
                total_risk = round(likelihood * target_value * 10, 1)
                candidates.append((total_risk, path, edge_weights))
        except nx.NodeNotFound:
            continue

    candidates.sort(key=lambda c: c[0], reverse=True)

    seen_signatures = set()
    results = []
    for total_risk, path, edge_weights in candidates:
        sig = tuple(path)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)

        severity = _severity_from_score(total_risk)
        edge_ids = [g[path[i]][path[i + 1]]["id"] for i in range(len(path) - 1)]
        node_labels = [g.nodes[n].get("name", n) for n in path]
        narrative = _build_narrative(g, path)

        results.append({
            "id": f"path-{len(results) + 1}",
            "name": f"{node_labels[0]} \u2192 {node_labels[-1]}",
            "node_ids": path,
            "edge_ids": edge_ids,
            "total_risk_score": min(total_risk, 100.0),
            "severity": severity,
            "entry_point": path[0],
            "target": path[-1],
            "steps": len(path) - 1,
            "narrative": narrative,
        })
        if len(results) >= max_paths:
            break

    return results


def _severity_from_score(score: float) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def _build_narrative(g: nx.DiGraph, path: List[str]) -> str:
    steps = []
    for i in range(len(path) - 1):
        edge = g[path[i]][path[i + 1]]
        src_name = g.nodes[path[i]].get("name", path[i])
        tgt_name = g.nodes[path[i + 1]].get("name", path[i + 1])
        steps.append(f"From {src_name}, attacker uses \u201c{edge['label']}\u201d "
                      f"({edge['technique']}) to reach {tgt_name}.")
    return " ".join(steps)
