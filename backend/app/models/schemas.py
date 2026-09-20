"""
Pydantic data models shared across the API layer.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResourceType(str, Enum):
    INTERNET = "internet"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    EC2_INSTANCE = "ec2_instance"
    SECURITY_GROUP = "security_group"
    S3_BUCKET = "s3_bucket"
    RDS_INSTANCE = "rds_instance"
    LAMBDA_FUNCTION = "lambda_function"
    VPC = "vpc"
    KMS_KEY = "kms_key"


class CloudResource(BaseModel):
    id: str
    name: str
    type: ResourceType
    account_id: str
    region: str
    public_exposure: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    resource_id: str
    resource_name: str
    resource_type: ResourceType
    category: str  # e.g. "IAM Misconfiguration", "Network Exposure", "Encryption"
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    exploitability: float = Field(..., ge=0, le=10)
    impact: float = Field(..., ge=0, le=10)
    exposure: float = Field(..., ge=0, le=10)
    risk_score: float = 0.0
    remediation: str
    remediation_effort: str  # "low" | "medium" | "high"
    compliance_frameworks: List[str] = Field(default_factory=list)
    discovered_at: str


class GraphNode(BaseModel):
    id: str
    label: str
    type: ResourceType
    severity: Optional[Severity] = None
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    technique: str
    weight: float = 1.0


class AttackPath(BaseModel):
    id: str
    name: str
    node_ids: List[str]
    edge_ids: List[str]
    total_risk_score: float
    severity: Severity
    entry_point: str
    target: str
    steps: int
    narrative: str


class AttackGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    attack_paths: List[AttackPath]


class RemediationItem(BaseModel):
    id: str
    vulnerability_id: str
    title: str
    priority_rank: int
    risk_score: float
    severity: Severity
    effort: str
    quick_win: bool
    affected_resources: List[str]
    recommended_action: str
    estimated_risk_reduction: float


class DashboardSummary(BaseModel):
    total_resources: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_attack_paths: int
    critical_attack_paths: int
    overall_risk_score: float
    quick_wins: int
    top_categories: List[Dict[str, Any]]


class ScanRequest(BaseModel):
    account_id: Optional[str] = None
    regions: List[str] = Field(default_factory=lambda: ["us-east-1"])
    use_live_aws: bool = False


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    resources_scanned: int
    findings_count: int
    started_at: str
    completed_at: Optional[str] = None
