"""
Generates a realistic, deterministic sample cloud environment (resources +
misconfigurations) so CloudGuard can be demoed and developed against without
live AWS credentials. Structure mirrors what app.services.aws_scanner returns
from a real account, so the rest of the pipeline (graph builder, risk engine)
is agnostic to the data source.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

random.seed(42)

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
ACCOUNT_ID = "123456789012"


def _iso(days_ago: int) -> str:
    return (datetime.utcnow() - timedelta(days=days_ago)).isoformat() + "Z"


def get_mock_resources():
    return [
        {"id": "internet", "name": "Public Internet", "type": "internet",
         "account_id": "-", "region": "-", "public_exposure": True, "tags": {}, "metadata": {}},

        {"id": "iam-user-devops", "name": "devops-ci-user", "type": "iam_user",
         "account_id": ACCOUNT_ID, "region": "global", "public_exposure": False,
         "tags": {"team": "platform"}, "metadata": {"mfa_enabled": False,
         "access_keys": 2, "access_key_age_days": 410, "console_access": True}},

        {"id": "iam-user-readonly", "name": "analytics-readonly", "type": "iam_user",
         "account_id": ACCOUNT_ID, "region": "global", "public_exposure": False,
         "tags": {"team": "data"}, "metadata": {"mfa_enabled": True, "access_keys": 1,
         "access_key_age_days": 45, "console_access": False}},

        {"id": "iam-role-lambda-exec", "name": "lambda-exec-role", "type": "iam_role",
         "account_id": ACCOUNT_ID, "region": "global", "public_exposure": False,
         "tags": {}, "metadata": {"attached_policies": ["AdministratorAccess"],
         "trust_policy_wildcard": False}},

        {"id": "iam-role-ec2-app", "name": "ec2-app-instance-role", "type": "iam_role",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {}, "metadata": {"attached_policies": ["S3FullAccess", "SecretsManagerReadWrite"],
         "trust_policy_wildcard": False}},

        {"id": "sg-web-public", "name": "web-tier-sg", "type": "security_group",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": True,
         "tags": {"tier": "web"}, "metadata": {"ingress_rules": [
             {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
             {"port": 443, "cidr": "0.0.0.0/0", "protocol": "tcp"},
             {"port": 80, "cidr": "0.0.0.0/0", "protocol": "tcp"},
         ]}},

        {"id": "sg-db-internal", "name": "db-tier-sg", "type": "security_group",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {"tier": "db"}, "metadata": {"ingress_rules": [
             {"port": 5432, "cidr": "10.0.1.0/24", "protocol": "tcp"},
         ]}},

        {"id": "ec2-web-01", "name": "web-server-01", "type": "ec2_instance",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": True,
         "tags": {"env": "production", "tier": "web"}, "metadata": {
             "public_ip": "54.210.11.42", "security_groups": ["sg-web-public"],
             "iam_role": "iam-role-ec2-app", "os": "Amazon Linux 2",
             "patch_level": "outdated", "ssm_managed": False}},

        {"id": "ec2-worker-02", "name": "batch-worker-02", "type": "ec2_instance",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {"env": "production", "tier": "worker"}, "metadata": {
             "public_ip": None, "security_groups": ["sg-db-internal"],
             "iam_role": "iam-role-lambda-exec", "os": "Ubuntu 22.04",
             "patch_level": "current", "ssm_managed": True}},

        {"id": "lambda-image-resize", "name": "image-resize-fn", "type": "lambda_function",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {}, "metadata": {"execution_role": "iam-role-lambda-exec",
         "env_vars_encrypted": False, "runtime": "python3.9", "public_url": False}},

        {"id": "s3-app-assets", "name": "cloudguard-app-assets", "type": "s3_bucket",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {}, "metadata": {"encryption": "SSE-S3", "versioning": True,
         "public_access_block": True, "bucket_policy_public": False}},

        {"id": "s3-customer-backups", "name": "cloudguard-customer-backups", "type": "s3_bucket",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": True,
         "tags": {"data_classification": "sensitive"}, "metadata": {
             "encryption": "none", "versioning": False, "public_access_block": False,
             "bucket_policy_public": True, "contains_pii": True}},

        {"id": "rds-prod-primary", "name": "prod-postgres-primary", "type": "rds_instance",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {"data_classification": "sensitive"}, "metadata": {
             "engine": "postgres", "encrypted_at_rest": False, "publicly_accessible": False,
             "security_groups": ["sg-db-internal"], "automated_backups": True,
             "multi_az": False}},

        {"id": "kms-app-key", "name": "app-data-key", "type": "kms_key",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {}, "metadata": {"rotation_enabled": False,
         "key_policy_wildcard_principal": True}},

        {"id": "vpc-main", "name": "main-vpc", "type": "vpc",
         "account_id": ACCOUNT_ID, "region": "us-east-1", "public_exposure": False,
         "tags": {}, "metadata": {"flow_logs_enabled": False}},
    ]


def get_mock_vulnerabilities():
    """
    Findings are hand-authored to reflect realistic, high-signal cloud
    misconfigurations (IAM over-privilege, public storage, unencrypted data,
    network exposure) rather than randomly generated noise.
    """
    return [
        {
            "id": "vuln-001",
            "title": "S3 bucket with sensitive data is publicly accessible",
            "description": "cloudguard-customer-backups has a public bucket policy and no public "
                            "access block, exposing objects tagged as containing PII to anonymous "
                            "internet access.",
            "severity": "critical",
            "resource_id": "s3-customer-backups",
            "resource_name": "cloudguard-customer-backups",
            "resource_type": "s3_bucket",
            "category": "Data Exposure",
            "cve": None,
            "cvss_score": None,
            "exploitability": 9.5,
            "impact": 10.0,
            "exposure": 10.0,
            "remediation": "Enable S3 Block Public Access, remove the public bucket policy "
                            "statement, and audit access logs for prior unauthorized reads.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 2.1.5", "PCI-DSS 3.2.1", "SOC 2"],
            "discovered_at": _iso(2),
        },
        {
            "id": "vuln-002",
            "title": "Unencrypted S3 bucket storing customer backups",
            "description": "cloudguard-customer-backups does not have server-side encryption "
                            "enabled, so data at rest is stored in plaintext.",
            "severity": "high",
            "resource_id": "s3-customer-backups",
            "resource_name": "cloudguard-customer-backups",
            "resource_type": "s3_bucket",
            "category": "Encryption",
            "cve": None,
            "cvss_score": None,
            "exploitability": 4.0,
            "impact": 8.5,
            "exposure": 7.0,
            "remediation": "Enable default SSE-KMS encryption on the bucket and re-encrypt "
                            "existing objects via an S3 Batch Operations job.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 2.1.1", "HIPAA"],
            "discovered_at": _iso(2),
        },
        {
            "id": "vuln-003",
            "title": "IAM role attached to Lambda has AdministratorAccess",
            "description": "lambda-exec-role is attached to the AdministratorAccess managed "
                            "policy, granting the image-resize-fn function full account "
                            "privileges far beyond what it requires.",
            "severity": "critical",
            "resource_id": "iam-role-lambda-exec",
            "resource_name": "lambda-exec-role",
            "resource_type": "iam_role",
            "category": "IAM Misconfiguration",
            "cve": None,
            "cvss_score": None,
            "exploitability": 7.0,
            "impact": 10.0,
            "exposure": 6.0,
            "remediation": "Replace AdministratorAccess with a least-privilege policy scoped to "
                            "the specific S3 and CloudWatch actions the function performs.",
            "remediation_effort": "medium",
            "compliance_frameworks": ["CIS AWS 1.16", "NIST 800-53 AC-6"],
            "discovered_at": _iso(5),
        },
        {
            "id": "vuln-004",
            "title": "Security group allows unrestricted SSH from the internet",
            "description": "web-tier-sg permits inbound TCP/22 from 0.0.0.0/0, allowing SSH "
                            "brute-force attempts from any internet host against web-server-01.",
            "severity": "high",
            "resource_id": "sg-web-public",
            "resource_name": "web-tier-sg",
            "resource_type": "security_group",
            "category": "Network Exposure",
            "cve": None,
            "cvss_score": None,
            "exploitability": 8.0,
            "impact": 7.0,
            "exposure": 9.0,
            "remediation": "Restrict port 22 to a bastion host or corporate CIDR range, or "
                            "replace SSH access with AWS Systems Manager Session Manager.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 5.2"],
            "discovered_at": _iso(1),
        },
        {
            "id": "vuln-005",
            "title": "IAM user has console + API access without MFA",
            "description": "devops-ci-user has both console access and 2 long-lived access "
                            "keys (410 days old) with MFA disabled, significantly widening the "
                            "credential-theft attack surface.",
            "severity": "high",
            "resource_id": "iam-user-devops",
            "resource_name": "devops-ci-user",
            "resource_type": "iam_user",
            "category": "IAM Misconfiguration",
            "cve": None,
            "cvss_score": None,
            "exploitability": 7.5,
            "impact": 8.0,
            "exposure": 6.0,
            "remediation": "Enforce MFA via IAM policy condition, rotate access keys, and "
                            "migrate CI usage to short-lived STS credentials or OIDC federation.",
            "remediation_effort": "medium",
            "compliance_frameworks": ["CIS AWS 1.10", "CIS AWS 1.4"],
            "discovered_at": _iso(10),
        },
        {
            "id": "vuln-006",
            "title": "EC2 instance role grants broad S3 and Secrets Manager access",
            "description": "ec2-app-instance-role attached to web-server-01 has S3FullAccess "
                            "and SecretsManagerReadWrite, so compromise of the internet-facing "
                            "instance yields broad data-plane access.",
            "severity": "high",
            "resource_id": "iam-role-ec2-app",
            "resource_name": "ec2-app-instance-role",
            "resource_type": "iam_role",
            "category": "IAM Misconfiguration",
            "cve": None,
            "cvss_score": None,
            "exploitability": 6.5,
            "impact": 8.0,
            "exposure": 6.0,
            "remediation": "Scope the role to specific bucket ARNs and specific secret ARNs "
                            "the application actually needs; split read vs write permissions.",
            "remediation_effort": "medium",
            "compliance_frameworks": ["NIST 800-53 AC-6"],
            "discovered_at": _iso(7),
        },
        {
            "id": "vuln-007",
            "title": "Internet-facing EC2 instance is running outdated patches",
            "description": "web-server-01 is publicly reachable on ports 80/443/22 and its "
                            "patch level is flagged as outdated, increasing exposure to known "
                            "OS-level exploits.",
            "severity": "medium",
            "resource_id": "ec2-web-01",
            "resource_name": "web-server-01",
            "resource_type": "ec2_instance",
            "category": "Patch Management",
            "cve": "CVE-2023-38545",
            "cvss_score": 7.5,
            "exploitability": 6.0,
            "impact": 6.5,
            "exposure": 8.0,
            "remediation": "Apply pending OS and package updates, and enroll the instance in "
                            "AWS Systems Manager Patch Manager for automated patch compliance.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 4.1"],
            "discovered_at": _iso(3),
        },
        {
            "id": "vuln-008",
            "title": "RDS instance is not encrypted at rest",
            "description": "prod-postgres-primary stores sensitive production data without "
                            "storage encryption enabled.",
            "severity": "high",
            "resource_id": "rds-prod-primary",
            "resource_name": "prod-postgres-primary",
            "resource_type": "rds_instance",
            "category": "Encryption",
            "cve": None,
            "cvss_score": None,
            "exploitability": 3.0,
            "impact": 9.0,
            "exposure": 4.0,
            "remediation": "Snapshot the instance, create an encrypted copy using a KMS key, "
                            "and cut over during a maintenance window.",
            "remediation_effort": "high",
            "compliance_frameworks": ["CIS AWS 2.3.1", "PCI-DSS 3.4"],
            "discovered_at": _iso(14),
        },
        {
            "id": "vuln-009",
            "title": "KMS key policy grants access to a wildcard principal",
            "description": "app-data-key's key policy includes a statement with Principal: \"*\", "
                            "effectively allowing any authenticated AWS principal to request use "
                            "of the key if combined with a permissive IAM policy.",
            "severity": "medium",
            "resource_id": "kms-app-key",
            "resource_name": "app-data-key",
            "resource_type": "kms_key",
            "category": "IAM Misconfiguration",
            "cve": None,
            "cvss_score": None,
            "exploitability": 4.5,
            "impact": 7.0,
            "exposure": 3.0,
            "remediation": "Restrict the key policy Principal to explicit role/account ARNs "
                            "and remove the wildcard statement.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 1.16"],
            "discovered_at": _iso(6),
        },
        {
            "id": "vuln-010",
            "title": "KMS key rotation is disabled",
            "description": "app-data-key does not have automatic annual key rotation enabled.",
            "severity": "low",
            "resource_id": "kms-app-key",
            "resource_name": "app-data-key",
            "resource_type": "kms_key",
            "category": "Encryption",
            "cve": None,
            "cvss_score": None,
            "exploitability": 1.5,
            "impact": 4.0,
            "exposure": 2.0,
            "remediation": "Enable automatic key rotation in KMS key settings.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 2.8"],
            "discovered_at": _iso(20),
        },
        {
            "id": "vuln-011",
            "title": "VPC Flow Logs are disabled",
            "description": "main-vpc does not have flow logs enabled, limiting network "
                            "forensic visibility during an incident.",
            "severity": "medium",
            "resource_id": "vpc-main",
            "resource_name": "main-vpc",
            "resource_type": "vpc",
            "category": "Logging & Monitoring",
            "cve": None,
            "cvss_score": None,
            "exploitability": 1.0,
            "impact": 5.0,
            "exposure": 2.0,
            "remediation": "Enable VPC Flow Logs to CloudWatch Logs or S3 for all traffic types.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 3.9"],
            "discovered_at": _iso(30),
        },
        {
            "id": "vuln-012",
            "title": "Lambda environment variables are not encrypted with a CMK",
            "description": "image-resize-fn stores environment variables using only the default "
                            "AWS-managed key rather than a customer-managed KMS key, limiting "
                            "control over access and rotation.",
            "severity": "low",
            "resource_id": "lambda-image-resize",
            "resource_name": "image-resize-fn",
            "resource_type": "lambda_function",
            "category": "Encryption",
            "cve": None,
            "cvss_score": None,
            "exploitability": 2.0,
            "impact": 3.5,
            "exposure": 2.0,
            "remediation": "Configure the function to encrypt environment variables with a "
                            "customer-managed KMS key.",
            "remediation_effort": "low",
            "compliance_frameworks": ["CIS AWS 2.1.1"],
            "discovered_at": _iso(25),
        },
    ]
