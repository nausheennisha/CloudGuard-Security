"""
AWS resource scanner.

Uses boto3 to enumerate account resources (EC2, S3, IAM, RDS, Lambda, KMS,
VPC/Security Groups) needed to build the attack graph and run the risk
engine. If AWS credentials are not configured, or `use_live_aws=False`, the
scanner transparently falls back to the bundled mock dataset so the rest of
the application can be developed/demoed offline.

Real scanning is intentionally read-only: every boto3 call here is a
"describe"/"list"/"get" call. No resource is ever modified.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.data.mock_data import get_mock_resources, get_mock_vulnerabilities

logger = logging.getLogger("cloudguard.aws_scanner")

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:  # boto3 not installed in this environment
    BOTO3_AVAILABLE = False


class AWSScanner:
    """Collects a normalized inventory of security-relevant AWS resources."""

    def __init__(self, regions: List[str] | None = None, account_id: str | None = None):
        self.regions = regions or ["us-east-1"]
        self.account_id = account_id

    # ------------------------------------------------------------------ #
    # Public entrypoint
    # ------------------------------------------------------------------ #
    def scan(self, use_live_aws: bool = False) -> Dict[str, Any]:
        """
        Returns {"resources": [...], "vulnerabilities": [...], "source": "live"|"mock"}

        `vulnerabilities` from a live scan are raw findings detected directly
        from resource configuration (e.g. "public bucket"); the risk engine
        enriches these further before they're served to the frontend.
        """
        if use_live_aws and BOTO3_AVAILABLE:
            try:
                resources = self._scan_live()
                findings = self._derive_findings(resources)
                return {"resources": resources, "vulnerabilities": findings, "source": "live"}
            except (NoCredentialsError, ClientError, BotoCoreError) as exc:
                logger.warning("Live AWS scan failed (%s); falling back to mock data.", exc)
            except Exception as exc:  # defensive: never crash the API on scan failure
                logger.warning("Unexpected error during live scan (%s); using mock data.", exc)

        return {
            "resources": get_mock_resources(),
            "vulnerabilities": get_mock_vulnerabilities(),
            "source": "mock",
        }

    # ------------------------------------------------------------------ #
    # Live AWS collection (read-only describe/list/get calls only)
    # ------------------------------------------------------------------ #
    def _scan_live(self) -> List[Dict[str, Any]]:
        resources: List[Dict[str, Any]] = [{
            "id": "internet", "name": "Public Internet", "type": "internet",
            "account_id": "-", "region": "-", "public_exposure": True,
            "tags": {}, "metadata": {},
        }]

        resources += self._scan_iam()
        for region in self.regions:
            resources += self._scan_ec2_and_sg(region)
            resources += self._scan_rds(region)
            resources += self._scan_lambda(region)
            resources += self._scan_kms(region)
            resources += self._scan_vpc(region)
        resources += self._scan_s3()  # S3 is a global listing, per-bucket region lookups
        return resources

    def _scan_iam(self) -> List[Dict[str, Any]]:
        iam = boto3.client("iam")
        out = []
        for user in iam.list_users().get("Users", []):
            keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
            try:
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
            except ClientError:
                mfa = []
            out.append({
                "id": f"iam-user-{user['UserName']}", "name": user["UserName"],
                "type": "iam_user", "account_id": self.account_id or "-", "region": "global",
                "public_exposure": False, "tags": {},
                "metadata": {"mfa_enabled": len(mfa) > 0, "access_keys": len(keys),
                             "console_access": True},
            })
        for role in iam.list_roles().get("Roles", []):
            policies = iam.list_attached_role_policies(RoleName=role["RoleName"])
            policy_names = [p["PolicyName"] for p in policies.get("AttachedPolicies", [])]
            out.append({
                "id": f"iam-role-{role['RoleName']}", "name": role["RoleName"],
                "type": "iam_role", "account_id": self.account_id or "-", "region": "global",
                "public_exposure": False, "tags": {},
                "metadata": {"attached_policies": policy_names},
            })
        return out

    def _scan_ec2_and_sg(self, region: str) -> List[Dict[str, Any]]:
        ec2 = boto3.client("ec2", region_name=region)
        out = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            ingress = [{"port": r.get("FromPort"), "protocol": r.get("IpProtocol"),
                        "cidr": ip.get("CidrIp")}
                       for r in sg.get("IpPermissions", []) for ip in r.get("IpRanges", [])]
            public = any(r.get("cidr") == "0.0.0.0/0" for r in ingress)
            out.append({
                "id": sg["GroupId"], "name": sg.get("GroupName", sg["GroupId"]),
                "type": "security_group", "account_id": self.account_id or "-", "region": region,
                "public_exposure": public, "tags": {},
                "metadata": {"ingress_rules": ingress},
            })
        for res in ec2.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                out.append({
                    "id": inst["InstanceId"],
                    "name": next((t["Value"] for t in inst.get("Tags", [])
                                  if t["Key"] == "Name"), inst["InstanceId"]),
                    "type": "ec2_instance", "account_id": self.account_id or "-",
                    "region": region, "public_exposure": bool(inst.get("PublicIpAddress")),
                    "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                    "metadata": {
                        "public_ip": inst.get("PublicIpAddress"),
                        "security_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
                        "iam_role": (inst.get("IamInstanceProfile") or {}).get("Arn"),
                        "state": inst.get("State", {}).get("Name"),
                    },
                })
        return out

    def _scan_s3(self) -> List[Dict[str, Any]]:
        s3 = boto3.client("s3")
        out = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                encryption = enc["ServerSideEncryptionConfiguration"]["Rules"][0][
                    "ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            except ClientError:
                encryption = "none"
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                public_blocked = all(pab.values())
            except ClientError:
                public_blocked = False
            out.append({
                "id": f"s3-{name}", "name": name, "type": "s3_bucket",
                "account_id": self.account_id or "-", "region": "us-east-1",
                "public_exposure": not public_blocked, "tags": {},
                "metadata": {"encryption": encryption, "public_access_block": public_blocked},
            })
        return out

    def _scan_rds(self, region: str) -> List[Dict[str, Any]]:
        rds = boto3.client("rds", region_name=region)
        out = []
        for db in rds.describe_db_instances().get("DBInstances", []):
            out.append({
                "id": db["DBInstanceIdentifier"], "name": db["DBInstanceIdentifier"],
                "type": "rds_instance", "account_id": self.account_id or "-", "region": region,
                "public_exposure": db.get("PubliclyAccessible", False), "tags": {},
                "metadata": {"engine": db.get("Engine"),
                             "encrypted_at_rest": db.get("StorageEncrypted", False),
                             "publicly_accessible": db.get("PubliclyAccessible", False)},
            })
        return out

    def _scan_lambda(self, region: str) -> List[Dict[str, Any]]:
        lam = boto3.client("lambda", region_name=region)
        out = []
        for fn in lam.list_functions().get("Functions", []):
            out.append({
                "id": fn["FunctionArn"], "name": fn["FunctionName"], "type": "lambda_function",
                "account_id": self.account_id or "-", "region": region,
                "public_exposure": False, "tags": {},
                "metadata": {"execution_role": fn.get("Role"), "runtime": fn.get("Runtime"),
                             "kms_key": fn.get("KMSKeyArn")},
            })
        return out

    def _scan_kms(self, region: str) -> List[Dict[str, Any]]:
        kms = boto3.client("kms", region_name=region)
        out = []
        for key in kms.list_keys().get("Keys", []):
            try:
                rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]
            except ClientError:
                rotation = False
            out.append({
                "id": key["KeyId"], "name": key["KeyId"], "type": "kms_key",
                "account_id": self.account_id or "-", "region": region,
                "public_exposure": False, "tags": {},
                "metadata": {"rotation_enabled": rotation},
            })
        return out

    def _scan_vpc(self, region: str) -> List[Dict[str, Any]]:
        ec2 = boto3.client("ec2", region_name=region)
        out = []
        for vpc in ec2.describe_vpcs().get("Vpcs", []):
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}]
            ).get("FlowLogs", [])
            out.append({
                "id": vpc["VpcId"], "name": vpc["VpcId"], "type": "vpc",
                "account_id": self.account_id or "-", "region": region,
                "public_exposure": False, "tags": {},
                "metadata": {"flow_logs_enabled": len(flow_logs) > 0},
            })
        return out

    # ------------------------------------------------------------------ #
    # Lightweight rule-based findings derived straight from live config
    # ------------------------------------------------------------------ #
    def _derive_findings(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        For a live scan, run a small set of deterministic config checks to
        seed vulnerabilities. This intentionally mirrors the categories used
        in the mock dataset so the risk engine and graph builder behave
        identically regardless of data source.
        """
        findings = []
        for r in resources:
            md = r.get("metadata", {})
            if r["type"] == "s3_bucket" and r.get("public_exposure"):
                findings.append(self._finding(
                    r, "Data Exposure", "critical",
                    f"{r['name']} is publicly accessible",
                    f"{r['name']} does not have S3 Block Public Access fully enabled.",
                    9.0, 9.5, 9.5, "Enable S3 Block Public Access on this bucket.", "low"))
            if r["type"] == "s3_bucket" and md.get("encryption") == "none":
                findings.append(self._finding(
                    r, "Encryption", "high",
                    f"{r['name']} is not encrypted at rest",
                    f"{r['name']} has no default server-side encryption configured.",
                    3.5, 8.0, 6.0, "Enable default SSE-KMS encryption.", "low"))
            if r["type"] == "security_group" and r.get("public_exposure"):
                findings.append(self._finding(
                    r, "Network Exposure", "high",
                    f"{r['name']} allows inbound traffic from 0.0.0.0/0",
                    f"{r['name']} has one or more ingress rules open to the internet.",
                    7.5, 7.0, 8.5, "Restrict ingress CIDR ranges to known networks.", "low"))
            if r["type"] == "rds_instance" and not md.get("encrypted_at_rest", True):
                findings.append(self._finding(
                    r, "Encryption", "high",
                    f"{r['name']} is not encrypted at rest",
                    f"{r['name']} does not have storage encryption enabled.",
                    3.0, 9.0, 4.0, "Recreate the instance from an encrypted snapshot.", "high"))
            if r["type"] == "iam_role" and "AdministratorAccess" in md.get("attached_policies", []):
                findings.append(self._finding(
                    r, "IAM Misconfiguration", "critical",
                    f"{r['name']} has AdministratorAccess attached",
                    f"{r['name']} is attached to the AdministratorAccess managed policy.",
                    7.0, 10.0, 6.0, "Scope down to a least-privilege custom policy.", "medium"))
            if r["type"] == "iam_user" and not md.get("mfa_enabled", True):
                findings.append(self._finding(
                    r, "IAM Misconfiguration", "high",
                    f"{r['name']} does not have MFA enabled",
                    f"{r['name']} can authenticate without a second factor.",
                    7.0, 7.5, 6.0, "Enforce MFA for all IAM users with console access.", "medium"))
            if r["type"] == "kms_key" and not md.get("rotation_enabled", True):
                findings.append(self._finding(
                    r, "Encryption", "low",
                    f"{r['name']} key rotation is disabled",
                    f"{r['name']} does not have automatic annual rotation enabled.",
                    1.5, 4.0, 2.0, "Enable automatic key rotation.", "low"))
            if r["type"] == "vpc" and not md.get("flow_logs_enabled", True):
                findings.append(self._finding(
                    r, "Logging & Monitoring", "medium",
                    f"{r['name']} does not have flow logs enabled",
                    f"{r['name']} has no VPC Flow Logs configured.",
                    1.0, 5.0, 2.0, "Enable VPC Flow Logs.", "low"))
        return findings

    @staticmethod
    def _finding(resource, category, severity, title, description,
                 exploitability, impact, exposure, remediation, effort) -> Dict[str, Any]:
        return {
            "id": f"vuln-{resource['id']}-{category.replace(' ', '').lower()}",
            "title": title, "description": description, "severity": severity,
            "resource_id": resource["id"], "resource_name": resource["name"],
            "resource_type": resource["type"], "category": category, "cve": None,
            "cvss_score": None, "exploitability": exploitability, "impact": impact,
            "exposure": exposure, "remediation": remediation, "remediation_effort": effort,
            "compliance_frameworks": [], "discovered_at": "live-scan",
        }
