import logging
from typing import Dict, Any, List

logger = logging.getLogger("sentriq.scanners.cloud.cspm")


def mask_cloud_credential(ref: str) -> str:
    """Mask cloud credential, role ARN, or project secret for safe storage and display."""
    if not ref:
        return ""
    ref_clean = ref.strip()
    if ref_clean.startswith("arn:aws:"):
        parts = ref_clean.split(":")
        if len(parts) >= 6:
            parts[4] = "****" + parts[4][-4:] if len(parts[4]) >= 4 else "****"
            return ":".join(parts)
    if len(ref_clean) <= 8:
        return "****"
    return f"{ref_clean[:4]}****{ref_clean[-4:]}"


class CspmAnalyzer:
    """Audits cloud resource configurations against CIS Benchmarks and OWASP Cloud Top 10."""

    @classmethod
    def audit_configuration(
        cls,
        provider: str,
        account_identifier: str,
        config_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Runs read-only security checks across storage, IAM, network, and database resources.
        Returns list of finding dictionaries with severity, risk score, and remediation.
        """
        findings: List[Dict[str, Any]] = []

        # 1. Storage / S3 Checks
        buckets = config_data.get("buckets", [])
        for b in buckets:
            b_name = b.get("name", "unnamed-bucket")
            if b.get("public_access_block") is False or b.get("is_public") is True:
                findings.append({
                    "service": "storage",
                    "resource_id": b_name,
                    "resource_type": "storage_bucket",
                    "benchmark_ref": "CIS-STORAGE-PUBLIC-ACCESS",
                    "title": f"Storage Bucket '{b_name}' Has Public Access Enabled",
                    "description": "Bucket ACL or policy grants public read/write access to unauthenticated internet traffic.",
                    "severity": "critical",
                    "risk_score": 90,
                    "confidence": 1.0,
                    "remediation": "Enable S3 Block Public Access and restrict ACLs to specific IAM principals or VPC endpoints.",
                })

            if b.get("encryption_enabled") is False or b.get("sse_algorithm") is None:
                findings.append({
                    "service": "storage",
                    "resource_id": b_name,
                    "resource_type": "storage_bucket",
                    "benchmark_ref": "CIS-STORAGE-ENCRYPTION",
                    "title": f"Storage Bucket '{b_name}' Lacks Default Server-Side Encryption",
                    "description": "Bucket objects are stored without mandatory KMS/AES-256 server-side encryption at rest.",
                    "severity": "high",
                    "risk_score": 70,
                    "confidence": 1.0,
                    "remediation": "Configure default encryption on the bucket using AWS KMS (aws:kms) or AES-256.",
                })

            if b.get("versioning_enabled") is False:
                findings.append({
                    "service": "storage",
                    "resource_id": b_name,
                    "resource_type": "storage_bucket",
                    "benchmark_ref": "CIS-STORAGE-VERSIONING",
                    "title": f"Storage Bucket '{b_name}' Versioning Is Disabled",
                    "description": "Versioning protects data against accidental deletion, tampering, and ransomware overrides.",
                    "severity": "low",
                    "risk_score": 25,
                    "confidence": 0.9,
                    "remediation": "Enable bucket versioning and configure lifecycle transition rules.",
                })

        # 2. IAM & Identity Checks
        iam_data = config_data.get("iam", {})
        if iam_data.get("root_mfa_enabled") is False:
            findings.append({
                "service": "iam",
                "resource_id": "root-account",
                "resource_type": "iam_user",
                "benchmark_ref": "CIS-IAM-ROOT-MFA",
                "title": "Cloud Root Account Has No Multi-Factor Authentication (MFA)",
                "description": "The administrative root account can authenticate using only static credentials without hardware/software MFA.",
                "severity": "critical",
                "risk_score": 95,
                "confidence": 1.0,
                "remediation": "Immediately activate a hardware FIDO2 token or virtual TOTP device for the root user.",
            })

        for policy in iam_data.get("policies", []):
            p_name = policy.get("name", "unnamed-policy")
            if policy.get("has_wildcard_admin") is True or (policy.get("action") == "*" and policy.get("resource") == "*"):
                findings.append({
                    "service": "iam",
                    "resource_id": p_name,
                    "resource_type": "iam_policy",
                    "benchmark_ref": "CIS-IAM-WILDCARD-ADMIN",
                    "title": f"IAM Policy '{p_name}' Grants Full Wildcard Admin Privileges (*:*)",
                    "description": "The policy violates the principle of least privilege by allowing any action on any cloud resource.",
                    "severity": "critical",
                    "risk_score": 90,
                    "confidence": 1.0,
                    "remediation": "Scope down actions to minimum required service verbs and restrict Resource ARNs.",
                })

        for key in iam_data.get("access_keys", []):
            if key.get("age_days", 0) > 90 and key.get("is_active", True):
                k_id = key.get("id", "unknown-key")
                findings.append({
                    "service": "iam",
                    "resource_id": k_id,
                    "resource_type": "access_key",
                    "benchmark_ref": "CIS-IAM-STALE-KEYS",
                    "title": f"IAM Access Key '{k_id}' Exceeds 90-Day Rotation Policy",
                    "description": f"Access key has been active for {key.get('age_days')} days without cryptographic rotation.",
                    "severity": "medium",
                    "risk_score": 50,
                    "confidence": 1.0,
                    "remediation": "Create a new access key, deploy to workloads, and deactivate/delete the expired key.",
                })

        # 3. Network & Firewall Checks (Security Groups)
        security_groups = config_data.get("security_groups", [])
        for sg in security_groups:
            sg_id = sg.get("id", "sg-unknown")
            inbound_rules = sg.get("inbound_rules", [])
            for rule in inbound_rules:
                cidr = rule.get("cidr", "")
                from_port = rule.get("from_port", 0)
                to_port = rule.get("to_port", 0)

                if cidr in ["0.0.0.0/0", "::/0"]:
                    # Port 22 SSH
                    if from_port <= 22 <= to_port:
                        findings.append({
                            "service": "network",
                            "resource_id": sg_id,
                            "resource_type": "security_group",
                            "benchmark_ref": "CIS-NET-OPEN-SSH",
                            "title": f"Security Group '{sg_id}' Allows Unrestricted Ingress on Port 22 (SSH)",
                            "description": "Direct SSH access is exposed to the entire public internet (0.0.0.0/0), inviting brute-force attacks.",
                            "severity": "high",
                            "risk_score": 80,
                            "confidence": 1.0,
                            "remediation": "Restrict port 22 access to a corporate bastion, VPN CIDR, or migrate to AWS SSM Session Manager.",
                        })

                    # Port 3389 RDP
                    if from_port <= 3389 <= to_port:
                        findings.append({
                            "service": "network",
                            "resource_id": sg_id,
                            "resource_type": "security_group",
                            "benchmark_ref": "CIS-NET-OPEN-RDP",
                            "title": f"Security Group '{sg_id}' Allows Unrestricted Ingress on Port 3389 (RDP)",
                            "description": "Windows Remote Desktop Protocol is exposed to 0.0.0.0/0 without network perimeter restrictions.",
                            "severity": "high",
                            "risk_score": 80,
                            "confidence": 1.0,
                            "remediation": "Remove 0.0.0.0/0 from RDP rules and enforce corporate VPN / Zero Trust access gateway.",
                        })

                    # Database ports (5432 PostgreSQL, 3306 MySQL, 27017 MongoDB)
                    if (from_port <= 5432 <= to_port) or (from_port <= 3306 <= to_port) or (from_port <= 27017 <= to_port):
                        findings.append({
                            "service": "network",
                            "resource_id": sg_id,
                            "resource_type": "security_group",
                            "benchmark_ref": "CIS-NET-OPEN-DATABASE",
                            "title": f"Security Group '{sg_id}' Exposes Database Port to Public Internet",
                            "description": "Relational or document database listener is directly reachable from public IP addresses.",
                            "severity": "critical",
                            "risk_score": 90,
                            "confidence": 1.0,
                            "remediation": "Place the database inside private subnets and only allow ingress from application security groups.",
                        })

        # 4. Supabase & Database PaaS Specific Checks
        supabase_data = config_data.get("supabase", {})
        if provider.lower() == "supabase" or supabase_data:
            tables = supabase_data.get("tables", [])
            for t in tables:
                t_name = t.get("name", "unnamed-table")
                if t.get("rls_enabled") is False:
                    findings.append({
                        "service": "database",
                        "resource_id": t_name,
                        "resource_type": "supabase_table",
                        "benchmark_ref": "CIS-SUPABASE-RLS-DISABLED",
                        "title": f"Supabase Table '{t_name}' Has Row Level Security (RLS) Disabled",
                        "description": "Without RLS, any client holding an anonymous or authenticated JWT can read, mutate, or delete all records via PostgREST.",
                        "severity": "critical",
                        "risk_score": 95,
                        "confidence": 1.0,
                        "remediation": f"Run 'ALTER TABLE {t_name} ENABLE ROW LEVEL SECURITY;' and establish granular SELECT/INSERT policies.",
                    })

            if supabase_data.get("ssl_enforced") is False:
                findings.append({
                    "service": "database",
                    "resource_id": account_identifier,
                    "resource_type": "database_connection",
                    "benchmark_ref": "CIS-SUPABASE-SSL-ENFORCED",
                    "title": "Database Connection Does Not Enforce TLS/SSL",
                    "description": "Direct PostgreSQL connections may transmit plaintext database queries, tokens, and credentials over untrusted networks.",
                    "severity": "high",
                    "risk_score": 75,
                    "confidence": 1.0,
                    "remediation": "Enforce SSL connection requirement in Supabase project database settings (sslmode=require).",
                })

        return findings
