import re
from typing import List, Dict, Any, Optional

SECRET_PATTERNS = [
    {
        "rule_id": "SEC-AWS-KEY",
        "title": "Hardcoded AWS Access Key ID",
        "pattern": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "critical",
        "cwe": "CWE-798",
        "remediation": "Store AWS credentials in environment variables or use IAM Roles instead of hardcoded keys.",
    },
    {
        "rule_id": "SEC-GITHUB-PAT",
        "title": "Hardcoded GitHub Personal Access Token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "severity": "critical",
        "cwe": "CWE-798",
        "remediation": "Revoke this token immediately and use GitHub Actions secrets or environment variables.",
    },
    {
        "rule_id": "SEC-SLACK-TOKEN",
        "title": "Hardcoded Slack Token",
        "pattern": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
        "severity": "high",
        "cwe": "CWE-798",
        "remediation": "Rotate this Slack token and configure it via a secure secrets manager.",
    },
    {
        "rule_id": "SEC-PRIVATE-KEY",
        "title": "Exposed Cryptographic Private Key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": "critical",
        "cwe": "CWE-312",
        "remediation": "Remove private keys from repository history. Use a key vault (e.g., AWS KMS, HashiCorp Vault).",
    },
    {
        "rule_id": "SEC-GENERIC-API-KEY",
        "title": "Suspected Hardcoded API Key or Secret",
        "pattern": re.compile(r"""(?:api[_-]?key|secret[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][0-9a-zA-Z\-_=]{20,80}['"]""", re.IGNORECASE),
        "severity": "high",
        "cwe": "CWE-798",
        "remediation": "Extract hardcoded secrets into secure environment variables (.env files excluded from git).",
    },
    {
        "rule_id": "SEC-JWT-TOKEN",
        "title": "Hardcoded JSON Web Token (JWT)",
        "pattern": re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
        "severity": "medium",
        "cwe": "CWE-798",
        "remediation": "Do not commit static JWT tokens into source control. Generate tokens dynamically.",
    },
]


def mask_secret(matched_text: str) -> str:
    """Mask sensitive string content to prevent secret leakage in logs, database, or UI."""
    clean = matched_text.strip()
    if len(clean) <= 8:
        return "****"
    prefix = clean[:4]
    suffix = clean[-4:]
    return f"{prefix}****{suffix}"


def scan_file_for_secrets(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Scan file content for credentials and secrets using deterministic patterns."""
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # Ignore comments or docs that are likely test strings
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
            # Still scan if clearly looks like a private key or AWS key
            if "AKIA" not in stripped and "BEGIN" not in stripped:
                continue

        for rule in SECRET_PATTERNS:
            match = rule["pattern"].search(line)
            if match:
                raw_secret = match.group(0)
                # Mask secret before storing
                masked = mask_secret(raw_secret)
                sanitized_snippet = line.replace(raw_secret, masked).strip()

                findings.append({
                    "scan_type": "secret",
                    "title": rule["title"],
                    "description": f"Found exposed secret ({rule['rule_id']}) in {file_path}:{line_idx}.",
                    "severity": rule["severity"],
                    "confidence": 0.95,
                    "risk_score": 90 if rule["severity"] == "critical" else 75,
                    "file_path": file_path,
                    "line_number": line_idx,
                    "rule_id": rule["rule_id"],
                    "cwe": rule["cwe"],
                    "cve": None,
                    "snippet": sanitized_snippet[:250],
                    "remediation": rule["remediation"],
                })

    return findings
