import re
from typing import List, Dict, Any

SAST_RULES = [
    {
        "rule_id": "SAST-SQLI-RAW-CONCAT",
        "title": "Potential SQL Injection via String Concatenation",
        "pattern": re.compile(r"""(?:execute|cursor\.execute|raw_query|query)\s*\(\s*f?["'].*SELECT.*(?:%s|\+.*|\{.*\}).*["']""", re.IGNORECASE),
        "severity": "critical",
        "cwe": "CWE-89",
        "remediation": "Use parameterized queries or ORM query builders instead of raw string formatting in SQL statements.",
    },
    {
        "rule_id": "SAST-CMD-INJECTION",
        "title": "Command Injection Risk via Subshell Execution",
        "pattern": re.compile(r"""(?:os\.system|subprocess\.(?:Popen|run|call)\s*\(.*shell\s*=\s*True|child_process\.exec\s*\()"""),
        "severity": "critical",
        "cwe": "CWE-78",
        "remediation": "Avoid invoking shell commands with shell=True or pass arguments as an explicit array without shell interpolation.",
    },
    {
        "rule_id": "SAST-DANGEROUS-DESERIALIZATION",
        "title": "Unsafe Object Deserialization",
        "pattern": re.compile(r"""(?:pickle\.loads|yaml\.load\s*\([^,]+(?!\s*,\s*Loader\s*=\s*SafeLoader)\))"""),
        "severity": "high",
        "cwe": "CWE-502",
        "remediation": "Do not deserialize untrusted data with pickle. Use yaml.safe_load() instead of yaml.load().",
    },
    {
        "rule_id": "SAST-PATH-TRAVERSAL",
        "title": "Potential Path Traversal via Unvalidated File Path",
        "pattern": re.compile(r"""(?:open|fs\.readFileSync|fs\.readFile)\s*\(\s*(?:os\.path\.join|path\.join)\s*\(.*req\.(?:query|params|body)"""),
        "severity": "high",
        "cwe": "CWE-22",
        "remediation": "Sanitize user-supplied file paths and verify that the canonical path resides within the intended base directory.",
    },
    {
        "rule_id": "SAST-WEAK-CRYPTO-HASH",
        "title": "Use of Broken or Weak Cryptographic Hash",
        "pattern": re.compile(r"""(?:hashlib\.md5|hashlib\.sha1|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"])"""),
        "severity": "medium",
        "cwe": "CWE-327",
        "remediation": "Use secure hashing algorithms like SHA-256, SHA-3, or bcrypt/Argon2 for passwords.",
    },
    {
        "rule_id": "SAST-DISABLED-TLS-VERIFY",
        "title": "Disabled TLS/SSL Certificate Verification",
        "pattern": re.compile(r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"])"""),
        "severity": "high",
        "cwe": "CWE-295",
        "remediation": "Enable TLS certificate verification to prevent Man-in-the-Middle (MitM) attacks.",
    },
]


def scan_file_for_sast(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Scan source code file for static security vulnerabilities."""
    findings: List[Dict[str, Any]] = []

    # Check only relevant source extensions
    lower_path = file_path.lower()
    if not (
        lower_path.endswith(".py")
        or lower_path.endswith(".js")
        or lower_path.endswith(".ts")
        or lower_path.endswith(".tsx")
        or lower_path.endswith(".jsx")
        or lower_path.endswith(".go")
    ):
        return findings

    lines = content.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue

        for rule in SAST_RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "scan_type": "sast",
                    "title": rule["title"],
                    "description": f"Static analysis detected {rule['title']} ({rule['rule_id']}) in {file_path}:{line_idx}.",
                    "severity": rule["severity"],
                    "confidence": 0.85,
                    "risk_score": 85 if rule["severity"] == "critical" else 70 if rule["severity"] == "high" else 45,
                    "file_path": file_path,
                    "line_number": line_idx,
                    "rule_id": rule["rule_id"],
                    "cwe": rule["cwe"],
                    "cve": None,
                    "snippet": stripped[:250],
                    "remediation": rule["remediation"],
                })

    return findings
