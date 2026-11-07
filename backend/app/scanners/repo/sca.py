import json
import re
from typing import List, Dict, Any, Tuple

# Known high-profile vulnerability database mapping
KNOWN_ADVISORIES = [
    {
        "ecosystem": "npm",
        "package": "lodash",
        "vulnerable_below": (4, 17, 21),
        "cve": "CVE-2021-23337",
        "severity": "high",
        "title": "Prototype Pollution in Lodash",
        "safe_version": ">= 4.17.21",
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "vulnerable_below": (1, 6, 0),
        "cve": "CVE-2023-45857",
        "severity": "high",
        "title": "Cross-Site Request Forgery (CSRF) in Axios",
        "safe_version": ">= 1.6.0",
    },
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "vulnerable_below": (9, 0, 0),
        "cve": "CVE-2022-23529",
        "severity": "critical",
        "title": "Insecure Key Verification in JsonWebToken",
        "safe_version": ">= 9.0.0",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "vulnerable_below": (4, 19, 2),
        "cve": "CVE-2024-29041",
        "severity": "medium",
        "title": "Open Redirect via malformed URLs in Express",
        "safe_version": ">= 4.19.2",
    },
    {
        "ecosystem": "pypi",
        "package": "requests",
        "vulnerable_below": (2, 31, 0),
        "cve": "CVE-2023-32681",
        "severity": "medium",
        "title": "Proxy-Authorization Header Leak in Requests",
        "safe_version": ">= 2.31.0",
    },
    {
        "ecosystem": "pypi",
        "package": "urllib3",
        "vulnerable_below": (1, 26, 18),
        "cve": "CVE-2023-45803",
        "severity": "high",
        "title": "Cookie and Header Stripping Failure on HTTP 303 in Urllib3",
        "safe_version": ">= 1.26.18",
    },
    {
        "ecosystem": "pypi",
        "package": "cryptography",
        "vulnerable_below": (41, 0, 6),
        "cve": "CVE-2023-49083",
        "severity": "critical",
        "title": "NULL-pointer dereference in PKCS7 parsing in Cryptography",
        "safe_version": ">= 41.0.6",
    },
    {
        "ecosystem": "pypi",
        "package": "paramiko",
        "vulnerable_below": (3, 4, 0),
        "cve": "CVE-2023-48795",
        "severity": "high",
        "title": "Terrapin Attack (Prefix Truncation) in SSH / Paramiko",
        "safe_version": ">= 3.4.0",
    },
]


def parse_semver(ver_str: str) -> Optional[Tuple[int, ...]]:
    """Extract numeric semver tuple e.g. '1.26.17' -> (1, 26, 17)."""
    cleaned = re.sub(r"[^\d.]", "", ver_str.strip())
    parts = cleaned.split(".")
    nums = []
    for p in parts[:3]:
        try:
            nums.append(int(p))
        except ValueError:
            return None
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def scan_file_for_sca(file_path: str, content: str) -> List[Dict[str, Any]]:
    """Scan dependency manifest files (package.json, requirements.txt) for known vulnerabilities."""
    findings: List[Dict[str, Any]] = []
    base_name = file_path.replace("\\", "/").split("/")[-1].lower()

    if base_name == "package.json":
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg_name, ver_spec in deps.items():
                ver = parse_semver(str(ver_spec))
                if not ver:
                    continue
                for adv in KNOWN_ADVISORIES:
                    if adv["ecosystem"] == "npm" and adv["package"].lower() == pkg_name.lower():
                        if ver < adv["vulnerable_below"]:
                            findings.append({
                                "scan_type": "sca",
                                "title": f"Vulnerable Dependency: {pkg_name} ({adv['cve']})",
                                "description": f"{adv['title']}. Installed version {ver_spec} is below safe version {adv['safe_version']}.",
                                "severity": adv["severity"],
                                "confidence": 0.95,
                                "risk_score": 85 if adv["severity"] == "critical" else 70 if adv["severity"] == "high" else 45,
                                "file_path": file_path,
                                "line_number": None,
                                "rule_id": f"SCA-{adv['cve']}",
                                "cwe": "CWE-1395",
                                "cve": adv["cve"],
                                "snippet": f'"{pkg_name}": "{ver_spec}"',
                                "remediation": f"Upgrade {pkg_name} to safe version {adv['safe_version']}.",
                            })
        except Exception:
            pass

    elif "requirements" in base_name and base_name.endswith(".txt"):
        for line_num, line in enumerate(content.splitlines(), start=1):
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            # Match formats like: requests==2.28.0 or urllib3>=1.25,<1.26.17
            parts = re.split(r"[=<>~]", cleaned)
            if parts:
                pkg_name = parts[0].strip().lower()
                version_match = re.search(r"==\s*([0-9.]+)", cleaned)
                if version_match:
                    ver = parse_semver(version_match.group(1))
                    if ver:
                        for adv in KNOWN_ADVISORIES:
                            if adv["ecosystem"] == "pypi" and adv["package"].lower() == pkg_name:
                                if ver < adv["vulnerable_below"]:
                                    findings.append({
                                        "scan_type": "sca",
                                        "title": f"Vulnerable Python Dependency: {pkg_name} ({adv['cve']})",
                                        "description": f"{adv['title']}. Installed version {version_match.group(1)} is below safe version {adv['safe_version']}.",
                                        "severity": adv["severity"],
                                        "confidence": 0.95,
                                        "risk_score": 85 if adv["severity"] == "critical" else 70 if adv["severity"] == "high" else 45,
                                        "file_path": file_path,
                                        "line_number": line_num,
                                        "rule_id": f"SCA-{adv['cve']}",
                                        "cwe": "CWE-1395",
                                        "cve": adv["cve"],
                                        "snippet": cleaned,
                                        "remediation": f"Upgrade {pkg_name} to {adv['safe_version']} in {file_path}.",
                                    })

    return findings
