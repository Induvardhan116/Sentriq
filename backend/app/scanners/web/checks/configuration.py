import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from app.scanners.web.client import SafeHttpClient, SafeResponse

# Mixed content patterns for HTTPS web pages
ACTIVE_MIXED_CONTENT = re.compile(
    r'<(?:script|iframe|link[^>]+rel=[\'"]stylesheet[\'"])[^>]+src=[\'"]http://',
    re.IGNORECASE,
)
PASSIVE_MIXED_CONTENT = re.compile(
    r'<(?:img|audio|video|source)[^>]+src=[\'"]http://',
    re.IGNORECASE,
)


async def check_website_configuration(
    target_url: str, main_response: SafeResponse, client: SafeHttpClient
) -> List[Dict[str, Any]]:
    """Perform safe checks for security.txt, robots.txt, and mixed-content indicators."""
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 1. Mixed Content Check (Only relevant if page is delivered over HTTPS)
    if parsed.scheme.lower() == "https" and main_response.text:
        body = main_response.text
        if ACTIVE_MIXED_CONTENT.search(body):
            findings.append({
                "category": "configuration",
                "title": "Mixed Content: Insecure Active Resource Loaded via HTTP",
                "description": "The HTTPS page includes active resources (such as scripts, stylesheets, or iframes) loaded over unencrypted HTTP, allowing man-in-the-middle tampering.",
                "severity": "medium",
                "confidence": 0.9,
                "cwe": "CWE-311",
                "endpoint": target_url,
                "evidence": "Found <script>, <link>, or <iframe> pointing to unencrypted http:// resource in HTML response.",
                "remediation": "Update all asset references to use https:// or relative paths, and enable Upgrade-Insecure-Requests via CSP.",
            })
        elif PASSIVE_MIXED_CONTENT.search(body):
            findings.append({
                "category": "configuration",
                "title": "Mixed Content: Insecure Passive Media Loaded via HTTP",
                "description": "The HTTPS page includes passive media (such as images, audio, or video) loaded over plain HTTP.",
                "severity": "low",
                "confidence": 0.9,
                "cwe": "CWE-311",
                "endpoint": target_url,
                "evidence": "Found <img> or media tag referencing unencrypted http:// asset.",
                "remediation": "Migrate media assets to HTTPS.",
            })

    # 2. security.txt Check (Informational posture check)
    sec_txt_url = urljoin(base_url, "/.well-known/security.txt")
    sec_resp = await client.get(sec_txt_url, follow_redirects=True)
    if sec_resp.status_code != 200:
        # Try fallback /security.txt
        sec_txt_url = urljoin(base_url, "/security.txt")
        sec_resp = await client.get(sec_txt_url, follow_redirects=True)

    if sec_resp.status_code == 200 and "contact:" in sec_resp.text.lower():
        findings.append({
            "category": "configuration",
            "title": "security.txt Policy Published",
            "description": "The target publishes a RFC 9116 security.txt policy defining responsible vulnerability disclosure contacts.",
            "severity": "informational",
            "confidence": 1.0,
            "cwe": "CWE-1059",
            "endpoint": sec_txt_url,
            "evidence": f"HTTP {sec_resp.status_code} at {sec_txt_url}",
            "remediation": "Maintain contact details and signing keys up to date in security.txt.",
        })
    else:
        findings.append({
            "category": "configuration",
            "title": "Missing security.txt Disclosure Policy",
            "description": "No security.txt file was found at /.well-known/security.txt. Having a published security.txt helps ethical security researchers responsibly report potential vulnerabilities.",
            "severity": "informational",
            "confidence": 0.95,
            "cwe": "CWE-1059",
            "endpoint": sec_txt_url,
            "evidence": "Probed /.well-known/security.txt and /security.txt (not found).",
            "remediation": "Create a /.well-known/security.txt file per RFC 9116 with your security contact email and policy.",
        })

    # 3. robots.txt Check (Informational posture check - presence is normal, not a vulnerability)
    robots_url = urljoin(base_url, "/robots.txt")
    robots_resp = await client.get(robots_url, follow_redirects=True)
    if robots_resp.status_code == 200 and "user-agent:" in robots_resp.text.lower():
        findings.append({
            "category": "configuration",
            "title": "robots.txt Detected",
            "description": "The target serves a robots.txt file. Note: robots.txt is standard search engine guidance and is not a vulnerability, but ensure sensitive administrative paths are not cataloged here.",
            "severity": "informational",
            "confidence": 1.0,
            "cwe": "CWE-200",
            "endpoint": robots_url,
            "evidence": f"HTTP {robots_resp.status_code} at {robots_url}",
            "remediation": "Do not rely on robots.txt for access control. Restrict sensitive administrative portals with proper authentication.",
        })

    return findings
