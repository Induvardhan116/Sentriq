import re
from typing import List, Dict, Any
from app.scanners.web.client import SafeResponse

# Patterns identifying detailed software versions
VERSION_PATTERN = re.compile(r"\b\d+\.\d+(\.\d+)?\b")

# Common debug and stack trace indicators in error bodies
DEBUG_INDICATORS = [
    ("Traceback (most recent call last):", "Python/Django traceback detected"),
    ("Fatal error: Uncaught", "PHP fatal error traceback detected"),
    ("Microsoft.AspNetCore.Diagnostics.DeveloperExceptionPage", "ASP.NET developer exception page detected"),
    ("org.springframework.web.util.NestedServletException", "Spring framework stack trace detected"),
    ("Whoops! There was an error.", "Laravel debug screen detected"),
    ("Django Version:", "Django debug error page detected"),
    ("at Module._compile (internal/modules/cjs/loader.js", "Node.js stack trace detected"),
]


def check_information_exposure(response: SafeResponse) -> List[Dict[str, Any]]:
    """Detect unnecessary technical disclosures in response headers and response body."""
    findings: List[Dict[str, Any]] = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    url = response.url
    body = response.text

    # 1. Server Header Disclosure
    server = headers.get("server")
    if server:
        clean_server = server.strip()
        has_version = bool(VERSION_PATTERN.search(clean_server))
        if has_version:
            findings.append({
                "category": "information_exposure",
                "title": "Server Banner Exposing Software Version",
                "description": f"The 'Server' header reveals exact underlying web server software and version numbers ('{clean_server}'), making it easier for adversaries to identify known CVEs.",
                "severity": "low",
                "confidence": 0.95,
                "cwe": "CWE-200",
                "endpoint": url,
                "evidence": f"Server: {clean_server}",
                "remediation": "Configure the web server to suppress or tokenize the Server banner (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx).",
            })
        else:
            findings.append({
                "category": "information_exposure",
                "title": "Server Software Header Disclosed",
                "description": f"The 'Server' header discloses the server technology ('{clean_server}').",
                "severity": "informational",
                "confidence": 0.9,
                "cwe": "CWE-200",
                "endpoint": url,
                "evidence": f"Server: {clean_server}",
                "remediation": "Suppress the Server header to minimize reconnaissance footprint.",
            })

    # 2. X-Powered-By Header Disclosure
    x_powered_by = headers.get("x-powered-by")
    if x_powered_by:
        findings.append({
            "category": "information_exposure",
            "title": "Technology Disclosure via X-Powered-By Header",
            "description": f"The 'X-Powered-By' header discloses backend runtime technology ('{x_powered_by.strip()}'), assisting targeted automated fingerprinting.",
            "severity": "low",
            "confidence": 1.0,
            "cwe": "CWE-200",
            "endpoint": url,
            "evidence": f"X-Powered-By: {x_powered_by.strip()}",
            "remediation": "Disable the X-Powered-By header in application or framework configuration (e.g. app.disable('x-powered-by') in Express).",
        })

    # 3. Debug Error / Stack Trace Indicators in Body
    for pattern, desc in DEBUG_INDICATORS:
        if pattern in body:
            findings.append({
                "category": "information_exposure",
                "title": "Active Debug Screen or Stack Trace Exposed",
                "description": f"The application response body appears to contain an active framework debug error page or stack trace ({desc}). This can disclose source code paths, database details, or credentials.",
                "severity": "high",
                "confidence": 0.9,
                "cwe": "CWE-209",
                "endpoint": url,
                "evidence": f"Matched pattern '{pattern}' in response body snippet.",
                "remediation": "Disable debug mode in production (e.g. DEBUG=False) and display generic custom error pages.",
            })
            break

    # 4. JavaScript Source Map Directives
    if ".js.map" in body or "//# sourceMappingURL=" in body:
        findings.append({
            "category": "information_exposure",
            "title": "Production JavaScript Source Maps Referenced",
            "description": "Source map directives were found in the page body. Publicly deployed source maps allow anyone to reconstruct original unminified application source code.",
            "severity": "low",
            "confidence": 0.85,
            "cwe": "CWE-540",
            "endpoint": url,
            "evidence": "Found reference to .js.map or sourceMappingURL in response body.",
            "remediation": "Remove production source map files and disable sourceMappingURL comments in production build pipelines.",
        })

    return findings
