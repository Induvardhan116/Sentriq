from typing import List, Dict, Any
from app.scanners.web.client import SafeResponse


def check_security_headers(response: SafeResponse) -> List[Dict[str, Any]]:
    """Inspect HTTP response headers and generate normalized security findings."""
    findings: List[Dict[str, Any]] = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    url = response.url

    # 1. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append({
            "category": "security_headers",
            "title": "Missing Content-Security-Policy",
            "description": "Content-Security-Policy (CSP) helps prevent Cross-Site Scripting (XSS), data injection, and malicious frame execution by declaring approved resource origins.",
            "severity": "medium",
            "confidence": 1.0,
            "cwe": "CWE-693",
            "endpoint": url,
            "evidence": "Header 'Content-Security-Policy' was not present in HTTP response.",
            "remediation": "Define a Content-Security-Policy header restricting script, style, and media sources (e.g. default-src 'self').",
        })
    else:
        # Check for overly permissive directives
        lower_csp = csp.lower()
        if "'unsafe-inline'" in lower_csp or "'unsafe-eval'" in lower_csp:
            findings.append({
                "category": "security_headers",
                "title": "Permissive Content-Security-Policy Directives",
                "description": "The Content-Security-Policy includes 'unsafe-inline' or 'unsafe-eval', which weakens protection against Cross-Site Scripting (XSS).",
                "severity": "low",
                "confidence": 0.9,
                "cwe": "CWE-693",
                "endpoint": url,
                "evidence": f"CSP directive: {csp[:120]}...",
                "remediation": "Replace 'unsafe-inline' and 'unsafe-eval' with cryptographic nonces or hashes.",
            })

    # 2. Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if url.lower().startswith("https://"):
        if not hsts:
            findings.append({
                "category": "security_headers",
                "title": "Missing Strict-Transport-Security (HSTS)",
                "description": "HTTP Strict Transport Security informs browsers that the site must only be accessed over HTTPS, preventing SSL stripping and protocol downgrade attacks.",
                "severity": "low",
                "confidence": 1.0,
                "cwe": "CWE-319",
                "endpoint": url,
                "evidence": "Header 'Strict-Transport-Security' was not present in HTTPS response.",
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            })
        else:
            lower_hsts = hsts.lower()
            if "max-age" in lower_hsts:
                try:
                    for part in lower_hsts.split(";"):
                        if "max-age=" in part:
                            val = int(part.split("=")[1].strip())
                            if val < 10368000:  # Less than 120 days
                                findings.append({
                                    "category": "security_headers",
                                    "title": "Short HSTS Max-Age Duration",
                                    "description": f"The HSTS max-age is set to {val} seconds, which is less than the recommended 1 year (31,536,000s) for robust transport protection.",
                                    "severity": "low",
                                    "confidence": 0.85,
                                    "cwe": "CWE-319",
                                    "endpoint": url,
                                    "evidence": f"Strict-Transport-Security: {hsts}",
                                    "remediation": "Increase HSTS max-age to at least 31536000 seconds (1 year).",
                                })
                except Exception:
                    pass

    # 3. X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if not xcto or xcto.lower().strip() != "nosniff":
        findings.append({
            "category": "security_headers",
            "title": "Missing X-Content-Type-Options Header",
            "description": "X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing responses away from the declared content-type, defending against drive-by downloads and content spoofing.",
            "severity": "low",
            "confidence": 1.0,
            "cwe": "CWE-16",
            "endpoint": url,
            "evidence": f"Header value: '{xcto or 'Not Set'}'",
            "remediation": "Set 'X-Content-Type-Options: nosniff' on all HTTP responses.",
        })

    # 4. Clickjacking Protection: X-Frame-Options or CSP frame-ancestors
    xfo = headers.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append({
            "category": "security_headers",
            "title": "Missing Clickjacking Protection",
            "description": "Neither X-Frame-Options nor Content-Security-Policy frame-ancestors is present. Attackers may embed this page inside an invisible iframe to perform clickjacking attacks.",
            "severity": "medium",
            "confidence": 0.95,
            "cwe": "CWE-1021",
            "endpoint": url,
            "evidence": "Neither 'X-Frame-Options' nor 'frame-ancestors' directive was configured.",
            "remediation": "Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or configure 'frame-ancestors' in CSP.",
        })

    # 5. Referrer-Policy
    referrer_policy = headers.get("referrer-policy")
    if not referrer_policy:
        findings.append({
            "category": "security_headers",
            "title": "Missing Referrer-Policy Header",
            "description": "Without a Referrer-Policy, the browser may send full URLs (including sensitive query parameters or session IDs) in the Referer header to external origins.",
            "severity": "low",
            "confidence": 1.0,
            "cwe": "CWE-200",
            "endpoint": url,
            "evidence": "Header 'Referrer-Policy' was not present.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        })
    elif referrer_policy.lower().strip() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append({
            "category": "security_headers",
            "title": "Insecure Referrer-Policy Configuration",
            "description": f"The configured Referrer-Policy '{referrer_policy}' can leak sensitive request path and parameter data across third-party domains.",
            "severity": "low",
            "confidence": 0.9,
            "cwe": "CWE-200",
            "endpoint": url,
            "evidence": f"Referrer-Policy: {referrer_policy}",
            "remediation": "Switch to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        })

    # 6. Permissions-Policy
    permissions_policy = headers.get("permissions-policy")
    if not permissions_policy:
        findings.append({
            "category": "security_headers",
            "title": "Missing Permissions-Policy Header",
            "description": "Permissions-Policy allows site owners to explicitly restrict browser features and APIs (e.g., geolocation, camera, microphone) that third-party scripts can invoke.",
            "severity": "informational",
            "confidence": 1.0,
            "cwe": "CWE-693",
            "endpoint": url,
            "evidence": "Header 'Permissions-Policy' was not present.",
            "remediation": "Define a Permissions-Policy header (e.g. camera=(), microphone=(), geolocation=()).",
        })

    return findings
