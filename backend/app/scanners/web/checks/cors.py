from typing import List, Dict, Any
from app.scanners.web.client import SafeHttpClient, SafeResponse


async def check_cors_configuration(
    target_url: str, initial_response: SafeResponse, client: SafeHttpClient
) -> List[Dict[str, Any]]:
    """Safely inspect Cross-Origin Resource Sharing (CORS) behavior."""
    findings: List[Dict[str, Any]] = []

    # 1. Inspect initial response headers
    headers = {k.lower(): v for k, v in initial_response.headers.items()}
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")

    if acao:
        acao_clean = acao.strip()
        is_wildcard = acao_clean == "*"
        allows_credentials = acac and acac.lower().strip() == "true"

        if is_wildcard and allows_credentials:
            findings.append({
                "category": "cors",
                "title": "Critical CORS Misconfiguration: Wildcard Origin With Credentials",
                "description": "The server specifies Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. While disallowed by modern browsers, this indicates an insecure cross-origin posture.",
                "severity": "high",
                "confidence": 1.0,
                "cwe": "CWE-942",
                "endpoint": target_url,
                "evidence": f"Access-Control-Allow-Origin: {acao_clean}, Access-Control-Allow-Credentials: {acac}",
                "remediation": "Do not use wildcard origins when credentials (cookies, HTTP authorization) are permitted. Explicitly validate and whitelist allowed client origins.",
            })
        elif is_wildcard:
            findings.append({
                "category": "cors",
                "title": "Permissive CORS Policy (Wildcard Origin)",
                "description": "The server returns Access-Control-Allow-Origin: *, allowing any public website to execute client-side requests and read unauthenticated responses.",
                "severity": "low",
                "confidence": 0.95,
                "cwe": "CWE-942",
                "endpoint": target_url,
                "evidence": f"Access-Control-Allow-Origin: {acao_clean}",
                "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains if this endpoint exposes non-public data.",
            })
        elif acao_clean.lower() == "null":
            findings.append({
                "category": "cors",
                "title": "Insecure CORS Policy Allowing 'null' Origin",
                "description": "The server allows the 'null' origin. Sandboxed iframes, local HTML files, or data URLs can execute cross-origin requests and read responses.",
                "severity": "medium",
                "confidence": 1.0,
                "cwe": "CWE-942",
                "endpoint": target_url,
                "evidence": "Access-Control-Allow-Origin: null",
                "remediation": "Do not whitelist or reflect the 'null' origin in CORS configuration.",
            })

    # 2. Probe with a benign test origin to check for insecure origin reflection
    probe_origin = "https://untrusted-security-probe.example"
    cors_resp = await client.get(
        target_url,
        follow_redirects=False,
        headers={"Origin": probe_origin},
    )

    if cors_resp.status_code and cors_resp.status_code < 500:
        cors_headers = {k.lower(): v for k, v in cors_resp.headers.items()}
        reflected_origin = cors_headers.get("access-control-allow-origin")
        allows_creds = cors_headers.get("access-control-allow-credentials", "").lower() == "true"

        if reflected_origin and reflected_origin.strip() == probe_origin:
            sev = "high" if allows_creds else "medium"
            findings.append({
                "category": "cors",
                "title": "Arbitrary Origin Reflection in CORS Response",
                "description": f"The application reflects arbitrary untrusted Origin headers directly into Access-Control-Allow-Origin{' with credentials enabled' if allows_creds else ''}.",
                "severity": sev,
                "confidence": 0.95,
                "cwe": "CWE-942",
                "endpoint": target_url,
                "evidence": f"Request Origin: '{probe_origin}' -> Access-Control-Allow-Origin: '{reflected_origin}', Credentials: {allows_creds}",
                "remediation": "Validate the Origin header against a strict server-side whitelist before echoing it in Access-Control-Allow-Origin.",
            })

    return findings
