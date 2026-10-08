import re
from typing import List, Dict, Any, Tuple
from app.scanners.web.client import SafeResponse

# Common sensitive cookie patterns (session, auth tokens, csrf, etc.)
SENSITIVE_COOKIE_REGEX = re.compile(
    r"(sess|token|auth|id|jwt|sid|login|remember|credential)", re.IGNORECASE
)


def sanitize_cookie_string(cookie_header_value: str) -> Tuple[str, str]:
    """Parse cookie name and return a redacted representation for safe evidence logging.

    Example:
        'session_id=1a2b3c4d5e; Path=/; HttpOnly' ->
        ('session_id', 'session_id=REDACTED; Path=/; HttpOnly')
    """
    parts = cookie_header_value.split(";")
    name_value = parts[0].strip()
    attributes = [p.strip() for p in parts[1:]]

    cookie_name = name_value.split("=")[0].strip() if "=" in name_value else name_value

    # Reconstruct sanitized string without raw value
    sanitized_parts = [f"{cookie_name}=REDACTED"] + attributes
    return cookie_name, "; ".join(sanitized_parts)


def check_cookie_security(response: SafeResponse) -> List[Dict[str, Any]]:
    """Inspect Set-Cookie headers for Secure, HttpOnly, and SameSite attributes.

    CRITICAL PRIVACY RULE: Raw cookie values are never stored or exposed.
    """
    findings: List[Dict[str, Any]] = []
    url = response.url
    is_https = url.lower().startswith("https://")

    # Extract all Set-Cookie headers from raw headers
    cookie_headers = [
        val for name, val in response.raw_headers if name.lower() == "set-cookie"
    ]

    for raw_cookie in cookie_headers:
        cookie_name, sanitized_evidence = sanitize_cookie_string(raw_cookie)
        attributes_lower = [part.strip().lower() for part in raw_cookie.split(";")[1:]]

        is_secure = any(attr == "secure" for attr in attributes_lower)
        is_httponly = any(attr == "httponly" for attr in attributes_lower)
        samesite_attr = next(
            (attr for attr in attributes_lower if attr.startswith("samesite")), None
        )

        is_sensitive = bool(SENSITIVE_COOKIE_REGEX.search(cookie_name))

        # 1. Missing Secure Flag (Crucial on HTTPS)
        if not is_secure and is_https:
            severity = "medium" if is_sensitive else "low"
            findings.append({
                "category": "cookie_security",
                "title": f"Cookie '{cookie_name}' Missing Secure Flag",
                "description": f"The cookie '{cookie_name}' does not have the 'Secure' attribute. Browsers may transmit it in cleartext over unencrypted HTTP connections.",
                "severity": severity,
                "confidence": 1.0,
                "cwe": "CWE-614",
                "endpoint": url,
                "evidence": sanitized_evidence,
                "remediation": f"Add the '; Secure' directive when issuing the '{cookie_name}' Set-Cookie header.",
            })

        # 2. Missing HttpOnly Flag
        if not is_httponly:
            severity = "medium" if is_sensitive else "low"
            findings.append({
                "category": "cookie_security",
                "title": f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                "description": f"The cookie '{cookie_name}' does not have the 'HttpOnly' flag, allowing client-side scripts to access it via document.cookie. This increases exposure to Cross-Site Scripting (XSS) credential theft.",
                "severity": severity,
                "confidence": 1.0,
                "cwe": "CWE-1004",
                "endpoint": url,
                "evidence": sanitized_evidence,
                "remediation": f"Set '; HttpOnly' on the '{cookie_name}' cookie to block JavaScript access.",
            })

        # 3. Missing or Insecure SameSite Flag
        if not samesite_attr:
            findings.append({
                "category": "cookie_security",
                "title": f"Cookie '{cookie_name}' Missing SameSite Attribute",
                "description": f"The cookie '{cookie_name}' lacks a SameSite attribute, which leaves it vulnerable to cross-site request forgery (CSRF) in older browsers or non-default contexts.",
                "severity": "low",
                "confidence": 1.0,
                "cwe": "CWE-1275",
                "endpoint": url,
                "evidence": sanitized_evidence,
                "remediation": f"Configure '; SameSite=Lax' (or 'SameSite=Strict') on the '{cookie_name}' cookie.",
            })
        elif "samesite=none" in samesite_attr and not is_secure:
            findings.append({
                "category": "cookie_security",
                "title": f"Cookie '{cookie_name}' SameSite=None Without Secure",
                "description": f"The cookie '{cookie_name}' is set with 'SameSite=None' but lacks the mandatory 'Secure' attribute, causing modern browsers to reject it.",
                "severity": "medium",
                "confidence": 1.0,
                "cwe": "CWE-1275",
                "endpoint": url,
                "evidence": sanitized_evidence,
                "remediation": f"Include '; Secure' whenever setting 'SameSite=None' on '{cookie_name}'.",
            })

    return findings
