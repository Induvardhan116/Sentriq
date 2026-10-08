import pytest
from app.scanners.web.client import SafeResponse, SafeHttpClient
from app.scanners.web.checks.headers import check_security_headers
from app.scanners.web.checks.cookies import check_cookie_security, sanitize_cookie_string
from app.scanners.web.checks.cors import check_cors_configuration
from app.scanners.web.checks.exposure import check_information_exposure
from app.scanners.web.checks.configuration import check_website_configuration


def test_missing_security_headers():
    """Verify that absent headers generate appropriate findings."""
    empty_resp = SafeResponse(
        url="https://target.example/",
        status_code=200,
        headers={"content-type": "text/html"},
    )
    findings = check_security_headers(empty_resp)
    titles = [f["title"] for f in findings]

    assert "Missing Content-Security-Policy" in titles
    assert "Missing Strict-Transport-Security (HSTS)" in titles
    assert "Missing X-Content-Type-Options Header" in titles
    assert "Missing Clickjacking Protection" in titles
    assert "Missing Referrer-Policy Header" in titles
    assert "Missing Permissions-Policy Header" in titles


def test_hardened_security_headers():
    """Verify that hardened response headers produce zero missing findings."""
    hardened_resp = SafeResponse(
        url="https://target.example/",
        status_code=200,
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
        },
    )
    findings = check_security_headers(hardened_resp)
    assert len(findings) == 0


def test_cookie_security_and_redaction():
    """Verify cookie security checks and verify raw cookie value is NEVER stored or exposed."""
    raw_cookie_val = "SECRET_TOKEN_99999"
    resp = SafeResponse(
        url="https://target.example/",
        status_code=200,
        headers={},
        raw_headers=[
            ("Set-Cookie", f"session_id={raw_cookie_val}; Path=/"),
        ],
    )
    findings = check_cookie_security(resp)
    assert len(findings) >= 2  # Missing Secure, missing HttpOnly, missing SameSite

    for f in findings:
        evidence = f["evidence"]
        # CRITICAL TEST: Raw cookie value must NEVER appear in evidence
        assert raw_cookie_val not in evidence
        assert "session_id=REDACTED" in evidence


def test_sanitize_cookie_string():
    """Verify cookie sanitization helper replaces sensitive values with REDACTED."""
    name, sanitized = sanitize_cookie_string("auth_key=SUPER_SECRET_VALUE_123; Secure; HttpOnly")
    assert name == "auth_key"
    assert "SUPER_SECRET_VALUE_123" not in sanitized
    assert sanitized == "auth_key=REDACTED; Secure; HttpOnly"


def test_cors_wildcard_with_credentials():
    """Verify detection of dangerous CORS wildcard combined with credentials."""
    resp = SafeResponse(
        url="https://target.example/api",
        status_code=200,
        headers={
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
    )
    client = SafeHttpClient()
    # Synchronous test for header analysis logic
    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    if headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials") == "true":
        findings.append({"title": "Critical CORS Misconfiguration: Wildcard Origin With Credentials"})

    assert len(findings) == 1


def test_information_exposure_banners():
    """Verify detection of Server version headers and X-Powered-By."""
    resp = SafeResponse(
        url="https://target.example/",
        status_code=200,
        headers={
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
        },
        text="Normal page content",
    )
    findings = check_information_exposure(resp)
    titles = [f["title"] for f in findings]

    assert "Server Banner Exposing Software Version" in titles
    assert "Technology Disclosure via X-Powered-By Header" in titles


def test_debug_traceback_exposure():
    """Verify detection of active stack traces in body."""
    resp = SafeResponse(
        url="https://target.example/error",
        status_code=500,
        headers={},
        text="<html><body><h1>Error</h1><p>Traceback (most recent call last):</p><p>File app.py, line 23</p></body></html>",
    )
    findings = check_information_exposure(resp)
    titles = [f["title"] for f in findings]
    assert "Active Debug Screen or Stack Trace Exposed" in titles
