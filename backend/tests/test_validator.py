import pytest
from app.scanners.web.validator import validate_target_url, is_private_or_reserved_ip


def test_valid_urls():
    """Verify that legitimate public URLs are accepted and normalized."""
    valid_cases = [
        ("https://example.com", "https://example.com/"),
        ("http://example.com/api", "http://example.com/api"),
        ("example.com/dashboard", "https://example.com/dashboard"),
        ("https://app.example.com:8443/test", "https://app.example.com:8443/test"),
    ]
    for raw, expected in valid_cases:
        is_valid, error, normalized = validate_target_url(raw, allow_internal=False)
        assert is_valid is True, f"Failed for {raw}: {error}"
        assert normalized == expected


def test_prohibited_schemes():
    """Verify that unsafe protocols are strictly blocked."""
    prohibited_cases = [
        "file:///etc/passwd",
        "ftp://ftp.example.com",
        "javascript:alert(1)",
        "data:text/html,test",
        "gopher://gopher.example.com",
    ]
    for url in prohibited_cases:
        is_valid, error, _ = validate_target_url(url, allow_internal=False)
        assert is_valid is False
        assert "prohibited" in error.lower() or "unsupported" in error.lower()


def test_ssrf_private_network_rejection():
    """Verify that private IP ranges, loopback, and cloud metadata are blocked."""
    private_targets = [
        "http://127.0.0.1",
        "http://localhost",
        "http://10.0.0.5",
        "http://192.168.1.100",
        "http://172.16.0.1",
        "http://169.254.169.254",  # AWS/GCP instance metadata service
        "http://[::1]",
    ]
    for target in private_targets:
        is_valid, error, _ = validate_target_url(target, allow_internal=False)
        assert is_valid is False, f"Expected {target} to be blocked by SSRF filter"
        assert "prohibited" in error.lower() or "private" in error.lower() or "ssrf" in error.lower()


def test_private_ip_helper():
    """Direct verification of IP network classification helper."""
    assert is_private_or_reserved_ip("127.0.0.1") is True
    assert is_private_or_reserved_ip("10.10.10.10") is True
    assert is_private_or_reserved_ip("192.168.0.1") is True
    assert is_private_or_reserved_ip("169.254.169.254") is True
    assert is_private_or_reserved_ip("8.8.8.8") is False
    assert is_private_or_reserved_ip("1.1.1.1") is False
