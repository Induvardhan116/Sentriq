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


def test_embedded_credentials_rejection():
    """Verify that URLs containing embedded user credentials are strictly rejected."""
    credential_cases = [
        "https://admin:secret123@example.com",
        "http://user@example.com/api",
        "https://guest:password@104.21.5.10/",
    ]
    for url in credential_cases:
        is_valid, error, _ = validate_target_url(url, allow_internal=False)
        assert is_valid is False, f"Expected {url} to be rejected due to embedded credentials"
        assert "credentials" in error.lower()


def test_private_ip_helper():
    """Direct verification of IP network classification helper across standard and alternative encodings."""
    assert is_private_or_reserved_ip("127.0.0.1") is True
    assert is_private_or_reserved_ip("10.10.10.10") is True
    assert is_private_or_reserved_ip("192.168.0.1") is True
    assert is_private_or_reserved_ip("169.254.169.254") is True
    # Alternate integer, octal, and hex notations
    assert is_private_or_reserved_ip("2130706433") is True  # 127.0.0.1 in decimal integer
    assert is_private_or_reserved_ip("0x7f000001") is True  # 127.0.0.1 in hex
    assert is_private_or_reserved_ip("0x7f.1") is True  # 127.0.0.1 in 2-part dotted hex
    assert is_private_or_reserved_ip("0x7f.0.0.1") is True  # 127.0.0.1 in dotted hex
    assert is_private_or_reserved_ip("0177.0.0.1") is True  # 127.0.0.1 in dotted octal
    assert is_private_or_reserved_ip("017700000001") is True  # 127.0.0.1 in single octal
    assert is_private_or_reserved_ip("0377.0377.0377.0377") is True  # 255.255.255.255 broadcast in octal
    assert is_private_or_reserved_ip("012.0.0.1") is True  # 10.0.0.1 in octal
    # IPv6 and mapped addresses
    assert is_private_or_reserved_ip("::1") is True
    assert is_private_or_reserved_ip("::ffff:127.0.0.1") is True
    assert is_private_or_reserved_ip("::ffff:100.64.0.1") is True  # CGNAT mapped
    assert is_private_or_reserved_ip("::127.0.0.1") is True  # IPv4 compatible
    # Public addresses
    assert is_private_or_reserved_ip("8.8.8.8") is False
    assert is_private_or_reserved_ip("1.1.1.1") is False


def test_malformed_and_unclassifiable_destinations_fail_closed():
    """Verify that malformed, ambiguous, and unclassifiable destinations fail closed."""
    malformed_cases = [
        "http://999.999.999.999",
        "http://256.0.0.1",
        "http://0x7f00000100",  # 32-bit overflow
        "http://invalid..domain",
        "http://-invalid-domain.com",
        "http://[::gggg]",  # invalid IPv6 hex
    ]
    for url in malformed_cases:
        is_valid, error, _ = validate_target_url(url, allow_internal=False)
        assert is_valid is False, f"Expected {url} to fail closed"
        assert error is not None


@pytest.mark.asyncio
async def test_redirect_ssrf_mitigation():
    """Verify that SafeHttpClient refuses to follow redirects pointing to private/metadata IP destinations.
    Asserts exact number of requests dispatched (exactly 1 request before blocking).
    """
    from unittest.mock import AsyncMock, patch, MagicMock
    from app.scanners.web.client import SafeHttpClient

    client = SafeHttpClient(allow_internal=False)

    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.status_code = 302
    redirect_resp.url = "https://public-site.example/login"
    redirect_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    mock_httpx = AsyncMock()
    mock_httpx.get.return_value = redirect_resp

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value = mock_httpx
        resp = await client.get("https://public-site.example/login", follow_redirects=True)

        assert resp.error is not None
        assert "ssrf" in resp.error.lower()
        # Assert exact request count: only the initial request occurred
        assert mock_httpx.get.call_count == 1
        # Ensure httpx never requested the internal metadata URL
        for call in mock_httpx.get.call_args_list:
            assert "169.254.169.254" not in str(call)


@pytest.mark.asyncio
async def test_chained_redirect_ssrf_mitigation():
    """Verify that SafeHttpClient safely follows legitimate redirects but halts immediately
    and dispatches zero requests to a subsequent private/SSRF destination in a chain.
    """
    from unittest.mock import AsyncMock, patch, MagicMock
    from httpx import URL
    from app.scanners.web.client import SafeHttpClient

    client = SafeHttpClient(allow_internal=False)

    # Step 1: public-site -> 302 to public-cdn
    resp1 = MagicMock()
    resp1.is_redirect = True
    resp1.status_code = 302
    resp1.url = URL("https://public-site.example/start")
    resp1.headers = {"Location": "https://public-cdn.example/next"}

    # Step 2: public-cdn -> 302 to internal metadata (blocked)
    resp2 = MagicMock()
    resp2.is_redirect = True
    resp2.status_code = 302
    resp2.url = URL("https://public-cdn.example/next")
    resp2.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    mock_httpx = AsyncMock()
    mock_httpx.get.side_effect = [resp1, resp2]

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value = mock_httpx
        resp = await client.get("https://public-site.example/start", follow_redirects=True)

        assert resp.error is not None
        assert "ssrf" in resp.error.lower()
        # Exactly 2 requests dispatched (public-site and public-cdn)
        assert mock_httpx.get.call_count == 2
        # Zero requests dispatched to the private target
        for call in mock_httpx.get.call_args_list:
            assert "169.254.169.254" not in str(call)
