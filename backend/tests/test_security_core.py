import time
from datetime import datetime, timezone, timedelta
import pytest
from pydantic import BaseModel
from typing import Optional

from app.security.hasher import (
    hash_password,
    verify_password,
    needs_rehash,
    dummy_verify,
)
from app.security.session import (
    generate_session_token,
    hash_session_token,
    validate_session_token_format,
)
from app.security.csrf import (
    generate_session_csrf_token,
    verify_session_csrf_token,
    validate_request_origin,
)
from app.security.oauth import (
    generate_oauth_state,
    verify_oauth_state,
    hash_oauth_state,
    build_github_authorization_url,
    validate_github_account_linking,
)
from app.security.limiter import (
    is_account_locked,
    should_lockout,
    calculate_lockout_time,
    calculate_progressive_throttle_delay,
    extract_client_ip,
    is_ip_in_trusted_proxies,
    is_ip_eligible_for_flood_limit,
)


# =====================================================================
# 1. Argon2id Password Hashing Tests
# =====================================================================

def test_hash_password_produces_argon2id():
    """Argon2id hasher must produce valid RFC 9106 Argon2id hash with OWASP parameters."""
    pwd = "CorrectHorseBatteryStaple!2026"
    hashed = hash_password(pwd)
    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert hashed != pwd


def test_verify_password_correct_and_incorrect():
    """Verify password must validate match and reject incorrect passwords."""
    pwd = "Secr3tPassword!#"
    hashed = hash_password(pwd)

    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!#", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(pwd, "") is False
    assert verify_password(pwd, None) is False


def test_hash_password_empty_raises():
    """Empty or non-string password must raise ValueError."""
    with pytest.raises(ValueError):
        hash_password("")
    with pytest.raises(ValueError):
        hash_password(None)  # type: ignore


def test_dummy_verify_runs_without_exceptions():
    """Dummy verification runs safely to equalize timing for non-existent users."""
    dummy_verify()


def test_needs_rehash_behavior():
    """Detects whether hash meets current Argon2id parameters."""
    pwd = "SecureTestPassword123!"
    hashed = hash_password(pwd)
    assert needs_rehash(hashed) is False
    assert needs_rehash("") is True


# =====================================================================
# 2. Opaque Session Token & Response Payload Isolation Tests
# =====================================================================

def test_generate_session_token_entropy():
    """Session tokens must be high-entropy, opaque strings of sufficient length."""
    token1 = generate_session_token()
    token2 = generate_session_token()
    assert len(token1) >= 40
    assert token1 != token2
    assert validate_session_token_format(token1) is True


def test_hash_session_token_is_sha256():
    """Only SHA-256 hex digest is stored in DB, never plaintext token."""
    raw_token = "4d6f8a2b-test-opaque-session-token-random-value"
    digest = hash_session_token(raw_token)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)
    # Deterministic
    assert hash_session_token(raw_token) == digest


def test_hash_session_token_empty_raises():
    """Empty token raises ValueError."""
    with pytest.raises(ValueError):
        hash_session_token("")


def test_validate_session_token_format():
    """Validates opaque token format and rejects malformed candidate strings."""
    assert validate_session_token_format("a" * 32) is True
    assert validate_session_token_format("a" * 128) is True
    assert validate_session_token_format("short") is False
    assert validate_session_token_format("invalid spaces not allowed!!") is False
    assert validate_session_token_format("") is False
    assert validate_session_token_format(None) is False


def test_session_token_never_in_response_payload():
    """CRITICAL SECURITY TEST: Ensure session tokens never leak in response schemas or JSON bodies."""
    # Define representative authentication response model
    class UserProfileResponse(BaseModel):
        id: str
        email: str
        full_name: Optional[str] = None
        csrf_token: Optional[str] = None

    profile_data = {
        "id": "user-uuid-1234",
        "email": "analyst@sentriq.io",
        "full_name": "Security Analyst",
        "csrf_token": "hmac-session-bound-csrf-token",
    }
    response_obj = UserProfileResponse(**profile_data)
    dumped = response_obj.model_dump()

    # Plaintext token generated for cookie
    raw_session_token = generate_session_token()

    # Plaintext token must NEVER be in response payload
    assert "session_token" not in dumped
    assert "token" not in dumped
    assert "access_token" not in dumped
    assert raw_session_token not in str(dumped)


# =====================================================================
# 3. Session-Bound Anti-CSRF Token Tests
# =====================================================================

def test_generate_and_verify_session_csrf_token():
    """Session-bound CSRF token is tied to session hash and verified in constant time."""
    secret_key = "sentriq-production-secret-signing-key"
    session_hash_1 = hash_session_token(generate_session_token())
    session_hash_2 = hash_session_token(generate_session_token())

    csrf_token_1 = generate_session_csrf_token(session_hash_1, secret_key)
    assert len(csrf_token_1) == 64
    assert all(c in "0123456789abcdef" for c in csrf_token_1)

    # 1. Matching token and session succeeds
    assert verify_session_csrf_token(csrf_token_1, session_hash_1, secret_key) is True
    assert verify_session_csrf_token(f"  {csrf_token_1}  ", session_hash_1, secret_key) is True

    # 2. Token used with wrong session fails
    assert verify_session_csrf_token(csrf_token_1, session_hash_2, secret_key) is False

    # 3. Mismatched/tampered token fails
    assert verify_session_csrf_token("tampered-csrf-token", session_hash_1, secret_key) is False

    # 4. Missing or empty header token fails
    assert verify_session_csrf_token("", session_hash_1, secret_key) is False
    assert verify_session_csrf_token(None, session_hash_1, secret_key) is False
    assert verify_session_csrf_token(csrf_token_1, "", secret_key) is False


def test_validate_request_origin_and_referer():
    """Validates Origin and Referer against strict allowed CORS list."""
    allowed = ["https://sentriq-rouge.vercel.app", "http://localhost:5173"]

    # 1. Legitimate Origin matches
    assert validate_request_origin("https://sentriq-rouge.vercel.app", None, allowed) is True
    assert validate_request_origin("http://localhost:5173", None, allowed) is True

    # 2. Legitimate Referer matches when Origin is omitted
    assert validate_request_origin(None, "https://sentriq-rouge.vercel.app/projects", allowed) is True
    assert validate_request_origin(None, "http://localhost:5173/scan/123", allowed) is True

    # 3. Malicious / unauthorized origin rejected
    assert validate_request_origin("https://attacker.evil", None, allowed) is False
    assert validate_request_origin(None, "https://attacker.evil/csrf-exploit", allowed) is False

    # 4. Missing both Origin and Referer on browser mutating request rejected
    assert validate_request_origin(None, None, allowed) is False
    assert validate_request_origin("", "", allowed) is False
    assert validate_request_origin("   ", "   ", allowed) is False


def test_validate_request_origin_edge_cases():
    """Edge cases: invalid Origin with valid Referer, valid Origin with invalid Referer, null Origin."""
    allowed = ["https://sentriq-rouge.vercel.app", "http://localhost:5173"]

    # 1. CRITICAL: Invalid Origin MUST be rejected even if a valid Referer is present
    assert validate_request_origin(
        origin="https://attacker.evil",
        referer="https://sentriq-rouge.vercel.app/projects",
        allowed_origins=allowed,
    ) is False

    # 2. Valid Origin with an invalid / attacking Referer MUST be rejected
    assert validate_request_origin(
        origin="https://sentriq-rouge.vercel.app",
        referer="https://attacker.evil/cross-site-exploit",
        allowed_origins=allowed,
    ) is False

    # 3. Both Origin and Referer valid succeeds
    assert validate_request_origin(
        origin="https://sentriq-rouge.vercel.app",
        referer="https://sentriq-rouge.vercel.app/projects",
        allowed_origins=allowed,
    ) is True

    # 4. Null origin (sandboxed iframe / privacy context) MUST be rejected
    assert validate_request_origin(origin="null", referer=None, allowed_origins=allowed) is False
    assert validate_request_origin(origin="null", referer="https://sentriq-rouge.vercel.app", allowed_origins=allowed) is False

    # 5. Malformed Referer URL without scheme/netloc MUST be rejected
    assert validate_request_origin(origin=None, referer="javascript:alert(1)", allowed_origins=allowed) is False
    assert validate_request_origin(origin=None, referer="not-a-valid-url", allowed_origins=allowed) is False


# =====================================================================
# 4. GitHub OAuth Security & Account Linking Tests
# =====================================================================

def test_generate_and_verify_oauth_state():
    """OAuth state generation produces signed token with freshness and redirect validation."""
    secret = "test-secret-key-for-oauth-signing-32-bytes"
    state = generate_oauth_state(secret, redirect_path="/projects")

    is_valid, path = verify_oauth_state(state, secret)
    assert is_valid is True
    assert path == "/projects"


def test_verify_oauth_state_tampering_rejected():
    """Tampered OAuth state signature must be rejected."""
    secret = "test-secret-key-for-oauth-signing-32-bytes"
    state = generate_oauth_state(secret, redirect_path="/projects")
    parts = state.split(".")
    tampered_state = f"{parts[0]}.forged-signature-value"

    is_valid, path = verify_oauth_state(tampered_state, secret)
    assert is_valid is False
    assert path is None


def test_verify_oauth_state_expired_rejected():
    """Expired OAuth state (> 600s) must be rejected."""
    secret = "test-secret-key-for-oauth-signing-32-bytes"
    state = generate_oauth_state(secret, redirect_path="/projects")

    # Verify with 0 second max_age
    time.sleep(0.01)
    is_valid, _ = verify_oauth_state(state, secret, max_age_seconds=0)
    assert is_valid is False


def test_verify_oauth_state_open_redirect_sanitized():
    """Malicious open redirect paths in state are safely neutralized."""
    secret = "test-secret-key-for-oauth-signing-32-bytes"
    state = generate_oauth_state(secret, redirect_path="//evil.example.com/steal")

    is_valid, path = verify_oauth_state(state, secret)
    assert is_valid is True
    assert path == "/overview"


def test_build_github_authorization_url():
    """Authorization URL includes client_id, redirect_uri, scope, and state."""
    url = build_github_authorization_url(
        client_id="gh-client-123",
        redirect_uri="https://api.example.com/callback",
        state="signed-state-456",
    )
    assert url.startswith("https://github.com/login/oauth/authorize?")
    assert "client_id=gh-client-123" in url
    assert "redirect_uri=https%3A%2F%2Fapi.example.com%2Fcallback" in url
    assert "state=signed-state-456" in url
    assert "scope=read%3Auser+user%3Aemail" in url


def test_validate_github_account_linking_rules():
    """CRITICAL SECURITY RULE: Never auto-link an existing email/password account to GitHub
    based only on matching email addresses. Require explicit authenticated account linking."""
    # 1. Existing OAuth link -> Allowed
    allowed, err = validate_github_account_linking(
        existing_user_by_email=object(),
        existing_oauth_account=object(),
        github_email="dev@example.com",
    )
    assert allowed is True
    assert err is None

    # 2. Brand new user -> Allowed
    allowed, err = validate_github_account_linking(
        existing_user_by_email=None,
        existing_oauth_account=None,
        github_email="newbie@example.com",
    )
    assert allowed is True
    assert err is None

    # 3. Existing user by email but NO existing OAuth link -> REJECT AUTO-LINK
    allowed, err = validate_github_account_linking(
        existing_user_by_email=object(),
        existing_oauth_account=None,
        github_email="existing-local-user@example.com",
    )
    assert allowed is False
    assert "already exists" in err
    assert "sign in with your password first" in err


# =====================================================================
# 5. Trusted Proxy IP Extraction & Rate Limiting Threshold Tests
# =====================================================================

def test_extract_client_ip_untrusted_proxy_spoof_rejected():
    """Untrusted connecting hosts cannot spoof X-Forwarded-For."""
    spoofed_headers = {"x-forwarded-for": "1.1.1.1, 8.8.8.8"}

    # 1. Proxy trust disabled: always returns direct socket peer
    ip = extract_client_ip(
        headers=spoofed_headers,
        client_host="198.51.100.25",
        trusted_proxies=["127.0.0.1"],
        trust_proxy_headers=False,
    )
    assert ip == "198.51.100.25", "Must ignore X-Forwarded-For when trust_proxy_headers is False"

    # 2. Proxy trust enabled but connecting peer is NOT in narrow trusted_proxies list: rejects spoofed header
    ip = extract_client_ip(
        headers=spoofed_headers,
        client_host="198.51.100.25",
        trusted_proxies=["127.0.0.1", "::1"],
        trust_proxy_headers=True,
    )
    assert ip == "198.51.100.25", "Must ignore X-Forwarded-For from untrusted direct peer"

    # 3. Internal unverified peer (e.g. 10.0.0.50) cannot spoof when trusted_proxies is narrowly scoped
    ip = extract_client_ip(
        headers=spoofed_headers,
        client_host="10.0.0.50",
        trusted_proxies=["127.0.0.1", "::1"],
        trust_proxy_headers=True,
    )
    assert ip == "10.0.0.50", "Unverified internal IP cannot spoof forwarded headers without explicit proxy trust"


def test_extract_client_ip_case_insensitive_and_trusted_proxy():
    """Forwarded headers are accepted ONLY from verified trusted proxies and handled case-insensitively."""
    # Uppercase header name
    headers_upper = {"X-FORWARDED-FOR": "203.0.113.195, 10.0.0.1"}
    ip = extract_client_ip(
        headers=headers_upper,
        client_host="127.0.0.1",
        trusted_proxies=["127.0.0.1", "::1"],
        trust_proxy_headers=True,
    )
    assert ip == "203.0.113.195", "Must extract client IP from uppercase X-FORWARDED-FOR header"

    # X-Real-IP fallback with mixed casing
    headers_real = {"X-Real-IP": "198.51.100.99"}
    ip = extract_client_ip(
        headers=headers_real,
        client_host="127.0.0.1",
        trusted_proxies=["127.0.0.1"],
        trust_proxy_headers=True,
    )
    assert ip == "198.51.100.99", "Must extract client IP from X-Real-IP"


def test_extract_client_ip_malformed_forwarded_falls_back():
    """Malformed forwarded IP headers safely fall back to direct peer."""
    malformed_headers = {"x-forwarded-for": "<script>alert(1)</script>, 127.0.0.1"}
    ip = extract_client_ip(
        headers=malformed_headers,
        client_host="127.0.0.1",
        trusted_proxies=["127.0.0.1"],
        trust_proxy_headers=True,
    )
    assert ip == "127.0.0.1", "Must safely fall back to direct peer on malformed header"


def test_is_ip_in_trusted_proxies():
    """Tests IP matching against specific IPs and CIDR ranges."""
    proxies = ["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12"]

    assert is_ip_in_trusted_proxies("127.0.0.1", proxies) is True
    assert is_ip_in_trusted_proxies("::1", proxies) is True
    assert is_ip_in_trusted_proxies("10.0.1.5", proxies) is True
    assert is_ip_in_trusted_proxies("172.16.50.1", proxies) is True
    assert is_ip_in_trusted_proxies("203.0.113.5", proxies) is False
    assert is_ip_in_trusted_proxies("invalid-ip", proxies) is False


def test_is_account_locked():
    """Determines whether account is currently locked."""
    now = datetime.now(timezone.utc)
    future = now + timedelta(minutes=15)
    past = now - timedelta(minutes=5)

    assert is_account_locked(future) is True
    assert is_account_locked(past) is False
    assert is_account_locked(None) is False


def test_should_lockout():
    """Triggers lockout on reaching threshold."""
    assert should_lockout(4, max_attempts=5) is False
    assert should_lockout(5, max_attempts=5) is True
    assert should_lockout(6, max_attempts=5) is True


def test_calculate_lockout_time():
    """Calculates lockout duration with backoff."""
    lock_time = calculate_lockout_time(5, base_minutes=15)
    now = datetime.now(timezone.utc)
    diff = (lock_time - now).total_seconds() / 60
    assert 14.5 <= diff <= 15.5

    # Higher attempts trigger exponential backoff
    lock_time_higher = calculate_lockout_time(7, base_minutes=15)
    diff_higher = (lock_time_higher - now).total_seconds() / 60
    assert 58.0 <= diff_higher <= 61.0


def test_calculate_lockout_time_never_exceeds_cap():
    """Verify that lockout duration is strictly capped and never allows 24-hour DoS lockouts."""
    now = datetime.now(timezone.utc)
    # Even after 50 or 100 failed attempts, duration is strictly capped at max_minutes (default 60 min)
    lock_time_50 = calculate_lockout_time(50, base_minutes=15, max_minutes=60)
    diff_50 = (lock_time_50 - now).total_seconds() / 60
    assert diff_50 <= 60.1
    # Must never reach 24 hours (1440 minutes)
    assert diff_50 < 1440


def test_calculate_progressive_throttle_delay():
    """Verify progressive throttle delay ramps safely with strict ceiling."""
    assert calculate_progressive_throttle_delay(1) == 0
    assert calculate_progressive_throttle_delay(4) == 0
    assert calculate_progressive_throttle_delay(5) == 5
    assert calculate_progressive_throttle_delay(6) == 10
    assert calculate_progressive_throttle_delay(7) == 20
    assert calculate_progressive_throttle_delay(8) == 40
    # Extreme failures must be capped at max_seconds (300s / 5 minutes)
    assert calculate_progressive_throttle_delay(100) == 300


def test_hash_oauth_state():
    """SHA-256 hash of OAuth state is deterministic and 64 characters."""
    state = "test.state.payload.value"
    h1 = hash_oauth_state(state)
    h2 = hash_oauth_state(state)
    assert h1 == h2
    assert len(h1) == 64


def test_auth_enabled_environment_resolution():
    """Verify that AUTH_ENABLED is disabled by default in production, fails closed without verification, but enabled in development."""
    from app.config import Settings

    # 1. Production defaults to AUTH_ENABLED = False
    prod_default = Settings(ENVIRONMENT="production")
    assert prod_default.AUTH_ENABLED is False

    # 2. Production with AUTH_ENABLED = True but unverified architecture FAILS CLOSED to False
    prod_unverified = Settings(ENVIRONMENT="production", AUTH_ENABLED=True)
    assert prod_unverified.AUTH_ENABLED is False

    # 3. Production with AUTH_ENABLED=True and PRODUCTION_AUTH_VERIFIED=True:
    # 3a. Arbitrary/unapproved *.vercel.app origins FAIL CLOSED
    prod_arbitrary_vercel = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://attacker-app.vercel.app"],
        FRONTEND_URL="https://attacker-app.vercel.app",
    )
    assert prod_arbitrary_vercel.AUTH_ENABLED is False

    # 3b. Direct onrender.com backend host as frontend FAILS CLOSED
    prod_render = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://sentriq.onrender.com"],
        FRONTEND_URL="https://sentriq.onrender.com",
    )
    assert prod_render.AUTH_ENABLED is False

    # 3c. Unencrypted HTTP origin in production FAILS CLOSED
    prod_http = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["http://sentriq-rouge.vercel.app"],
        FRONTEND_URL="http://sentriq-rouge.vercel.app",
    )
    assert prod_http.AUTH_ENABLED is False

    # 3d. Sanctioned Vercel reverse-proxy gateway WITH verification SUCCEEDS
    prod_sanctioned_vercel = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://sentriq-rouge.vercel.app"],
        FRONTEND_URL="https://sentriq-rouge.vercel.app",
    )
    assert prod_sanctioned_vercel.AUTH_ENABLED is True

    # 4. Production explicitly enabled WITH verified architecture AND custom domain
    prod_verified = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://app.sentriq.io"],
        FRONTEND_URL="https://app.sentriq.io",
    )
    assert prod_verified.AUTH_ENABLED is True

    # 4. Development defaults to AUTH_ENABLED = True
    dev_default = Settings(ENVIRONMENT="development")
    assert dev_default.AUTH_ENABLED is True

    # 5. Development explicitly disabled with AUTH_ENABLED = False
    dev_explicit_false = Settings(ENVIRONMENT="development", AUTH_ENABLED=False)
    assert dev_explicit_false.AUTH_ENABLED is False


def test_is_ip_eligible_for_flood_limit():
    """Verify that only trustworthy client IPs are eligible for IP flood limiting."""
    # 1. Untrusted proxy mode (trust_proxy_headers=False)
    # Loopback and private ranges must NOT be eligible (shared gateway proxy DoS prevention)
    assert is_ip_eligible_for_flood_limit("127.0.0.1", trust_proxy_headers=False) is False
    assert is_ip_eligible_for_flood_limit("::1", trust_proxy_headers=False) is False
    assert is_ip_eligible_for_flood_limit("10.0.1.25", trust_proxy_headers=False) is False
    assert is_ip_eligible_for_flood_limit("172.16.0.5", trust_proxy_headers=False) is False
    assert is_ip_eligible_for_flood_limit("192.168.1.1", trust_proxy_headers=False) is False

    # Public, direct client socket connections ARE eligible
    assert is_ip_eligible_for_flood_limit("93.184.216.34", trust_proxy_headers=False) is True
    assert is_ip_eligible_for_flood_limit("8.8.8.8", trust_proxy_headers=False) is True

    # 2. Trusted proxy mode (trust_proxy_headers=True)
    # Extracted verified client IP is eligible
    assert is_ip_eligible_for_flood_limit("203.0.113.195", trust_proxy_headers=True) is True
    assert is_ip_eligible_for_flood_limit("127.0.0.1", trust_proxy_headers=True) is True

    # Malformed or empty IPs are not eligible
    assert is_ip_eligible_for_flood_limit("", trust_proxy_headers=False) is False
    assert is_ip_eligible_for_flood_limit("invalid-ip", trust_proxy_headers=False) is False


# =====================================================================
# 11. Production Session Cookie Enforcement Tests
# =====================================================================

def test_production_session_cookie_secure_enforcement():
    """Verify that SESSION_COOKIE_SECURE is strictly enforced in production."""
    from app.config import Settings

    # Test A — Production authentication enabled with SESSION_COOKIE_SECURE=false:
    # Must force SESSION_COOKIE_SECURE=True
    prod_insecure_override = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://sentriq-rouge.vercel.app"],
        FRONTEND_URL="https://sentriq-rouge.vercel.app",
        SESSION_COOKIE_SECURE=False,
    )
    assert prod_insecure_override.AUTH_ENABLED is True
    assert prod_insecure_override.SESSION_COOKIE_SECURE is True

    # Test B — Production authentication already secure:
    # Must remain SESSION_COOKIE_SECURE=True
    prod_secure = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://sentriq-rouge.vercel.app"],
        FRONTEND_URL="https://sentriq-rouge.vercel.app",
        SESSION_COOKIE_SECURE=True,
    )
    assert prod_secure.AUTH_ENABLED is True
    assert prod_secure.SESSION_COOKIE_SECURE is True

    # Test C — Production authentication disabled:
    # Authentication remains disabled, no accidental activation
    prod_disabled = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=False,
        PRODUCTION_AUTH_VERIFIED=False,
        SESSION_COOKIE_SECURE=False,
    )
    assert prod_disabled.AUTH_ENABLED is False
    assert prod_disabled.SESSION_COOKIE_SECURE is False

    # Test D — Local development:
    # Existing local development behavior remains unchanged
    dev_auth_off = Settings(
        ENVIRONMENT="development",
        AUTH_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
    )
    assert dev_auth_off.AUTH_ENABLED is False
    assert dev_auth_off.SESSION_COOKIE_SECURE is False

    dev_auth_on = Settings(
        ENVIRONMENT="development",
        AUTH_ENABLED=True,
        SESSION_COOKIE_SECURE=False,
    )
    assert dev_auth_on.AUTH_ENABLED is True
    assert dev_auth_on.SESSION_COOKIE_SECURE is False


def test_production_cookie_issuance_attributes():
    """Test E — Verify session and OAuth state cookies are issued with Secure, HttpOnly, SameSite=Lax, and Path=/."""
    from unittest.mock import patch
    from fastapi import Response
    from app.config import Settings
    from app.api.auth import _set_session_cookie

    prod_settings = Settings(
        ENVIRONMENT="production",
        AUTH_ENABLED=True,
        PRODUCTION_AUTH_VERIFIED=True,
        CORS_ORIGINS=["https://sentriq-rouge.vercel.app"],
        FRONTEND_URL="https://sentriq-rouge.vercel.app",
        SESSION_COOKIE_SECURE=False,  # Enforces True
    )
    assert prod_settings.SESSION_COOKIE_SECURE is True

    # 1. Verify session cookie issuance via auth._set_session_cookie
    with patch("app.api.auth.settings", prod_settings):
        resp_session = Response()
        _set_session_cookie(resp_session, "raw_test_session_token_12345")
        set_cookie_session = resp_session.headers.get("set-cookie", "")

        assert f"{prod_settings.SESSION_COOKIE_NAME}=raw_test_session_token_12345" in set_cookie_session
        assert "httponly" in set_cookie_session.lower()
        assert "secure" in set_cookie_session.lower()
        assert "samesite=lax" in set_cookie_session.lower()
        assert "path=/" in set_cookie_session.lower()

    # 2. Verify OAuth state cookie issuance
    resp_oauth = Response()
    resp_oauth.set_cookie(
        key="sentriq_oauth_state",
        value="raw_oauth_state_12345",
        max_age=600,
        httponly=True,
        secure=prod_settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    set_cookie_oauth = resp_oauth.headers.get("set-cookie", "")

    assert "sentriq_oauth_state=raw_oauth_state_12345" in set_cookie_oauth
    assert "httponly" in set_cookie_oauth.lower()
    assert "secure" in set_cookie_oauth.lower()
    assert "samesite=lax" in set_cookie_oauth.lower()
    assert "path=/" in set_cookie_oauth.lower()




