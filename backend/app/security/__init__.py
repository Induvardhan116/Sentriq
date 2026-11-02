"""Sentriq Security Core package.

Provides cryptographic password hashing, opaque session token generation,
SHA-256 token hashing, anti-CSRF validation, persistent rate-limiting foundation,
and GitHub OAuth 2.0 flow utilities.
"""

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
    save_oauth_state,
    consume_oauth_state,
    build_github_authorization_url,
    validate_github_account_linking,
)
from app.security.limiter import (
    is_account_locked,
    calculate_lockout_time,
    calculate_progressive_throttle_delay,
    should_lockout,
    extract_client_ip,
    is_ip_in_trusted_proxies,
    is_ip_eligible_for_flood_limit,
)

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
    "dummy_verify",
    "generate_session_token",
    "hash_session_token",
    "validate_session_token_format",
    "generate_session_csrf_token",
    "verify_session_csrf_token",
    "validate_request_origin",
    "generate_oauth_state",
    "verify_oauth_state",
    "hash_oauth_state",
    "save_oauth_state",
    "consume_oauth_state",
    "build_github_authorization_url",
    "validate_github_account_linking",
    "is_account_locked",
    "calculate_lockout_time",
    "calculate_progressive_throttle_delay",
    "should_lockout",
    "extract_client_ip",
    "is_ip_in_trusted_proxies",
    "is_ip_eligible_for_flood_limit",
]
