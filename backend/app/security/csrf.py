import hashlib
import hmac
from typing import Optional, List, Union
from urllib.parse import urlparse


def generate_session_csrf_token(session_token_hash: str, secret_key: str) -> str:
    """Generate a cryptographic session-bound anti-CSRF token.

    Security Architecture:
    - Binds the CSRF token deterministically to the user's active session (`session_token_hash`).
    - Computed using HMAC-SHA256 with the application secret key.
    - Returned in authenticated API response bodies (e.g. GET /api/auth/me, POST /api/auth/login).
    - Held strictly in React memory (AuthContext) by the frontend (never written to localStorage or cookies).
    - Eliminates cross-origin cookie-reading limitations between Vercel and Render.
    """
    if not session_token_hash or not secret_key:
        raise ValueError("session_token_hash and secret_key are required to generate CSRF token.")

    return hmac.new(
        secret_key.encode("utf-8"),
        f"sentriq-csrf:{session_token_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_session_csrf_token(
    header_token: Optional[str],
    session_token_hash: str,
    secret_key: str,
) -> bool:
    """Verify that the X-CSRF-Token custom header matches the session-bound CSRF token in constant time.

    Requirements:
    - Rejects missing, empty, or whitespace-only header tokens.
    - Uses constant-time comparison (hmac.compare_digest) to eliminate timing attacks.
    - Guarantees the CSRF token was minted specifically for this user's active session.
    """
    if not header_token or not isinstance(header_token, str):
        return False
    if not session_token_hash or not secret_key:
        return False

    clean_header = header_token.strip()
    if not clean_header:
        return False

    expected_token = generate_session_csrf_token(session_token_hash, secret_key)
    return hmac.compare_digest(clean_header.encode("utf-8"), expected_token.encode("utf-8"))


def validate_request_origin(
    origin: Optional[str],
    referer: Optional[str],
    allowed_origins: Union[List[str], str],
) -> bool:
    """Validate Origin and Referer headers against explicit allowed CORS origins.

    Defense-in-depth against Cross-Site Request Forgery (CSRF):
    1. If Origin header is present:
       - Must match an allowed origin.
       - If invalid, the request is REJECTED IMMEDIATELY, even if a valid Referer header is present.
    2. If Referer header is present:
       - Its origin component (scheme + netloc) must match an allowed origin.
       - If invalid, the request is REJECTED IMMEDIATELY, even if a valid Origin header is present.
    3. If NEITHER Origin NOR Referer is present:
       - The request is REJECTED (state-changing browser requests must prove their origin).
    4. If BOTH are present:
       - BOTH must match the allowed origins list.
    """
    if isinstance(allowed_origins, str):
        allowed_list = {o.strip().rstrip("/").lower() for o in allowed_origins.split(",") if o.strip()}
    else:
        allowed_list = {o.strip().rstrip("/").lower() for o in allowed_origins if o.strip()}

    has_origin = origin is not None and isinstance(origin, str) and bool(origin.strip())
    has_referer = referer is not None and isinstance(referer, str) and bool(referer.strip())

    # Rule 3: Missing both Origin and Referer must be rejected
    if not has_origin and not has_referer:
        return False

    # Rule 1: If Origin is provided, validate strictly against whitelist
    if has_origin:
        clean_origin = origin.strip().rstrip("/").lower()
        if clean_origin not in allowed_list:
            return False

    # Rule 2: If Referer is provided, validate its origin component strictly
    if has_referer:
        clean_referer = referer.strip()
        parsed = urlparse(clean_referer)
        if not parsed.scheme or not parsed.netloc:
            return False
        referer_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}".rstrip("/")
        if referer_origin not in allowed_list:
            return False

    return True
