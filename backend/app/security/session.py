import hashlib
import re
import secrets
from typing import Optional

# 32 bytes of urlsafe base64 entropy produces ~43 characters
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


def generate_session_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure, high-entropy opaque session token.

    Default 32 bytes of entropy yields 256 bits of security.
    """
    return secrets.token_urlsafe(nbytes)


def hash_session_token(token: str) -> str:
    """Compute deterministic SHA-256 hex digest of an opaque session token.

    CRITICAL SECURITY REQUIREMENT:
    Plaintext session tokens are never stored in the database.
    Only this irreversible SHA-256 digest is persisted in `user_sessions.token_hash`.
    """
    if not token or not isinstance(token, str):
        raise ValueError("Session token must be a non-empty string.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_session_token_format(token: Optional[str]) -> bool:
    """Validate that a candidate session token matches expected length and character set.

    Rejects malformed tokens early before performing database lookups.
    """
    if not token or not isinstance(token, str):
        return False
    return bool(_TOKEN_PATTERN.match(token.strip()))
