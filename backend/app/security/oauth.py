import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Any
from urllib.parse import urlencode

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import OAuthState


def generate_oauth_state(secret_key: str, redirect_path: str = "/overview") -> str:
    """Generate a tamper-proof HMAC-signed OAuth state parameter.

    Contains:
    - nonce: 16 bytes of cryptographic entropy
    - timestamp: current UTC epoch seconds
    - redirect_path: client destination after authentication
    - signature: HMAC-SHA256 signature
    """
    if not secret_key:
        raise ValueError("secret_key is required to sign OAuth state.")

    payload = {
        "nonce": secrets.token_hex(16),
        "ts": time.time(),
        "path": redirect_path or "/overview",
    }
    raw_json = json.dumps(payload, separators=(",", ":"))
    b64_payload = base64.urlsafe_b64encode(raw_json.encode("utf-8")).decode("utf-8").rstrip("=")

    signature = hmac.new(
        secret_key.encode("utf-8"),
        b64_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{b64_payload}.{signature}"


def verify_oauth_state(
    state: Optional[str],
    secret_key: str,
    max_age_seconds: int = 600,
) -> Tuple[bool, Optional[str]]:
    """Verify an OAuth state parameter's cryptographic signature and freshness.

    Returns:
        (is_valid, redirect_path)
    """
    if not state or not secret_key or "." not in state:
        return False, None

    parts = state.split(".", 1)
    if len(parts) != 2:
        return False, None

    b64_payload, signature = parts

    # 1. Constant-time signature verification
    expected_sig = hmac.new(
        secret_key.encode("utf-8"),
        b64_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature.encode("utf-8"), expected_sig.encode("utf-8")):
        return False, None

    # 2. Decode payload
    try:
        # Add padding back if necessary
        padded = b64_payload + "=" * ((4 - len(b64_payload) % 4) % 4)
        raw_json = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        payload = json.loads(raw_json)
    except Exception:
        return False, None

    # 3. Expiration check
    ts = payload.get("ts")
    if not isinstance(ts, (int, float)):
        return False, None

    now = time.time()
    if now - ts > max_age_seconds or ts > now + 60:
        return False, None

    redirect_path = payload.get("path", "/overview")
    # Sanitize redirect path to prevent open redirect
    if not redirect_path.startswith("/") or redirect_path.startswith("//"):
        redirect_path = "/overview"

    return True, redirect_path


def hash_oauth_state(state: str) -> str:
    """Generate SHA-256 hash of state string for safe indexing and DB lookup."""
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


async def save_oauth_state(
    db: AsyncSession,
    state: str,
    redirect_path: str = "/overview",
    max_age_seconds: int = 600,
) -> OAuthState:
    """Persist a new OAuth state parameter in the database with strict expiration."""
    nonce = secrets.token_hex(16)
    if "." in state:
        b64_payload = state.split(".", 1)[0]
        try:
            padded = b64_payload + "=" * ((4 - len(b64_payload) % 4) % 4)
            raw = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
            data = json.loads(raw)
            nonce = data.get("nonce", nonce)
        except Exception:
            pass

    state_hash = hash_oauth_state(state)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max_age_seconds)

    record = OAuthState(
        state_hash=state_hash,
        nonce=nonce,
        redirect_path=redirect_path or "/overview",
        expires_at=expires_at,
        consumed_at=None,
    )
    db.add(record)
    await db.flush()
    return record


async def consume_oauth_state(
    db: AsyncSession,
    state: Optional[str],
    secret_key: str,
    max_age_seconds: int = 600,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Atomically consume an OAuth state record, preventing replays, tampering, and race conditions.

    Protections:
    1. Rejects tampered, malformed, or unsigned state values.
    2. Rejects expired state tokens.
    3. Atomically consumes via single SQL UPDATE statement (race-condition immune).
    4. Rejects already consumed state values (replay prevention).

    Returns:
        (is_valid, redirect_path, error_reason)
        error_reason: None on success, or "tampered_or_invalid", "expired", "already_used", "not_found"
    """
    if not state:
        return False, None, "tampered_or_invalid"

    # 1. Constant-time HMAC signature verification and timestamp freshness check
    is_valid_crypto, redirect_path = verify_oauth_state(state, secret_key, max_age_seconds=max_age_seconds)
    if not is_valid_crypto:
        return False, None, "tampered_or_invalid"

    state_hash = hash_oauth_state(state)
    now = datetime.now(timezone.utc)

    # 2. Atomic state consumption using UPDATE with WHERE consumed_at IS NULL AND expires_at > now
    stmt = (
        update(OAuthState)
        .where(
            OAuthState.state_hash == state_hash,
            OAuthState.consumed_at.is_(None),
            OAuthState.expires_at > now,
        )
        .values(consumed_at=now)
    )
    result = await db.execute(stmt)
    await db.commit()

    if result.rowcount == 1:
        return True, redirect_path, None

    # Inspect the record to determine exact failure cause
    record = await db.scalar(select(OAuthState).where(OAuthState.state_hash == state_hash))
    if not record:
        return False, None, "not_found"
    if record.consumed_at is not None:
        return False, None, "already_used"
    if record.is_expired:
        return False, None, "expired"

    return False, None, "already_used"



def build_github_authorization_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    scope: str = "read:user user:email",
) -> str:
    """Construct GitHub OAuth 2.0 authorization URL."""
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "allow_signup": "true",
    }
    return f"https://github.com/login/oauth/authorize?{urlencode(params)}"


def validate_github_account_linking(
    existing_user_by_email: Optional[Any],
    existing_oauth_account: Optional[Any],
    github_email: str,
) -> Tuple[bool, Optional[str]]:
    """Enforce strict account linking policy:
    Never automatically link an existing email/password account to GitHub
    based only on matching email addresses. Require explicit authenticated account linking.

    Returns:
        (is_allowed, error_reason)
    """
    # 1. If this exact GitHub account is already linked, login is allowed
    if existing_oauth_account is not None:
        return True, None

    # 2. If a local user exists with this email but has NOT linked this GitHub account,
    # auto-linking is strictly prohibited to prevent account takeover.
    if existing_user_by_email is not None:
        return False, (
            f"An account with email '{github_email}' already exists. "
            "To link your GitHub account, please sign in with your password first "
            "and connect GitHub in Profile Settings."
        )

    # 3. Brand new user registering via GitHub -> allowed
    return True, None
