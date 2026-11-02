import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.user import User, LoginAttempt
from app.security.hasher import dummy_verify
from app.security.limiter import (
    is_account_locked,
    calculate_progressive_throttle_delay,
    is_ip_eligible_for_flood_limit,
)

logger = logging.getLogger("sentriq.security.rate_limiter")
settings = get_settings()


async def record_login_attempt(
    db: AsyncSession,
    ip_address: str,
    email: Optional[str],
    success: bool,
) -> LoginAttempt:
    """Persist an authentication attempt in the audit table."""
    attempt = LoginAttempt(
        ip_address=ip_address,
        email=email.strip().lower() if email else None,
        attempted_at=datetime.now(timezone.utc),
        success=success,
    )
    db.add(attempt)
    await db.flush()
    return attempt


async def check_login_rate_limit(
    db: AsyncSession,
    email: str,
    ip_address: str,
    user: Optional[User],
) -> Tuple[bool, Optional[str], Optional[int]]:
    """Evaluate database-backed rate limits, progressive delays, and account lockouts before password verification.

    Security & Balance Policy (Phase 3.3):
    1. Administrative lockout: If user account has an active `locked_until` in the future, rejects immediately.
    2. IP flood protection: Caps high-volume brute-force traffic from eligible/trustworthy client IP addresses.
    3. Progressive throttling: Calculates progressive delays based on recent failure count.
       Prolonged account lockout (15-60 minutes) triggered by unauthenticated attackers is strictly eliminated.
       Attackers are throttled with exponential backoff delays between attempts (Retry-After header),
       ensuring legitimate users are never blocked from authenticating with their correct password.

    Returns:
        (is_allowed, error_message, retry_after_seconds)
    """
    clean_email = email.strip().lower()
    now = datetime.now(timezone.utc)

    # Generic error message to prevent user enumeration
    GENERIC_LOCKOUT_MSG = "Too many failed login attempts. Account temporarily locked. Please try again later."

    # 1. Check administrative account lockout state on the User model
    if user and is_account_locked(user.locked_until):
        locked_dt = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        retry_after = max(1, min(3600, int((locked_dt - now).total_seconds())))
        logger.warning("Login rejected: Account locked for %s (retry-after: %ds)", clean_email, retry_after)
        return False, GENERIC_LOCKOUT_MSG, retry_after

    cutoff = now - timedelta(minutes=settings.AUTH_LOCKOUT_MINUTES)

    # 2. Check IP flood protection (max 50 failures per IP in lockout window)
    # Only enforce if the IP is trustworthy/eligible (not a shared untrusted proxy IP)
    if is_ip_eligible_for_flood_limit(ip_address, trust_proxy_headers=settings.TRUST_PROXY_HEADERS):
        query_ip = (
            select(func.count(LoginAttempt.id))
            .where(LoginAttempt.ip_address == ip_address)
            .where(LoginAttempt.attempted_at >= cutoff)
            .where(LoginAttempt.success.is_(False))
        )
        ip_failures = (await db.scalar(query_ip)) or 0
        if ip_failures >= 50:
            logger.warning("Login rejected: IP flood threshold exceeded (%d failures) for %s", ip_failures, ip_address)
            return False, "Too many failed login attempts from this network location. Please try again later.", 60
    else:
        logger.debug(
            "Skipping IP flood limiter for unverified/shared proxy IP %s. Account-level throttling is active.",
            ip_address,
        )

    # 3. Check failed attempts for this email within window
    query_email = (
        select(func.count(LoginAttempt.id), func.max(LoginAttempt.attempted_at))
        .where(LoginAttempt.email == clean_email)
        .where(LoginAttempt.attempted_at >= cutoff)
        .where(LoginAttempt.success.is_(False))
    )
    res_email = (await db.execute(query_email)).first()
    email_failures = res_email[0] or 0
    last_failure_at = res_email[1]

    # Calculate progressive throttle delay for repeated failures
    throttle_delay = calculate_progressive_throttle_delay(email_failures)

    # Enforce progressive backoff delay between repeated failed attempts (e.g. 5s, 10s, 20s... up to 300s)
    if email_failures >= settings.AUTH_MAX_FAILED_ATTEMPTS and throttle_delay > 0 and last_failure_at:
        last_dt = last_failure_at if last_failure_at.tzinfo else last_failure_at.replace(tzinfo=timezone.utc)
        elapsed = (now - last_dt).total_seconds()
        if elapsed < throttle_delay:
            retry_after = max(1, int(throttle_delay - elapsed))
            logger.warning(
                "Login throttled: Progressive delay active for %s (retry-after: %ds)",
                clean_email,
                retry_after,
            )
            return False, GENERIC_LOCKOUT_MSG, retry_after

    return True, None, None


async def on_login_failure(
    db: AsyncSession,
    email: str,
    ip_address: str,
    user: Optional[User],
) -> None:
    """Handle a failed authentication attempt with timing equalization."""
    clean_email = email.strip().lower()
    await record_login_attempt(db, ip_address=ip_address, email=clean_email, success=False)

    if user:
        user.failed_login_attempts += 1
        # NOTE (Phase 3.3 Security Remediation):
        # Prolonged account lockout (15-60 min) by unauthenticated attackers is strictly removed.
        # Failed attempts increment counters and trigger progressive backoff delays (Retry-After)
        # without denying legitimate account owners the ability to log in with their correct password.
        await db.commit()
    else:
        await db.commit()
        # Equalize execution timing for non-existent accounts to eliminate user enumeration
        dummy_verify()


async def on_login_success(
    db: AsyncSession,
    email: str,
    ip_address: str,
    user: User,
) -> None:
    """Handle a successful login attempt, resetting failure counters."""
    clean_email = email.strip().lower()
    await record_login_attempt(db, ip_address=ip_address, email=clean_email, success=True)
    user.failed_login_attempts = 0
    user.locked_until = None
    # Reset recent failed login attempts for this email upon successful authentication
    await db.execute(
        delete(LoginAttempt).where(
            LoginAttempt.email == clean_email,
            LoginAttempt.success.is_(False),
        )
    )
    await db.flush()


async def cleanup_old_login_attempts(
    db: AsyncSession,
    retention_hours: int = 24,
) -> int:
    """Safely delete login attempt records older than the retention window.

    Prevents the login_attempts audit table from growing indefinitely in production.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
    stmt = delete(LoginAttempt).where(LoginAttempt.attempted_at < cutoff)
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount or 0


async def periodic_login_attempts_cleanup(
    interval_seconds: int = 3600,
    retention_hours: int = 24,
) -> None:
    """Asynchronous background maintenance task that periodically purges expired login attempts.

    Runs outside the HTTP request lifecycle, ensuring zero added latency or blocking on login requests.
    Reliably executes on startup and recurring intervals even when no users authenticate.
    """
    import asyncio
    from app.database.session import AsyncSessionLocal

    logger.info("Starting background login attempts retention worker (interval: %ds, retention: %dh)", interval_seconds, retention_hours)
    while True:
        try:
            async with AsyncSessionLocal() as session:
                deleted = await cleanup_old_login_attempts(session, retention_hours=retention_hours)
                if deleted > 0:
                    logger.info("Background retention cleanup purged %d expired login attempt records.", deleted)
        except asyncio.CancelledError:
            logger.info("Background login attempts retention worker cancelled.")
            break
        except Exception as e:
            logger.warning("Background login attempts retention cleanup error: %s", e)

        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break


