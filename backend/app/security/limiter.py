"""Rate-Limiting Calculation & Trusted Proxy Utilities.

ARCHITECTURE NOTE (Phase 3.1):
This module provides pure calculation and threshold evaluation utilities for:
- Evaluating lockout windows and exponential backoff durations.
- Validating connecting socket peers against explicit trusted proxies.
- Safely extracting client IP addresses without trusting spoofed X-Forwarded-For headers.

PERSISTENCE BOUNDARY:
These functions provide the security foundation for rate-limiting.
Actual database persistence (recording attempts in the `login_attempts` table and
persisting `users.locked_until`) will be integrated with database sessions in Phase 3.2.

RENDER PROXY & TRUSTED PROXY ARCHITECTURE:
Render deploys an edge proxy infrastructure (Cloudflare + internal load balancers)
that routes traffic to service containers over dynamic internal networking.
Render does NOT publish static, narrowly scoped IP ranges for its internal proxies.

SECURITY POLICY:
1. Do NOT trust broad private ranges (e.g., 10.0.0.0/8 or 172.16.0.0/12) without verified justification,
   as shared-tenant or dynamic internal networks cannot guarantee peer authenticity without
   mutual TLS or cryptographic headers.
2. If the exact upstream proxy peer addresses cannot be verified, keep `TRUST_PROXY_HEADERS = False` (the default).
   When disabled, `extract_client_ip` uses only the direct socket peer (`client_host`), completely
   rejecting spoofed `X-Forwarded-For` or `X-Real-IP` headers.
3. Only enable `TRUST_PROXY_HEADERS = True` when running behind a verified, narrowly scoped proxy
   (e.g., a local reverse proxy on `127.0.0.1` or an enterprise gateway with a known static address).
"""

import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Union


def is_ip_in_trusted_proxies(
    ip_str: str,
    trusted_proxies: List[str],
) -> bool:
    """Verify whether a candidate connecting IP matches an explicitly trusted proxy address or network."""
    if not ip_str or not trusted_proxies:
        return False

    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False

    for proxy_entry in trusted_proxies:
        entry = proxy_entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if ip_obj in net:
                    return True
            else:
                trusted_obj = ipaddress.ip_address(entry)
                if ip_obj == trusted_obj:
                    return True
        except ValueError:
            continue

    return False


def extract_client_ip(
    headers: Dict[str, str],
    client_host: Optional[str] = None,
    trusted_proxies: Optional[Union[List[str], str]] = None,
    trust_proxy_headers: bool = False,
) -> str:
    """Safely extract normalized client IP for security auditing and rate-limiting.

    SECURITY RULES:
    1. Never trust arbitrary or spoofed X-Forwarded-For values from untrusted connecting hosts.
    2. Forwarded headers are ONLY parsed if `trust_proxy_headers` is True AND the immediate
       connecting socket peer (`client_host`) is verified to be in `trusted_proxies`.
    3. The candidate forwarded IP is strictly validated using `ipaddress.ip_address`.
    4. If validation fails or the proxy is untrusted, safely falls back to `client_host`.
    """
    direct_peer = (client_host or "127.0.0.1").strip()

    # Rule 1: If proxy header trust is disabled, always return the direct socket peer
    if not trust_proxy_headers:
        return direct_peer

    # Normalize trusted proxies list
    if trusted_proxies is None:
        proxies_list = ["127.0.0.1", "::1"]
    elif isinstance(trusted_proxies, str):
        proxies_list = [p.strip() for p in trusted_proxies.split(",") if p.strip()]
    else:
        proxies_list = [p.strip() for p in trusted_proxies if p.strip()]

    # Rule 2: Verify direct socket peer is in the trusted proxies whitelist
    if not is_ip_in_trusted_proxies(direct_peer, proxies_list):
        return direct_peer

    # Rule 3: Inspect X-Forwarded-For or X-Real-IP provided by the trusted proxy (case-insensitive)
    lower_headers = {k.lower(): v for k, v in headers.items() if isinstance(k, str) and v is not None}
    x_forwarded_for = lower_headers.get("x-forwarded-for")
    x_real_ip = lower_headers.get("x-real-ip")

    candidate_str = None
    if x_forwarded_for:
        parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
        if parts:
            # First hop represents the original client connecting to the edge proxy
            candidate_str = parts[0]
    elif x_real_ip:
        candidate_str = x_real_ip.strip()

    if candidate_str:
        try:
            # Validate IP syntax strictly
            ip_obj = ipaddress.ip_address(candidate_str)
            return str(ip_obj)
        except ValueError:
            # Malformed candidate IP in forwarded header; fail closed to direct peer
            return direct_peer

    return direct_peer


def is_account_locked(locked_until: Optional[datetime]) -> bool:
    """Pure calculation helper: check if an account is currently in a temporary locked state."""
    if not locked_until:
        return False

    now = datetime.now(timezone.utc)
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)

    return now < locked_until


def should_lockout(failed_attempts: int, max_attempts: int = 5) -> bool:
    """Pure threshold helper: check if consecutive failure count has reached the lockout limit."""
    return failed_attempts >= max_attempts


def calculate_lockout_time(
    failed_attempts: int,
    base_minutes: int = 15,
    max_minutes: int = 60,
) -> datetime:
    """Pure calculation helper: calculate progressive temporary throttle duration.

    SECURITY DEFENSE (Phase 3.3):
    24-hour account lockout is strictly prohibited to prevent Denial-of-Service (DoS)
    attacks where an adversary locks out legitimate account owners by repeatedly
    submitting incorrect credentials.
    Throttling is capped at max_minutes (default 60 minutes) to provide brute-force
    resistance without permitting indefinite or 24-hour account lockouts.
    """
    now = datetime.now(timezone.utc)
    multiplier = max(1, 2 ** min(2, failed_attempts - 5)) if failed_attempts > 5 else 1
    total_minutes = min(base_minutes * multiplier, max_minutes)
    return now + timedelta(minutes=total_minutes)


def calculate_progressive_throttle_delay(
    failed_attempts: int,
    base_seconds: int = 5,
    max_seconds: int = 300,
) -> int:
    """Calculate progressive temporary delay in seconds for repeated authentication failures.

    Provides progressive throttling without locking out legitimate users across other devices.
    Returns 0 for attempts below threshold (< 5), then ramps exponentially:
    - 5 attempts: 5s
    - 6 attempts: 10s
    - 7 attempts: 20s
    - 8 attempts: 40s
    Capped strictly at max_seconds (default 300s / 5 minutes).
    """
    if failed_attempts < 5:
        return 0
    multiplier = 2 ** min(6, failed_attempts - 5)
    return min(base_seconds * multiplier, max_seconds)


def is_ip_eligible_for_flood_limit(
    ip_address: str,
    trust_proxy_headers: bool = False,
) -> bool:
    """Determine whether an IP address is eligible for global IP flood rate limiting.

    When running behind an untrusted reverse proxy (such as on Render with TRUST_PROXY_HEADERS=False),
    all incoming socket connections share a private or loopback proxy address (e.g. 127.0.0.1 or 10.x.x.x).
    Enforcing an IP flood threshold against this shared gateway address would cause collateral
    Denial of Service (DoS) for all unrelated users on the platform whenever any account is attacked.

    Rules:
    1. If trust_proxy_headers is True: The IP was already verified and extracted from a trusted proxy
       (or is a direct public peer), so it is eligible for IP flood limiting.
    2. If trust_proxy_headers is False:
       - If the IP is loopback, private, link-local, or reserved: It is an unverified shared proxy IP
         and must NOT be used for platform-wide IP flood lockout.
       - If the IP is a public, routable IP: It represents a direct public socket connection and is eligible.
    """
    if not ip_address:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return False

    if trust_proxy_headers:
        return True

    # When proxy headers are NOT trusted, private, loopback, or reserved addresses indicate
    # an internal proxy/gateway hop where all users collapse onto the same IP.
    # Only globally routable public IPs directly connected to the socket are eligible.
    return ip_obj.is_global


