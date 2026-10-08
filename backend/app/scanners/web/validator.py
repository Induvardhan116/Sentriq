import ipaddress
import socket
from typing import Tuple, Optional
from urllib.parse import urlparse
from app.config import get_settings

# Reserved and private IP networks to block for SSRF mitigation
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local & cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to any private or reserved network."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or any(ip_obj in net for net in PRIVATE_NETWORKS)
        )
    except ValueError:
        return False


def validate_target_url(
    url: str, allow_internal: Optional[bool] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Strictly validate and normalize target URL for safe assessment.

    Prevents:
    - Unsupported schemes (file, ftp, javascript, data, etc.)
    - Malformed URI syntax
    - Server-Side Request Forgery (SSRF) against private networks, loopback, or cloud metadata.

    Returns:
        (is_valid, error_reason, normalized_url)
    """
    if not url or not isinstance(url, str):
        return False, "Target URL must be a non-empty string.", None

    url = url.strip()

    # Check for explicit scheme
    if ":" in url:
        scheme_candidate = url.split(":", 1)[0].lower().strip()
        if scheme_candidate not in ("http", "https"):
            return (
                False,
                f"Protocol '{scheme_candidate}' is prohibited. Only HTTP and HTTPS are permitted.",
                None,
            )

    # Prepend https:// if no scheme provided
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL syntax: {e}", None

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Protocol '{parsed.scheme}' is prohibited. Only HTTP and HTTPS are allowed.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname.", None

    # Determine internal target permission (config setting with override)
    settings = get_settings()
    allow_int = allow_internal if allow_internal is not None else settings.ALLOW_INTERNAL_TARGETS

    # Disallow known internal / localhost hostnames unless internal targets permitted
    lower_host = hostname.lower()
    if not allow_int:
        if (
            lower_host == "localhost"
            or lower_host.endswith(".localhost")
            or lower_host.endswith(".local")
            or lower_host.endswith(".internal")
        ):
            return (
                False,
                "Scanning localhost or local network targets is prohibited to prevent SSRF.",
                None,
            )

        # Check direct IP literals
        if is_private_or_reserved_ip(lower_host):
            return (
                False,
                f"Target IP '{lower_host}' is a private or reserved network address and cannot be scanned.",
                None,
            )

        # Resolve hostname and verify resolved IPs are not private
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = {item[4][0] for item in addr_info}
            for ip in resolved_ips:
                if is_private_or_reserved_ip(ip):
                    return (
                        False,
                        f"Hostname '{hostname}' resolves to private/reserved IP '{ip}', which is prohibited.",
                        None,
                    )
        except socket.gaierror:
            # DNS resolution failure will be handled gracefully during scan execution
            pass
        except Exception:
            pass

    # Normalize URL: scheme + netloc + path (if any)
    path = parsed.path if parsed.path else "/"
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc}{path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"

    return True, None, normalized
