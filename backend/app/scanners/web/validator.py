import ipaddress
import socket
from typing import Tuple, Optional, Union
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


def try_parse_ip_address(
    ip_str: str,
) -> Tuple[bool, Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]], bool]:
    """Parse an IP address string across standard and alternative representations.

    Returns:
        (is_ip_candidate, parsed_ip_obj, is_malformed)
        - is_ip_candidate: True if the string was recognized as an IP literal
        - parsed_ip_obj: The IPv4Address or IPv6Address object if valid
        - is_malformed: True if it is an IP candidate that failed bounds/syntax checks
    """
    s = ip_str.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if "%" in s:
        s = s.split("%")[0]

    # Standard parser handles RFC IPv4 and IPv6
    try:
        ip = ipaddress.ip_address(s)
        return True, ip, False
    except ValueError:
        pass

    # Single integer, hex, or octal notation (e.g. 2130706433, 0x7f000001, 017700000001)
    if "." not in s and (
        s.startswith(("0x", "0X"))
        or s.isdigit()
        or (s.startswith("0") and len(s) > 1 and s.isalnum())
    ):
        try:
            if s.lower().startswith("0x"):
                val = int(s, 16)
            elif s.startswith("0") and len(s) > 1 and not s.lower().startswith(("0o", "0x")):
                val = int(s, 8)
            else:
                val = int(s, 10)

            if 0 <= val <= 0xFFFFFFFF:
                return True, ipaddress.IPv4Address(val), False
            else:
                return True, None, True
        except ValueError:
            return True, None, True

    # Dotted notation (decimal, octal, or hex parts; e.g. 0x7f.1, 0177.0.0.1, 0377.0377.0377.0377)
    parts = s.split(".")
    if 2 <= len(parts) <= 4:
        def is_part_cand(p: str) -> bool:
            if not p:
                return False
            if p.lower().startswith("0x"):
                return len(p) > 2 and all(c in "0123456789abcdefABCDEF" for c in p[2:])
            return p.isdigit()

        if all(is_part_cand(p) for p in parts):
            parsed_parts = []
            for p in parts:
                try:
                    if p.lower().startswith("0x"):
                        parsed_parts.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1:
                        parsed_parts.append(int(p, 8))
                    else:
                        parsed_parts.append(int(p, 10))
                except ValueError:
                    return True, None, True

            if len(parts) == 4:
                if all(0 <= p <= 255 for p in parsed_parts):
                    val = (
                        (parsed_parts[0] << 24)
                        | (parsed_parts[1] << 16)
                        | (parsed_parts[2] << 8)
                        | parsed_parts[3]
                    )
                    return True, ipaddress.IPv4Address(val), False
                return True, None, True
            elif len(parts) == 3:
                if 0 <= parsed_parts[0] <= 255 and 0 <= parsed_parts[1] <= 255 and 0 <= parsed_parts[2] <= 0xFFFF:
                    val = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | parsed_parts[2]
                    return True, ipaddress.IPv4Address(val), False
                return True, None, True
            elif len(parts) == 2:
                if 0 <= parsed_parts[0] <= 255 and 0 <= parsed_parts[1] <= 0xFFFFFF:
                    val = (parsed_parts[0] << 24) | parsed_parts[1]
                    return True, ipaddress.IPv4Address(val), False
                return True, None, True

    # Explicit IPv6 brackets or colons that failed standard parsing
    if ":" in s or s.startswith("["):
        return True, None, True

    return False, None, False


def _is_ip_obj_private_or_reserved(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> bool:
    """Internal check for IP classifications across private, loopback, link-local, and reserved ranges."""
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        return True

    for net in PRIVATE_NETWORKS:
        if ip_obj.version == net.version and ip_obj in net:
            return True

    # Check IPv6-mapped IPv4 (e.g. ::ffff:100.64.0.1) or IPv4-compatible IPv6
    if isinstance(ip_obj, ipaddress.IPv6Address):
        mapped = getattr(ip_obj, "ipv4_mapped", None)
        if mapped:
            return _is_ip_obj_private_or_reserved(mapped)
        ip_int = int(ip_obj)
        if (ip_int >> 32) == 0 and ip_int not in (0, 1):
            compat = ipaddress.IPv4Address(ip_int & 0xFFFFFFFF)
            return _is_ip_obj_private_or_reserved(compat)

    return False


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to any private or reserved network.
    Handles standard IPv4/IPv6 notation, integer notation, and hex/octal forms.
    Fails closed on malformed or unclassifiable IP addresses.
    """
    is_cand, ip_obj, is_malformed = try_parse_ip_address(ip_str)
    if is_malformed:
        return True  # Fail closed for malformed IP destination
    if not is_cand or ip_obj is None:
        try:
            inet_addr = socket.inet_ntoa(socket.inet_aton(ip_str))
            ip_obj = ipaddress.ip_address(inet_addr)
        except Exception:
            return False

    return _is_ip_obj_private_or_reserved(ip_obj)


def validate_target_url(
    url: str, allow_internal: Optional[bool] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Strictly validate and normalize target URL for safe assessment.

    Prevents:
    - Unsupported schemes (file, ftp, javascript, data, etc.)
    - Malformed URI syntax
    - Embedded user credentials
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

    if parsed.username or parsed.password:
        return (
            False,
            "Target URL must not contain embedded user credentials.",
            None,
        )

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname.", None

    lower_host = hostname.lower()

    # Fail closed on malformed IP destination
    is_cand, ip_obj, is_malformed = try_parse_ip_address(lower_host)
    if is_malformed:
        return (
            False,
            f"Target IP '{lower_host}' is malformed or unclassifiable and cannot be scanned.",
            None,
        )

    # Fail closed on malformed domain destination
    if not is_cand:
        labels = lower_host.split(".")
        if any(not label for label in labels) or any(
            label.startswith("-") or label.endswith("-") for label in labels
        ):
            return (
                False,
                f"Target hostname '{hostname}' is malformed.",
                None,
            )
        if len(labels) > 1 and labels[-1].isdigit():
            return (
                False,
                f"Target hostname '{hostname}' is unclassifiable.",
                None,
            )

    # Determine internal target permission (config setting with override)
    settings = get_settings()
    allow_int = allow_internal if allow_internal is not None else settings.ALLOW_INTERNAL_TARGETS

    # Disallow known internal / localhost hostnames unless internal targets permitted
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
        if is_cand and ip_obj:
            if _is_ip_obj_private_or_reserved(ip_obj):
                return (
                    False,
                    f"Target IP '{lower_host}' is a private or reserved network address and cannot be scanned.",
                    None,
                )
        elif is_private_or_reserved_ip(lower_host):
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
