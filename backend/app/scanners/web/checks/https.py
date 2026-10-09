import asyncio
import datetime
import os
import socket
import ssl
import tempfile
from typing import List, Dict, Any
from urllib.parse import urlparse
from app.scanners.web.client import SafeHttpClient


def _inspect_ssl_cert(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Inspect SSL/TLS certificate details using Python standard ssl library."""
    result: Dict[str, Any] = {
        "connected": False,
        "expired": False,
        "expires_in_days": None,
        "valid_hostname": False,
        "version": None,
        "error": None,
        "subject_alt_names": [],
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Read certificate even if self-signed/expired

    try:
        with socket.create_connection((hostname, port), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["connected"] = True
                result["version"] = ssock.version()
                cert: Optional[Dict[str, Any]] = None

                # Extract and decode peer certificate from raw DER bytes if available
                try:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        pem = ssl.DER_cert_to_PEM_cert(der)
                        with tempfile.NamedTemporaryFile("w", delete=False) as f:
                            f.write(pem)
                            fn = f.name
                        try:
                            if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
                                cert = ssl._ssl._test_decode_cert(fn)
                        finally:
                            try:
                                if os.path.exists(fn):
                                    os.unlink(fn)
                            except OSError:
                                pass
                except Exception:
                    pass

                # Perform standard verification check to test certificate trust chain
                try:
                    verify_ctx = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=5.0) as s2:
                        with verify_ctx.wrap_socket(s2, server_hostname=hostname) as ss2:
                            if not cert:
                                cert = ss2.getpeercert()
                            result["valid_hostname"] = True
                except ssl.SSLCertVerificationError as ve:
                    result["error"] = str(ve)
                    if "expired" in str(ve).lower():
                        result["expired"] = True
                except Exception as e:
                    result["error"] = str(e)

                if cert:
                    # Check expiration
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        not_after = datetime.datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        delta = (not_after - now).days
                        result["expires_in_days"] = delta
                        if delta < 0:
                            result["expired"] = True

                    # Check Subject Alt Names
                    san = cert.get("subjectAltName", ())
                    sans = [name for typ, name in san if typ == "DNS"]
                    result["subject_alt_names"] = sans

                    # Hostname verification (SAN or Common Name fallback)
                    if not result["valid_hostname"]:
                        for san_name in sans:
                            if san_name == hostname or (
                                san_name.startswith("*.")
                                and hostname.endswith(san_name[1:])
                            ):
                                result["valid_hostname"] = True
                                break
                        if not result["valid_hostname"] and not sans:
                            subject = cert.get("subject", ())
                            for rdn in subject:
                                for typ, val in rdn:
                                    if typ == "commonName":
                                        if val == hostname or (
                                            val.startswith("*.")
                                            and hostname.endswith(val[1:])
                                        ):
                                            result["valid_hostname"] = True
                                            break

    except Exception as e:
        result["error"] = str(e)

    return result


async def check_https_tls(
    target_url: str, client: SafeHttpClient
) -> List[Dict[str, Any]]:
    """Safely inspect HTTPS availability, certificate status, and HTTP->HTTPS redirection."""
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if not hostname:
        return findings

    is_initially_https = parsed.scheme.lower() == "https"
    port = parsed.port or (443 if is_initially_https else 80)
    tls_port = port if (port and is_initially_https) else 443
    tls_endpoint = f"https://{hostname}:{tls_port}" if tls_port != 443 else f"https://{hostname}"

    # 1. TLS Certificate Inspection if port is 443 or target is HTTPS
    if is_initially_https or port == 443:
        cert_info = await asyncio.to_thread(_inspect_ssl_cert, hostname, tls_port)

        if not cert_info["connected"]:
            findings.append({
                "category": "https_tls",
                "title": "HTTPS Service Unavailable",
                "description": f"The target host '{hostname}' did not accept secure TLS connections on port {tls_port}. All communications may be sent in plaintext.",
                "severity": "high",
                "confidence": 0.95,
                "cwe": "CWE-319",
                "endpoint": tls_endpoint,
                "evidence": f"TLS connection probe failed: {cert_info.get('error') or 'Connection refused / timed out'}",
                "remediation": "Enable HTTPS on the web server with a valid TLS certificate (e.g., using Let's Encrypt or an authorized certificate authority) and disable plain HTTP.",
            })
        else:
            is_expired = cert_info.get("expired") or (
                cert_info.get("error") and "expired" in cert_info["error"].lower()
            )
            if is_expired:
                days_str = (
                    f" ({cert_info.get('expires_in_days')} days ago)"
                    if cert_info.get("expires_in_days") is not None
                    else ""
                )
                findings.append({
                    "category": "https_tls",
                    "title": "Expired SSL/TLS Certificate",
                    "description": f"The SSL/TLS certificate for '{hostname}' has expired. Browsers will block access and display security warnings.",
                    "severity": "critical",
                    "confidence": 1.0,
                    "cwe": "CWE-295",
                    "endpoint": tls_endpoint,
                    "evidence": f"Certificate expired{days_str}. Error: {cert_info.get('error') or 'Expired'}",
                    "remediation": "Renew the SSL/TLS certificate immediately and configure automatic renewal.",
                })
            elif (
                cert_info.get("expires_in_days") is not None
                and 0 <= cert_info["expires_in_days"] <= 14
            ):
                findings.append({
                    "category": "https_tls",
                    "title": "SSL/TLS Certificate Expiring Soon",
                    "description": f"The SSL/TLS certificate for '{hostname}' will expire in {cert_info['expires_in_days']} days.",
                    "severity": "low",
                    "confidence": 1.0,
                    "cwe": "CWE-295",
                    "endpoint": tls_endpoint,
                    "evidence": f"Days remaining: {cert_info['expires_in_days']}",
                    "remediation": "Renew the SSL/TLS certificate before it expires to prevent service disruption.",
                })

            # Check hostname mismatch
            is_mismatch = (
                (cert_info.get("error") and "hostname" in cert_info["error"].lower())
                or (
                    cert_info["connected"]
                    and not cert_info.get("valid_hostname")
                    and bool(cert_info.get("subject_alt_names"))
                )
            )
            if is_mismatch and not is_expired:
                findings.append({
                    "category": "https_tls",
                    "title": "SSL/TLS Certificate Hostname Mismatch",
                    "description": f"The certificate presented by the server does not match the requested hostname '{hostname}'.",
                    "severity": "high",
                    "confidence": 0.95,
                    "cwe": "CWE-297",
                    "endpoint": tls_endpoint,
                    "evidence": f"SANs: {cert_info.get('subject_alt_names')}, Verification error: {cert_info.get('error')}",
                    "remediation": f"Issue a certificate that covers '{hostname}' in its Subject Alternative Name (SAN) list.",
                })
            elif (
                cert_info.get("error")
                and not is_expired
                and any(
                    err_term in cert_info["error"].lower()
                    for err_term in ("self-signed", "self signed", "certificate verify failed", "unable to get local issuer")
                )
            ):
                findings.append({
                    "category": "https_tls",
                    "title": "Untrusted or Self-Signed SSL/TLS Certificate",
                    "description": f"The SSL/TLS certificate chain for '{hostname}' could not be verified by a recognized Certificate Authority.",
                    "severity": "high",
                    "confidence": 0.95,
                    "cwe": "CWE-295",
                    "endpoint": tls_endpoint,
                    "evidence": f"Verification error: {cert_info['error']}",
                    "remediation": "Install a TLS certificate issued by a trusted public Certificate Authority (e.g. Let's Encrypt).",
                })

    # 2. HTTP to HTTPS Redirection Check
    http_probe_url = f"http://{hostname}"
    if parsed.scheme.lower() == "http" and parsed.port and parsed.port != 80:
        http_probe_url = f"http://{hostname}:{parsed.port}"
    http_resp = await client.get(http_probe_url, follow_redirects=False)

    if http_resp.status_code in (301, 302, 307, 308):
        location = http_resp.headers.get("location", "")
        if not location.lower().startswith("https://"):
            findings.append({
                "category": "https_tls",
                "title": "Insecure HTTP Redirect Target",
                "description": f"The plain HTTP service redirects requests, but the target location '{location}' does not use HTTPS.",
                "severity": "medium",
                "confidence": 0.9,
                "cwe": "CWE-319",
                "endpoint": http_probe_url,
                "evidence": f"HTTP {http_resp.status_code} -> Location: {location}",
                "remediation": "Configure HTTP redirects to point directly to the HTTPS version of the domain.",
            })
    elif http_resp.status_code == 200:
        # HTTP served directly without redirecting to HTTPS
        findings.append({
            "category": "https_tls",
            "title": "HTTP Traffic Not Redirected to HTTPS",
            "description": f"The web server responds to plain HTTP requests with HTTP 200 without redirecting users to HTTPS.",
            "severity": "medium",
            "confidence": 0.95,
            "cwe": "CWE-319",
            "endpoint": http_probe_url,
            "evidence": f"Plain HTTP probe returned status code {http_resp.status_code} without redirect.",
            "remediation": "Configure a permanent 301 redirect on port 80 to redirect all HTTP traffic to HTTPS.",
        })

    return findings
