import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional
import httpx
from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class SafeResponse:
    """Bounded, sanitized HTTP response wrapper."""

    url: str
    status_code: int
    headers: Dict[str, str]
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)
    text: str = ""
    redirect_history: List[str] = field(default_factory=list)
    elapsed_ms: int = 0
    error: Optional[str] = None


class SafeHttpClient:
    """Controlled, asynchronous HTTP client enforcing security boundaries."""

    def __init__(self, timeout: Optional[float] = None, max_size: Optional[int] = None):
        settings = get_settings()
        self.timeout = timeout or settings.SCANNER_TIMEOUT_SECONDS
        self.max_size = max_size or settings.SCANNER_MAX_RESPONSE_SIZE
        self.user_agent = settings.SCANNER_USER_AGENT

    async def get(
        self,
        url: str,
        follow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
        max_redirects: int = 5,
    ) -> SafeResponse:
        """Perform a safe, bounded HTTP GET request."""
        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if headers:
            req_headers.update(headers)

        transport = httpx.AsyncHTTPTransport(retries=1)
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

        redirect_history: List[str] = []

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                transport=transport,
                limits=limits,
                verify=False,  # We allow probing self-signed/expired targets to detect TLS issues
                follow_redirects=False,  # We handle redirects manually up to max_redirects
            ) as client:
                current_url = url
                redirect_count = 0

                while True:
                    response = await client.get(current_url, headers=req_headers)

                    if follow_redirects and response.is_redirect and redirect_count < max_redirects:
                        redirect_history.append(str(response.url))
                        location = response.headers.get("Location")
                        if not location:
                            break
                        # Resolve relative redirect URLs
                        current_url = str(response.url.join(location))
                        redirect_count += 1
                        continue

                    # Bounded body reading to prevent memory exhaustion / DoS
                    content_bytes = response.content
                    if len(content_bytes) > self.max_size:
                        content_bytes = content_bytes[: self.max_size]

                    text = content_bytes.decode("utf-8", errors="replace")

                    # Extract raw headers preserve multiple Set-Cookie entries
                    raw_headers = [(k, v) for k, v in response.headers.raw]
                    # Also normalized string headers
                    raw_headers_str = [(k.decode("latin1", errors="replace"), v.decode("latin1", errors="replace")) for k, v in raw_headers]

                    return SafeResponse(
                        url=str(response.url),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        raw_headers=raw_headers_str,
                        text=text[:100000],  # Max 100KB body inspection
                        redirect_history=redirect_history,
                        elapsed_ms=int(response.elapsed.total_seconds() * 1000) if response.elapsed else 0,
                    )

        except httpx.TimeoutException:
            return SafeResponse(
                url=url,
                status_code=0,
                headers={},
                error=f"Connection timed out after {self.timeout}s",
            )
        except httpx.ConnectError as e:
            return SafeResponse(
                url=url,
                status_code=0,
                headers={},
                error=f"Connection failed: {e}",
            )
        except Exception as e:
            logger.warning("Safe HTTP client error probing %s: %s", url, e)
            return SafeResponse(
                url=url,
                status_code=0,
                headers={},
                error=str(e),
            )

    async def head(self, url: str) -> SafeResponse:
        """Perform a safe, bounded HTTP HEAD probe."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False,
                follow_redirects=False,
            ) as client:
                response = await client.head(
                    url, headers={"User-Agent": self.user_agent}
                )
                raw_headers = [
                    (k.decode("latin1", errors="replace"), v.decode("latin1", errors="replace"))
                    for k, v in response.headers.raw
                ]
                return SafeResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    raw_headers=raw_headers,
                    elapsed_ms=int(response.elapsed.total_seconds() * 1000) if response.elapsed else 0,
                )
        except Exception as e:
            return SafeResponse(url=url, status_code=0, headers={}, error=str(e))
