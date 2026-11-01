import hashlib
from typing import Optional


def compute_finding_fingerprint(
    target_url: str,
    category: str,
    check_rule_id: str,
    affected_resource: Optional[str] = None,
) -> str:
    """Generate a deterministic, stable SHA-256 fingerprint for finding deduplication and status persistence.

    Matching criteria:
    - Target URL: Normalized scheme and netloc.
    - Category: Finding category (e.g. security_headers, cookie_security).
    - Check / Rule ID: Identifier or title for the specific vulnerability check.
    - Affected Resource: Endpoint or target resource URI.
    """
    norm_target = (target_url or "").strip().lower().rstrip("/")
    norm_category = (category or "").strip().lower()
    norm_rule = (check_rule_id or "").strip()
    norm_resource = (affected_resource or norm_target).strip().rstrip("/")

    seed = f"{norm_target}|{norm_category}|{norm_rule}|{norm_resource}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()
