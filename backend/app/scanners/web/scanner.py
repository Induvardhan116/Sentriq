import asyncio
import logging
from typing import List, Dict, Any, Optional
from app.risk.engine import calculate_finding_risk, calculate_posture_score
from app.scanners.web.client import SafeHttpClient, SafeResponse
from app.scanners.web.validator import validate_target_url
from app.scanners.web.checks.https import check_https_tls
from app.scanners.web.checks.headers import check_security_headers
from app.scanners.web.checks.cookies import check_cookie_security
from app.scanners.web.checks.cors import check_cors_configuration
from app.scanners.web.checks.exposure import check_information_exposure
from app.scanners.web.checks.configuration import check_website_configuration

logger = logging.getLogger("sentriq.scanner")


class WebsiteScanner:
    """Safe, non-destructive, bounded website security assessment orchestrator."""

    def __init__(self, client: Optional[SafeHttpClient] = None):
        self.client = client or SafeHttpClient()

    async def scan(
        self, target_url: str, allow_internal: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Execute all defensive website security checks against an authorized target."""
        # 1. URL and SSRF Safety Validation
        is_valid, error, normalized_url = validate_target_url(
            target_url, allow_internal=allow_internal
        )
        if not is_valid or not normalized_url:
            return {
                "success": False,
                "error": error or "Invalid target URL",
                "findings": [],
                "overall_score": 0,
                "score_grade": "Critical",
                "counts": {},
            }

        logger.info("Starting safe website security scan against %s", normalized_url)
        all_findings: List[Dict[str, Any]] = []

        # 2. Probe Main Web Endpoint
        main_resp = await self.client.get(normalized_url, follow_redirects=True)

        if main_resp.error:
            logger.warning("Main probe failed for %s: %s", normalized_url, main_resp.error)
            all_findings.append({
                "category": "https_tls",
                "title": "Target Endpoint Unreachable",
                "description": f"The security scanner was unable to establish a connection to '{normalized_url}'. Reason: {main_resp.error}",
                "severity": "high",
                "confidence": 1.0,
                "cwe": "CWE-693",
                "endpoint": normalized_url,
                "evidence": f"Connection probe failed: {main_resp.error}",
                "remediation": "Verify the server is running, the domain DNS is correctly configured, and firewall rules allow incoming HTTP/HTTPS traffic.",
            })
        else:
            # Execute modular checks in parallel where appropriate
            tasks = [
                check_https_tls(normalized_url, self.client),
                check_cors_configuration(normalized_url, main_resp, self.client),
                check_website_configuration(normalized_url, main_resp, self.client),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 3. Synchronous inspections of main response
            all_findings.extend(check_security_headers(main_resp))
            all_findings.extend(check_cookie_security(main_resp))
            all_findings.extend(check_information_exposure(main_resp))

            # 4. Integrate parallel results safely
            for res in results:
                if isinstance(res, list):
                    all_findings.extend(res)
                elif isinstance(res, Exception):
                    logger.error("A scanner check encountered an error: %s", res)

        # 5. Calculate transparent risk scores and normalize findings
        normalized_findings: List[Dict[str, Any]] = []
        for raw in all_findings:
            sev = raw.get("severity", "informational")
            conf = float(raw.get("confidence", 1.0))
            risk_score = calculate_finding_risk(sev, conf)

            normalized_findings.append({
                "source": "web",
                "category": raw.get("category", "configuration"),
                "title": raw.get("title", "Security Finding"),
                "description": raw.get("description", ""),
                "severity": sev,
                "confidence": conf,
                "risk_score": risk_score,
                "cwe": raw.get("cwe"),
                "endpoint": raw.get("endpoint", normalized_url),
                "evidence": raw.get("evidence", ""),
                "remediation": raw.get("remediation", ""),
                "status": "open",
            })

        # Sort findings by risk score descending
        normalized_findings.sort(key=lambda x: x["risk_score"], reverse=True)

        # 6. Calculate overall posture score and grade
        score, grade, counts = calculate_posture_score(normalized_findings)

        logger.info(
            "Completed scan for %s: score=%d, grade=%s, findings=%d",
            normalized_url,
            score,
            grade,
            len(normalized_findings),
        )

        return {
            "success": True,
            "target_url": normalized_url,
            "overall_score": score,
            "score_grade": grade,
            "findings": normalized_findings,
            "counts": counts,
            "error": None,
        }
