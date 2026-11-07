import json
import re
from typing import Dict, Any, List, Tuple
from app.risk.engine import calculate_posture_score

try:
    import yaml
except ImportError:
    yaml = None

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "token",
    "private_key",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
}

DEBUG_PATH_PATTERNS = [
    re.compile(r"/debug", re.IGNORECASE),
    re.compile(r"/actuator", re.IGNORECASE),
    re.compile(r"/metrics", re.IGNORECASE),
    re.compile(r"/heapdump", re.IGNORECASE),
    re.compile(r"/trace", re.IGNORECASE),
    re.compile(r"/env", re.IGNORECASE),
]


class ApiSecurityAnalyzer:
    """Analyzer for OpenAPI 3.0 and Swagger 2.0 specifications against OWASP API Security Top 10."""

    @classmethod
    def parse_spec_content(cls, raw_content: str) -> Tuple[Dict[str, Any], str]:
        """Parse JSON or YAML specification text into a Python dict."""
        stripped = raw_content.strip()
        # Try JSON first
        if stripped.startswith("{"):
            try:
                return json.loads(stripped), "json"
            except Exception as e:
                raise ValueError(f"Invalid JSON specification: {e}")

        # Try YAML
        if yaml is not None:
            try:
                data = yaml.safe_load(stripped)
                if isinstance(data, dict):
                    return data, "yaml"
            except Exception as e:
                raise ValueError(f"Invalid YAML specification: {e}")

        raise ValueError("Could not parse specification as valid JSON or YAML.")

    @classmethod
    def extract_endpoints_and_findings(
        cls, spec_data: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
        """Analyze spec data for endpoints and OWASP API Security Top 10 vulnerabilities."""
        endpoints: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        is_openapi_3 = "openapi" in spec_data
        paths = spec_data.get("paths", {})

        # Extract Global Security Schemes
        has_global_security = bool(spec_data.get("security"))
        security_schemes = {}
        if is_openapi_3:
            security_schemes = spec_data.get("components", {}).get("securitySchemes", {})
        else:
            security_schemes = spec_data.get("securityDefinitions", {})

        # Check API7: Insecure Transport in Server URLs
        servers = spec_data.get("servers", [])
        for srv in servers:
            srv_url = srv.get("url", "")
            if srv_url.startswith("http://") and not ("localhost" in srv_url or "127.0.0.1" in srv_url):
                findings.append({
                    "owasp_category": "API7:2023",
                    "title": "Insecure Transport Protocol in API Server URL",
                    "description": f"API server defines plaintext HTTP transport ({srv_url}) exposing traffic to interception.",
                    "severity": "high",
                    "confidence": 1.0,
                    "risk_score": 75,
                    "path": srv_url,
                    "method": "CONFIG",
                    "remediation": "Enforce HTTPS with TLS 1.3 for all production API server configurations.",
                })

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Check API8: Debug / Verbose Endpoint exposure
            for dbg_re in DEBUG_PATH_PATTERNS:
                if dbg_re.search(path_str):
                    findings.append({
                        "owasp_category": "API8:2023",
                        "title": f"Exposed Debug or Actuator Endpoint ({path_str})",
                        "description": f"Internal diagnostic or management route '{path_str}' is defined in API schema.",
                        "severity": "high",
                        "confidence": 0.9,
                        "risk_score": 70,
                        "path": path_str,
                        "method": "ALL",
                        "remediation": "Restrict debug and administrative actuator endpoints from external public API documentation.",
                    })

            for method_str, op_item in path_item.items():
                method_upper = method_str.upper()
                if method_upper not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    continue

                if not isinstance(op_item, dict):
                    continue

                # Determine Auth Type
                op_security = op_item.get("security")
                auth_req = False
                auth_type = "none"

                if op_security is not None:
                    auth_req = len(op_security) > 0
                else:
                    auth_req = has_global_security

                if auth_req and security_schemes:
                    # Pick first scheme name
                    first_scheme = list(security_schemes.values())[0] if security_schemes else {}
                    auth_type = first_scheme.get("type", "bearer")
                elif auth_req:
                    auth_type = "bearer"

                # Check API2: Broken Authentication on Mutating Requests
                if method_upper in ("POST", "PUT", "DELETE", "PATCH") and not auth_req:
                    findings.append({
                        "owasp_category": "API2:2023",
                        "title": f"Unauthenticated State-Changing Operation ({method_upper} {path_str})",
                        "description": f"Route permits mutating requests without declaring security requirements.",
                        "severity": "critical",
                        "confidence": 0.9,
                        "risk_score": 85,
                        "path": path_str,
                        "method": method_upper,
                        "remediation": "Enforce authentication using OAuth 2.0 or JWT Bearer tokens on all data modification endpoints.",
                    })

                # Check API4: Missing Pagination on List Collections
                is_collection_get = method_upper == "GET" and not path_str.endswith("}")
                params = op_item.get("parameters", [])
                has_pagination = any(
                    isinstance(p, dict) and p.get("name", "").lower() in ("limit", "page", "offset", "size", "pagesize")
                    for p in params
                )
                if is_collection_get and not has_pagination:
                    findings.append({
                        "owasp_category": "API4:2023",
                        "title": f"Missing Pagination Bounds on Collection Route ({path_str})",
                        "description": f"Endpoint returns potential collections without defining 'limit' or 'page' pagination bounds.",
                        "severity": "medium",
                        "confidence": 0.8,
                        "risk_score": 50,
                        "path": path_str,
                        "method": method_upper,
                        "remediation": "Add limit, offset, or cursor-based pagination parameters to prevent Denial of Service.",
                    })

                # Check API3: Excessive Data Exposure in Responses
                responses = op_item.get("responses", {})
                for resp_code, resp_obj in responses.items():
                    if not isinstance(resp_obj, dict):
                        continue
                    schema_str = json.dumps(resp_obj).lower()
                    for sensitive_field in SENSITIVE_FIELD_NAMES:
                        if f'"{sensitive_field}"' in schema_str or f": {sensitive_field}" in schema_str:
                            findings.append({
                                "owasp_category": "API3:2023",
                                "title": f"Excessive Sensitive Data Exposure ({sensitive_field}) in Response",
                                "description": f"Endpoint response schema discloses sensitive property '{sensitive_field}' at HTTP {resp_code}.",
                                "severity": "high",
                                "confidence": 0.85,
                                "risk_score": 75,
                                "path": path_str,
                                "method": method_upper,
                                "remediation": f"Filter out internal field '{sensitive_field}' using Data Transfer Objects (DTOs) or response serializers.",
                            })
                            break

                endpoints.append({
                    "path": path_str,
                    "method": method_upper,
                    "summary": op_item.get("summary") or op_item.get("description") or f"{method_upper} {path_str}",
                    "auth_required": auth_req,
                    "auth_type": auth_type,
                    "parameters_count": len(params),
                    "has_request_body": "requestBody" in op_item or "parameters" in op_item,
                    "tags": ",".join(op_item.get("tags", [])) if op_item.get("tags") else None,
                })

        # Calculate overall posture score
        posture_score, _, _ = calculate_posture_score([{"severity": f["severity"]} for f in findings])
        return endpoints, findings, posture_score
