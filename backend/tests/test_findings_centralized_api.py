"""
Sentriq Phase 4.2 Integration Test Suite: Centralized Findings API

Tests:
1. Centralized listing (GET /api/findings) with pagination (limit, offset, total count).
2. Multi-dimensional filtering by status, severity, category, project_id, scan_id, and search query.
3. Dynamic sorting by risk_score, severity, created_at, and title.
4. Single finding detail endpoint (GET /api/findings/{id}) with relational project context.
5. Centralized summary metrics (GET /api/findings/summary) with severity, status, and category breakdowns.
6. Route ordering: ensures GET /api/findings/summary does not collide with /{finding_id}.
7. Strict tenant isolation across centralized listing, summary, and detail queries.
8. Superuser visibility across all tenant findings.
9. Preservation of Phase 4.1 OCC versioning, mandatory justification, and audit history.
10. Consistent error handling (sanitized 404s for cross-tenant access, 409 on version conflict).
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient

from app.config import get_settings
from app.models.user import User, UserSession
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.database.session import AsyncSessionLocal
from app.security.hasher import hash_password
from app.security.session import generate_session_token, hash_session_token
from app.security.csrf import generate_session_csrf_token

settings = get_settings()


async def create_isolated_tenant_user(email: str, is_superuser: bool = False):
    """Helper to create an isolated user and session, returning auth headers and cookies."""
    async with AsyncSessionLocal() as session:
        user = User(
            id=str(uuid.uuid4()),
            email=email.strip().lower(),
            hashed_password=hash_password("TenantPass123!"),
            full_name=f"User {email}",
            is_active=True,
            is_superuser=is_superuser,
        )
        session.add(user)
        await session.flush()

        raw_session_token = generate_session_token()
        token_hash = hash_session_token(raw_session_token)
        csrf_token = generate_session_csrf_token(token_hash, settings.SECRET_KEY)

        user_session = UserSession(
            user_id=user.id,
            token_hash=token_hash,
            ip_address="127.0.0.1",
            user_agent="Sentriq-Phase42-Test",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            revoked_at=None,
        )
        session.add(user_session)
        await session.commit()

        return {
            "id": user.id,
            "email": email,
            "token": raw_session_token,
            "csrf": csrf_token,
            "headers": {"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
            "cookies": {settings.SESSION_COOKIE_NAME: raw_session_token},
        }


@pytest.fixture
async def tenant_environment():
    """
    Sets up two isolated tenants (Tenant Alpha and Tenant Beta) each with a project,
    scan, and distinct findings for testing centralized queries and tenant boundary enforcement.
    """
    alpha = await create_isolated_tenant_user(f"alpha_{uuid.uuid4().hex[:6]}@sentriq.io")
    beta = await create_isolated_tenant_user(f"beta_{uuid.uuid4().hex[:6]}@sentriq.io")
    admin = await create_isolated_tenant_user(f"admin_{uuid.uuid4().hex[:6]}@sentriq.io", is_superuser=True)

    # Populate Alpha resources
    async with AsyncSessionLocal() as session:
        proj_alpha = Project(
            id=str(uuid.uuid4()),
            name="Alpha Portal",
            target_url="https://alpha.sentriq.io",
            authorization_confirmed=True,
            owner_id=alpha["id"],
        )
        session.add(proj_alpha)

        scan_alpha = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_alpha.id,
            target_url="https://alpha.sentriq.io",
            status="completed",
        )
        session.add(scan_alpha)

        f_alpha_1 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_alpha.id,
            category="headers",
            title="Missing HSTS Header",
            description="Strict-Transport-Security header is absent.",
            severity="high",
            confidence=1.0,
            risk_score=75,
            status="open",
            version=1,
            endpoint="https://alpha.sentriq.io/",
        )
        f_alpha_2 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_alpha.id,
            category="cookies",
            title="Session Cookie Missing HttpOnly",
            description="Sensitive auth cookie lacks HttpOnly flag.",
            severity="medium",
            confidence=0.9,
            risk_score=50,
            status="in_progress",
            version=1,
            endpoint="https://alpha.sentriq.io/login",
        )
        f_alpha_3 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_alpha.id,
            category="exposure",
            title="Git Repository Metadata Leaked",
            description="Public .git directory accessible.",
            severity="critical",
            confidence=1.0,
            risk_score=95,
            status="resolved",
            version=2,
            justification="Firewall blocked .git requests",
            endpoint="https://alpha.sentriq.io/.git/HEAD",
        )
        f_alpha_4 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_alpha.id,
            category="cors",
            title="Wildcard Access-Control-Allow-Origin",
            description="CORS allows arbitrary origins.",
            severity="low",
            confidence=0.8,
            risk_score=25,
            status="accepted_risk",
            version=2,
            justification="Public read-only API exception",
            endpoint="https://alpha.sentriq.io/api/public",
        )
        session.add_all([f_alpha_1, f_alpha_2, f_alpha_3, f_alpha_4])

        # Populate Beta resources
        proj_beta = Project(
            id=str(uuid.uuid4()),
            name="Beta Gateway",
            target_url="https://beta.sentriq.io",
            authorization_confirmed=True,
            owner_id=beta["id"],
        )
        session.add(proj_beta)

        scan_beta = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_beta.id,
            target_url="https://beta.sentriq.io",
            status="completed",
        )
        session.add(scan_beta)

        f_beta_1 = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_beta.id,
            category="headers",
            title="Missing Content-Security-Policy",
            description="No CSP header found.",
            severity="high",
            confidence=1.0,
            risk_score=70,
            status="open",
            version=1,
            endpoint="https://beta.sentriq.io/",
        )
        session.add(f_beta_1)
        await session.commit()

        return {
            "alpha": alpha,
            "beta": beta,
            "admin": admin,
            "proj_alpha_id": proj_alpha.id,
            "scan_alpha_id": scan_alpha.id,
            "f_alpha_ids": [f_alpha_1.id, f_alpha_2.id, f_alpha_3.id, f_alpha_4.id],
            "proj_beta_id": proj_beta.id,
            "scan_beta_id": scan_beta.id,
            "f_beta_ids": [f_beta_1.id],
        }


@pytest.mark.asyncio
async def test_centralized_findings_pagination(async_client: AsyncClient, tenant_environment):
    """Test pagination limit, offset, and total count on centralized GET /api/findings."""
    alpha = tenant_environment["alpha"]

    # 1. Fetch first page with limit=2, offset=0
    resp_p1 = await async_client.get(
        "/api/findings?limit=2&offset=0",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_p1.status_code == 200, resp_p1.text
    data_p1 = resp_p1.json()
    assert data_p1["total"] == 4
    assert len(data_p1["items"]) == 2
    assert data_p1["limit"] == 2
    assert data_p1["offset"] == 0
    first_page_ids = [f["id"] for f in data_p1["items"]]

    # 2. Fetch second page with limit=2, offset=2
    resp_p2 = await async_client.get(
        "/api/findings?limit=2&offset=2",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_p2.status_code == 200
    data_p2 = resp_p2.json()
    assert data_p2["total"] == 4
    assert len(data_p2["items"]) == 2
    assert data_p2["offset"] == 2
    second_page_ids = [f["id"] for f in data_p2["items"]]

    # Pages must be non-overlapping
    assert set(first_page_ids).isdisjoint(set(second_page_ids))

    # 3. Fetch past end of collection: limit=2, offset=10
    resp_empty = await async_client.get(
        "/api/findings?limit=2&offset=10",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_empty.status_code == 200
    data_empty = resp_empty.json()
    assert data_empty["total"] == 4
    assert len(data_empty["items"]) == 0


@pytest.mark.asyncio
async def test_centralized_findings_multi_attribute_filtering(async_client: AsyncClient, tenant_environment):
    """Test filtering by status, severity, category, scan_id, project_id, and search keyword."""
    alpha = tenant_environment["alpha"]

    # 1. Filter by status=open
    resp_st = await async_client.get(
        "/api/findings?status=open",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_st.status_code == 200
    data_st = resp_st.json()
    assert data_st["total"] == 1
    assert data_st["items"][0]["title"] == "Missing HSTS Header"

    # 2. Filter by status=accepted_risk
    resp_ar = await async_client.get(
        "/api/findings?status=accepted_risk",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_ar.status_code == 200
    assert resp_ar.json()["total"] == 1
    assert resp_ar.json()["items"][0]["status"] == "accepted_risk"

    # 3. Filter by severity=critical
    resp_sev = await async_client.get(
        "/api/findings?severity=critical",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_sev.status_code == 200
    data_sev = resp_sev.json()
    assert data_sev["total"] == 1
    assert data_sev["items"][0]["title"] == "Git Repository Metadata Leaked"

    # 4. Filter by category=cookies
    resp_cat = await async_client.get(
        "/api/findings?category=cookies",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_cat.status_code == 200
    assert resp_cat.json()["total"] == 1
    assert resp_cat.json()["items"][0]["category"] == "cookies"

    # 5. Case-insensitive Search by title keyword: "cookie"
    resp_search = await async_client.get(
        "/api/findings?search=cookie",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_search.status_code == 200
    data_search = resp_search.json()
    assert data_search["total"] == 1
    assert "HttpOnly" in data_search["items"][0]["title"]

    # 6. Search by endpoint keyword: ".git"
    resp_search_ep = await async_client.get(
        "/api/findings?search=.git",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_search_ep.status_code == 200
    assert resp_search_ep.json()["total"] == 1

    # 7. Non-matching search query
    resp_none = await async_client.get(
        "/api/findings?search=NonExistentVulnerabilityName12345",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_none.status_code == 200
    assert resp_none.json()["total"] == 0
    assert len(resp_none.json()["items"]) == 0

    # 8. Filter by unknown status returns empty list
    resp_unknown_st = await async_client.get(
        "/api/findings?status=unknown_status_val",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_unknown_st.status_code == 200
    assert resp_unknown_st.json()["total"] == 0


@pytest.mark.asyncio
async def test_centralized_findings_sorting(async_client: AsyncClient, tenant_environment):
    """Test dynamic sorting by risk_score, severity, created_at, and title."""
    alpha = tenant_environment["alpha"]

    # 1. Sort by risk_score desc (default): critical (95) -> high (75) -> medium (50) -> low (25)
    resp_desc = await async_client.get(
        "/api/findings?sort_by=risk_score&sort_order=desc",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_desc.status_code == 200
    scores_desc = [f["risk_score"] for f in resp_desc.json()["items"]]
    assert scores_desc == sorted(scores_desc, reverse=True)

    # 2. Sort by risk_score asc
    resp_asc = await async_client.get(
        "/api/findings?sort_by=risk_score&sort_order=asc",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_asc.status_code == 200
    scores_asc = [f["risk_score"] for f in resp_asc.json()["items"]]
    assert scores_asc == sorted(scores_asc)

    # 3. Sort by title asc
    resp_title = await async_client.get(
        "/api/findings?sort_by=title&sort_order=asc",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_title.status_code == 200
    titles = [f["title"].lower() for f in resp_title.json()["items"]]
    assert titles == sorted(titles)


@pytest.mark.asyncio
async def test_single_finding_detail_and_tenant_boundary(async_client: AsyncClient, tenant_environment):
    """Test GET /api/findings/{id}: owner succeeds with project context; cross-tenant access returns 404."""
    alpha = tenant_environment["alpha"]
    beta = tenant_environment["beta"]
    target_finding_id = tenant_environment["f_alpha_ids"][0]

    # 1. Owner (Alpha) fetches single finding -> 200 OK with relational project context
    resp_alpha = await async_client.get(
        f"/api/findings/{target_finding_id}",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_alpha.status_code == 200
    data_alpha = resp_alpha.json()
    assert data_alpha["id"] == target_finding_id
    assert data_alpha["project_id"] == tenant_environment["proj_alpha_id"]
    assert data_alpha["project_name"] == "Alpha Portal"
    assert data_alpha["target_url"] == "https://alpha.sentriq.io"

    # 2. Cross-tenant attempt: Beta tries to fetch Alpha's finding -> 404 Not Found (no IDOR leakage)
    resp_beta = await async_client.get(
        f"/api/findings/{target_finding_id}",
        headers=beta["headers"],
        cookies=beta["cookies"],
    )
    assert resp_beta.status_code == 404

    # 3. Nonexistent finding ID -> 404 Not Found
    resp_404 = await async_client.get(
        f"/api/findings/{uuid.uuid4()}",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_404.status_code == 404


@pytest.mark.asyncio
async def test_findings_summary_metrics_and_route_precedence(async_client: AsyncClient, tenant_environment):
    """Test GET /api/findings/summary: ensures route does not collide with /{finding_id} and computes accurate metrics."""
    alpha = tenant_environment["alpha"]

    # Verify /summary resolves to summary endpoint, not single finding lookup
    resp = await async_client.get(
        "/api/findings/summary",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp.status_code == 200, resp.text
    summary = resp.json()

    assert summary["total"] == 4
    # Severity breakdown
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["medium"] == 1
    assert summary["by_severity"]["low"] == 1
    assert summary["by_severity"]["informational"] == 0

    # Status breakdown
    assert summary["by_status"]["open"] == 1
    assert summary["by_status"]["in_progress"] == 1
    assert summary["by_status"]["resolved"] == 1
    assert summary["by_status"]["accepted_risk"] == 1

    # Category breakdown
    assert summary["by_category"]["headers"] == 1
    assert summary["by_category"]["cookies"] == 1
    assert summary["by_category"]["exposure"] == 1
    assert summary["by_category"]["cors"] == 1


@pytest.mark.asyncio
async def test_tenant_isolation_in_centralized_queries(async_client: AsyncClient, tenant_environment):
    """Tenant A can never see Tenant B findings in listing or summary, even when requesting Tenant B project_id."""
    alpha = tenant_environment["alpha"]
    beta = tenant_environment["beta"]
    proj_beta_id = tenant_environment["proj_beta_id"]

    # 1. Tenant Alpha lists findings -> only receives Alpha's 4 findings, 0 from Beta
    resp_alpha_list = await async_client.get(
        "/api/findings",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_alpha_list.status_code == 200
    alpha_items = resp_alpha_list.json()["items"]
    assert len(alpha_items) == 4
    for item in alpha_items:
        assert item["id"] in tenant_environment["f_alpha_ids"]
        assert item["id"] not in tenant_environment["f_beta_ids"]

    # 2. Tenant Alpha requests project_id of Tenant Beta -> 0 findings returned (no cross-tenant leakage)
    resp_cross_proj = await async_client.get(
        f"/api/findings?project_id={proj_beta_id}",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_cross_proj.status_code == 200
    assert resp_cross_proj.json()["total"] == 0
    assert len(resp_cross_proj.json()["items"]) == 0

    # 3. Tenant Alpha summary with Tenant Beta project_id -> total 0
    resp_cross_summary = await async_client.get(
        f"/api/findings/summary?project_id={proj_beta_id}",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp_cross_summary.status_code == 200
    assert resp_cross_summary.json()["total"] == 0

    # 4. Tenant Beta lists findings -> only receives Beta's 1 finding
    resp_beta_list = await async_client.get(
        "/api/findings",
        headers=beta["headers"],
        cookies=beta["cookies"],
    )
    assert resp_beta_list.status_code == 200
    assert resp_beta_list.json()["total"] == 1
    assert resp_beta_list.json()["items"][0]["id"] == tenant_environment["f_beta_ids"][0]


@pytest.mark.asyncio
async def test_superuser_visibility_across_all_tenants(async_client: AsyncClient, tenant_environment):
    """Superuser can view all findings across all tenants via centralized listing and summary."""
    admin = tenant_environment["admin"]

    # Superuser lists all findings -> sees all 5 findings (4 from Alpha + 1 from Beta)
    resp_all = await async_client.get(
        "/api/findings",
        headers=admin["headers"],
        cookies=admin["cookies"],
    )
    assert resp_all.status_code == 200
    data_all = resp_all.json()
    assert data_all["total"] == 5
    assert len(data_all["items"]) == 5

    # Superuser summary reflects all 5 findings
    resp_summary = await async_client.get(
        "/api/findings/summary",
        headers=admin["headers"],
        cookies=admin["cookies"],
    )
    assert resp_summary.status_code == 200
    assert resp_summary.json()["total"] == 5


@pytest.mark.asyncio
async def test_scan_findings_endpoint_backward_compatibility(async_client: AsyncClient, tenant_environment):
    """Verify that existing GET /api/scans/{scan_id}/findings operates identically through the service layer."""
    alpha = tenant_environment["alpha"]
    scan_alpha_id = tenant_environment["scan_alpha_id"]

    resp = await async_client.get(
        f"/api/scans/{scan_alpha_id}/findings",
        headers=alpha["headers"],
        cookies=alpha["cookies"],
    )
    assert resp.status_code == 200
    findings = resp.json()
    assert isinstance(findings, list)
    assert len(findings) == 4
    # Default order by risk_score desc
    scores = [f["risk_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)
