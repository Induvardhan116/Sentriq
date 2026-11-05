import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy import select, update

from app.models.user import User, UserSession
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.database.session import AsyncSessionLocal
from app.services.email_service import test_outbox
from app.config import get_settings

settings = get_settings()


@pytest.fixture(autouse=True)
def clean_outbox():
    """Ensure test outbox is cleared before each test."""
    test_outbox.clear()
    yield
    test_outbox.clear()


# =====================================================================
# 1. Verification Restriction Tests for Unverified Accounts
# =====================================================================

@pytest.mark.asyncio
async def test_unverified_user_cannot_create_project(async_client: AsyncClient):
    """Unverified users must be strictly blocked from creating projects with HTTP 403."""
    email = f"unverified_proj_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!", "full_name": "Unverified Tester"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201
    assert reg_resp.json()["is_verified"] is False
    csrf_token = reg_resp.json()["csrf_token"]
    cookie = reg_resp.cookies.get(settings.SESSION_COOKIE_NAME)

    # Attempt to create project directly via API
    create_resp = await async_client.post(
        "/api/projects",
        json={
            "name": "Forbidden Project",
            "target_url": "https://forbidden.example.com",
            "authorization_confirmed": True,
        },
        cookies={settings.SESSION_COOKIE_NAME: cookie},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
    )
    assert create_resp.status_code == 403
    assert "Email verification required" in create_resp.json()["detail"]


@pytest.mark.asyncio
async def test_unverified_user_cannot_launch_scan(async_client: AsyncClient):
    """Unverified users must be strictly blocked from starting scans with HTTP 403."""
    email = f"unverified_scan_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]
    csrf_token = reg_resp.json()["csrf_token"]
    cookie = reg_resp.cookies.get(settings.SESSION_COOKIE_NAME)

    # Insert a project owned by this user directly in DB
    proj_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        proj = Project(
            id=proj_id,
            name="Existing Target",
            target_url="https://existing.example.com",
            authorization_confirmed=True,
            owner_id=user_id,
        )
        session.add(proj)
        await session.commit()

    # Attempt to trigger scan while unverified
    scan_resp = await async_client.post(
        f"/api/projects/{proj_id}/scans",
        cookies={settings.SESSION_COOKIE_NAME: cookie},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
    )
    assert scan_resp.status_code == 403
    assert "Email verification required" in scan_resp.json()["detail"]


@pytest.mark.asyncio
async def test_unverified_user_cannot_access_restricted_investigation_features(async_client: AsyncClient):
    """Unverified users must be blocked from updating findings, viewing history, or mutating projects."""
    email = f"unverified_inv_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]
    csrf_token = reg_resp.json()["csrf_token"]
    cookie = reg_resp.cookies.get(settings.SESSION_COOKIE_NAME)
    headers = {"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token}
    cookies = {settings.SESSION_COOKIE_NAME: cookie}

    # Setup project, scan, and finding in DB
    proj_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())

    async with AsyncSessionLocal() as session:
        proj = Project(
            id=proj_id,
            name="Investigation Target",
            target_url="https://target.example.com",
            authorization_confirmed=True,
            owner_id=user_id,
        )
        session.add(proj)
        scan = Scan(
            id=scan_id,
            project_id=proj_id,
            target_url="https://target.example.com",
            status="completed",
            started_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        finding = Finding(
            id=finding_id,
            scan_id=scan_id,
            title="Investigation Vulnerability",
            description="Detail",
            category="Security Headers",
            severity="high",
            confidence=0.9,
            risk_score=75,
            status="open",
            fingerprint="fp-inv-001",
        )
        session.add(finding)
        await session.commit()

    # 1. Blocked from updating finding status
    patch_finding = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "resolved", "justification": "Fixed in code"},
        cookies=cookies,
        headers=headers,
    )
    assert patch_finding.status_code == 403
    assert "Email verification required" in patch_finding.json()["detail"]

    # 2. Blocked from viewing finding audit history
    hist_resp = await async_client.get(
        f"/api/findings/{finding_id}/history",
        cookies=cookies,
    )
    assert hist_resp.status_code == 403
    assert "Email verification required" in hist_resp.json()["detail"]

    # 3. Blocked from updating project
    update_proj = await async_client.patch(
        f"/api/projects/{proj_id}",
        json={"name": "Renamed Project"},
        cookies=cookies,
        headers=headers,
    )
    assert update_proj.status_code == 403
    assert "Email verification required" in update_proj.json()["detail"]

    # 4. Blocked from deleting project
    delete_proj = await async_client.delete(
        f"/api/projects/{proj_id}",
        cookies=cookies,
        headers=headers,
    )
    assert delete_proj.status_code == 403
    assert "Email verification required" in delete_proj.json()["detail"]


# =====================================================================
# 2. Verification Flow & Subsequent Access Activation
# =====================================================================

@pytest.mark.asyncio
async def test_unverified_user_can_verify_and_gain_full_access(async_client: AsyncClient):
    """After confirming verification, user becomes verified in database and gains access to all restricted operations."""
    email = f"activate_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201
    csrf_token = reg_resp.json()["csrf_token"]
    cookie = reg_resp.cookies.get(settings.SESSION_COOKIE_NAME)
    headers = {"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token}
    cookies = {settings.SESSION_COOKIE_NAME: cookie}

    # Step 1: User is unverified -> blocked from creating project
    blocked_resp = await async_client.post(
        "/api/projects",
        json={"name": "Blocked Alpha", "target_url": "https://alpha.com", "authorization_confirmed": True},
        cookies=cookies,
        headers=headers,
    )
    assert blocked_resp.status_code == 403

    # Step 2: Retrieve verification token from outbox and confirm verification
    raw_token = test_outbox.get_latest_token_for(email)
    assert raw_token is not None

    confirm_resp = await async_client.post(
        "/api/auth/verify-email/confirm",
        json={"token": raw_token},
        headers=headers,
    )
    assert confirm_resp.status_code == 200
    assert "verified successfully" in confirm_resp.json()["message"]

    # Verify session profile reflects verified state
    me_resp = await async_client.get("/api/auth/me", cookies=cookies)
    assert me_resp.status_code == 200
    assert me_resp.json()["is_verified"] is True

    # Step 3: Same user can now create project successfully!
    allowed_resp = await async_client.post(
        "/api/projects",
        json={"name": "Activated Alpha", "target_url": "https://alpha.com", "authorization_confirmed": True},
        cookies=cookies,
        headers=headers,
    )
    assert allowed_resp.status_code == 201
    proj_id = allowed_resp.json()["id"]

    # Step 4: Same user can trigger scan
    scan_resp = await async_client.post(
        f"/api/projects/{proj_id}/scans",
        cookies=cookies,
        headers=headers,
    )
    assert scan_resp.status_code == 202


# =====================================================================
# 3. Existing User Preservation & Multi-Tenant Isolation
# =====================================================================

@pytest.mark.asyncio
async def test_existing_verified_users_remain_unaffected(async_client: AsyncClient):
    """Existing users migrated with is_verified=True retain complete normal access."""
    email = f"legacy_{uuid.uuid4().hex[:8]}@sentriq.io"
    # Register and manually simulate migrated legacy verified user
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "LegacyPassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201
    csrf_token = reg_resp.json()["csrf_token"]
    cookie = reg_resp.cookies.get(settings.SESSION_COOKIE_NAME)

    # Mark user verified directly in database (as done by database migration DEFAULT 1)
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.email == email).values(is_verified=True))
        await session.commit()

    # Legacy verified user creates project without any restriction
    proj_resp = await async_client.post(
        "/api/projects",
        json={"name": "Legacy Project", "target_url": "https://legacy.com", "authorization_confirmed": True},
        cookies={settings.SESSION_COOKIE_NAME: cookie},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
    )
    assert proj_resp.status_code == 201


@pytest.mark.asyncio
async def test_multi_tenant_isolation_unverified_and_verified_cross_tenant_access_prevented(async_client: AsyncClient):
    """Verify tenant isolation: User A's data is never accessible or mutable by User B."""
    headers = {"Origin": "http://localhost:5173"}

    # User A (verified)
    email_a = f"tenant_a_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp_a = await async_client.post(
        "/api/auth/register",
        json={"email": email_a, "password": "PasswordUserA123!"},
        headers=headers,
    )
    assert resp_a.status_code == 201
    cookie_a = resp_a.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_a = resp_a.json()["csrf_token"]
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.email == email_a).values(is_verified=True))
        await session.commit()

    # User A creates project
    proj_a = await async_client.post(
        "/api/projects",
        json={"name": "Tenant A Project", "target_url": "https://tenanta.com", "authorization_confirmed": True},
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_a},
    )
    assert proj_a.status_code == 201
    proj_a_id = proj_a.json()["id"]

    # User B (verified)
    email_b = f"tenant_b_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp_b = await async_client.post(
        "/api/auth/register",
        json={"email": email_b, "password": "PasswordUserB123!"},
        headers=headers,
    )
    assert resp_b.status_code == 201
    cookie_b = resp_b.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_b = resp_b.json()["csrf_token"]
    async with AsyncSessionLocal() as session:
        await session.execute(update(User).where(User.email == email_b).values(is_verified=True))
        await session.commit()

    # User B attempts to view or update User A's project -> 404 Not Found (IDOR defense)
    get_cross = await async_client.get(
        f"/api/projects/{proj_a_id}",
        cookies={settings.SESSION_COOKIE_NAME: cookie_b},
    )
    assert get_cross.status_code == 404

    patch_cross = await async_client.patch(
        f"/api/projects/{proj_a_id}",
        json={"name": "Hijacked Name"},
        cookies={settings.SESSION_COOKIE_NAME: cookie_b},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_b},
    )
    assert patch_cross.status_code == 404

    delete_cross = await async_client.delete(
        f"/api/projects/{proj_a_id}",
        cookies={settings.SESSION_COOKIE_NAME: cookie_b},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_b},
    )
    assert delete_cross.status_code == 404


# =====================================================================
# 4. Matrix Regression: AUTH_ENABLED=True vs False & Authenticated vs Unauthenticated
# =====================================================================

@pytest.mark.asyncio
async def test_auth_enabled_true_unauthenticated_requests_strictly_blocked(async_client: AsyncClient):
    """When AUTH_ENABLED=True, all protected endpoints strictly reject unauthenticated requests with HTTP 401."""
    # Seed a project, scan, and finding directly in database
    proj_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        p = Project(id=proj_id, name="Test P", target_url="https://test.com", authorization_confirmed=True)
        s = Scan(id=scan_id, project_id=proj_id, target_url="https://test.com", status="completed")
        f = Finding(id=finding_id, scan_id=scan_id, title="Test F", description="D", category="web", severity="high", status="open", version=1)
        session.add_all([p, s, f])
        await session.commit()

    # 1. Project creation -> 401
    r_create = await async_client.post("/api/projects", json={"name": "P", "target_url": "https://test.com", "authorization_confirmed": True})
    assert r_create.status_code == 401

    # 2. Scan triggering -> 401
    r_scan = await async_client.post(f"/api/projects/{proj_id}/scans")
    assert r_scan.status_code == 401

    # 3. Project update -> 401
    r_patch_p = await async_client.patch(f"/api/projects/{proj_id}", json={"name": "New Name"})
    assert r_patch_p.status_code == 401

    # 4. Project delete -> 401
    r_del_p = await async_client.delete(f"/api/projects/{proj_id}")
    assert r_del_p.status_code == 401

    # 5. Project claim -> 401
    r_claim = await async_client.post(f"/api/projects/{proj_id}/claim")
    assert r_claim.status_code == 401

    # 6. Finding status update -> 401
    r_patch_f = await async_client.patch(f"/api/findings/{finding_id}", json={"status": "resolved", "justification": "Fixed"})
    assert r_patch_f.status_code == 401

    # 7. Finding audit history -> 401
    r_hist = await async_client.get(f"/api/findings/{finding_id}/history")
    assert r_hist.status_code == 401


@pytest.mark.asyncio
async def test_auth_enabled_true_authenticated_unverified_requests_strictly_blocked(async_client: AsyncClient):
    """When AUTH_ENABLED=True, authenticated unverified users are strictly blocked with HTTP 403 on all protected endpoints."""
    # Register new user (defaults to is_verified=False)
    email = f"unverified_matrix_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "Password123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg.status_code == 201
    user_id = reg.json()["id"]
    csrf = reg.json()["csrf_token"]
    cookie = reg.cookies.get(settings.SESSION_COOKIE_NAME)
    headers = {"Origin": "http://localhost:5173", "X-CSRF-Token": csrf}
    cookies = {settings.SESSION_COOKIE_NAME: cookie}

    # Seed project, scan, and finding owned by this user
    proj_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        p = Project(id=proj_id, name="Unverified P", target_url="https://test.com", authorization_confirmed=True, owner_id=user_id)
        s = Scan(id=scan_id, project_id=proj_id, target_url="https://test.com", status="completed")
        f = Finding(id=finding_id, scan_id=scan_id, title="Test F", description="D", category="web", severity="high", status="open", version=1)
        session.add_all([p, s, f])
        await session.commit()

    # 1. Project creation -> 403
    r1 = await async_client.post("/api/projects", json={"name": "Blocked", "target_url": "https://test.com", "authorization_confirmed": True}, cookies=cookies, headers=headers)
    assert r1.status_code == 403
    assert "Email verification required" in r1.json()["detail"]

    # 2. Scan trigger -> 403
    r2 = await async_client.post(f"/api/projects/{proj_id}/scans", cookies=cookies, headers=headers)
    assert r2.status_code == 403
    assert "Email verification required" in r2.json()["detail"]

    # 3. Project update -> 403
    r3 = await async_client.patch(f"/api/projects/{proj_id}", json={"name": "New"}, cookies=cookies, headers=headers)
    assert r3.status_code == 403
    assert "Email verification required" in r3.json()["detail"]

    # 4. Project delete -> 403
    r4 = await async_client.delete(f"/api/projects/{proj_id}", cookies=cookies, headers=headers)
    assert r4.status_code == 403
    assert "Email verification required" in r4.json()["detail"]

    # 5. Project claim -> 403
    r5 = await async_client.post(f"/api/projects/{proj_id}/claim", cookies=cookies, headers=headers)
    assert r5.status_code == 403
    assert "Email verification required" in r5.json()["detail"]

    # 6. Finding status update -> 403
    r6 = await async_client.patch(f"/api/findings/{finding_id}", json={"status": "resolved", "justification": "Fixed"}, cookies=cookies, headers=headers)
    assert r6.status_code == 403
    assert "Email verification required" in r6.json()["detail"]

    # 7. Finding audit history -> 403
    r7 = await async_client.get(f"/api/findings/{finding_id}/history", cookies=cookies)
    assert r7.status_code == 403
    assert "Email verification required" in r7.json()["detail"]


@pytest.mark.asyncio
async def test_auth_enabled_false_authenticated_unverified_strictly_blocked(async_client: AsyncClient):
    """When AUTH_ENABLED=False, authenticated requests from unverified users still strictly receive HTTP 403."""
    from unittest.mock import patch
    from app.config import Settings

    # Register an unverified user while auth is active
    email = f"unverified_dev_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "Password123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg.status_code == 201
    user_id = reg.json()["id"]
    csrf = reg.json()["csrf_token"]
    cookie = reg.cookies.get(settings.SESSION_COOKIE_NAME)
    cookies = {settings.SESSION_COOKIE_NAME: cookie}
    headers = {"Origin": "http://localhost:5173", "X-CSRF-Token": csrf}

    # Seed project, scan, finding
    proj_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        p = Project(id=proj_id, name="Dev Unverified P", target_url="https://test.com", authorization_confirmed=True, owner_id=user_id)
        s = Scan(id=scan_id, project_id=proj_id, target_url="https://test.com", status="completed")
        f = Finding(id=finding_id, scan_id=scan_id, title="Test F", description="D", category="web", severity="high", status="open", version=1)
        session.add_all([p, s, f])
        await session.commit()

    dev_settings = Settings(ENVIRONMENT="development", AUTH_ENABLED=False)
    with patch("app.security.deps.settings", dev_settings), \
         patch("app.api.projects.settings", dev_settings), \
         patch("app.services.finding_service.settings", dev_settings):

        # Authenticated with unverified session -> MUST strictly return 403 Forbidden
        r1 = await async_client.post("/api/projects", json={"name": "Dev Blocked", "target_url": "https://test.com", "authorization_confirmed": True}, cookies=cookies, headers=headers)
        assert r1.status_code == 403
        assert "Email verification required" in r1.json()["detail"]

        r2 = await async_client.post(f"/api/projects/{proj_id}/scans", cookies=cookies, headers=headers)
        assert r2.status_code == 403
        assert "Email verification required" in r2.json()["detail"]

        r3 = await async_client.patch(f"/api/projects/{proj_id}", json={"name": "New"}, cookies=cookies, headers=headers)
        assert r3.status_code == 403
        assert "Email verification required" in r3.json()["detail"]

        r4 = await async_client.delete(f"/api/projects/{proj_id}", cookies=cookies, headers=headers)
        assert r4.status_code == 403
        assert "Email verification required" in r4.json()["detail"]

        r5 = await async_client.post(f"/api/projects/{proj_id}/claim", cookies=cookies, headers=headers)
        assert r5.status_code == 403
        assert "Email verification required" in r5.json()["detail"]

        r6 = await async_client.patch(f"/api/findings/{finding_id}", json={"status": "resolved", "justification": "Fixed"}, cookies=cookies, headers=headers)
        assert r6.status_code == 403
        assert "Email verification required" in r6.json()["detail"]

        r7 = await async_client.get(f"/api/findings/{finding_id}/history", cookies=cookies)
        assert r7.status_code == 403
        assert "Email verification required" in r7.json()["detail"]


@pytest.mark.asyncio
async def test_auth_enabled_false_unauthenticated_dev_mode_behavior(async_client: AsyncClient):
    """When AUTH_ENABLED=False, unauthenticated requests exercise local development fallback."""
    from unittest.mock import patch
    from app.config import Settings

    dev_settings = Settings(ENVIRONMENT="development", AUTH_ENABLED=False)
    with patch("app.security.deps.settings", dev_settings), \
         patch("app.api.projects.settings", dev_settings), \
         patch("app.services.finding_service.settings", dev_settings):

        # 1. Unauthenticated project creation -> 201 Created (owner_id is None)
        create_resp = await async_client.post(
            "/api/projects",
            json={"name": "Unauth Dev Target", "target_url": "https://unauth-dev.example.com", "authorization_confirmed": True},
        )
        assert create_resp.status_code == 201
        proj_data = create_resp.json()
        assert proj_data["owner_id"] is None
        proj_id = proj_data["id"]

        # 2. Unauthenticated project update -> 200 OK
        patch_resp = await async_client.patch(
            f"/api/projects/{proj_id}",
            json={"name": "Renamed Unauth Target"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["name"] == "Renamed Unauth Target"

        # 3. Unauthenticated scan trigger -> 202 Accepted
        scan_resp = await async_client.post(f"/api/projects/{proj_id}/scans")
        assert scan_resp.status_code == 202
        scan_id = scan_resp.json()["id"]

        # Seed a finding for the scan
        finding_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            f = Finding(id=finding_id, scan_id=scan_id, title="Dev F", description="D", category="web", severity="medium", status="open", version=1)
            session.add(f)
            await session.commit()

        # 4. Unauthenticated finding status update -> 200 OK (audit event recorded with user_id=None)
        f_patch = await async_client.patch(
            f"/api/findings/{finding_id}",
            json={"status": "resolved", "justification": "Resolved in local dev"},
        )
        assert f_patch.status_code == 200

        # 5. Unauthenticated finding audit history -> 200 OK
        f_hist = await async_client.get(f"/api/findings/{finding_id}/history")
        assert f_hist.status_code == 200
        assert len(f_hist.json()) >= 1
        assert f_hist.json()[0]["user_id"] is None

        # 6. Unauthenticated project claim -> strictly 401 Unauthorized (claim requires a user identity)
        claim_resp = await async_client.post(f"/api/projects/{proj_id}/claim")
        assert claim_resp.status_code == 401

        # 7. Unauthenticated project delete -> 200 OK
        del_resp = await async_client.delete(f"/api/projects/{proj_id}")
        assert del_resp.status_code == 200


