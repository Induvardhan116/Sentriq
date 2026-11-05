import asyncio
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from app.main import app
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


async def create_test_user_session(
    email: str,
    is_superuser: bool = False,
    is_active: bool = True,
    is_verified: bool = True,
) -> tuple[User, str, str]:
    """Helper creating user in database and returning (user, session_token, csrf_token)."""
    async with AsyncSessionLocal() as session:
        user = User(
            email=email.strip().lower(),
            hashed_password=hash_password("SuperSecret2026!"),
            full_name=f"User {email}",
            is_active=is_active,
            is_superuser=is_superuser,
            is_verified=is_verified,
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
            user_agent="Sentriq-Isolation-Test",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            revoked_at=None,
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user)
        return user, raw_session_token, csrf_token


def make_auth_headers(csrf_token: str) -> dict:
    return {
        "Origin": "http://localhost:5173",
        "X-CSRF-Token": csrf_token,
    }


def make_auth_cookies(raw_session_token: str) -> dict:
    return {
        settings.SESSION_COOKIE_NAME: raw_session_token,
    }


# =====================================================================
# 1. Unauthenticated Requests Rejected when AUTH_ENABLED=True
# =====================================================================

@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected_when_auth_enabled(async_client: AsyncClient):
    """When AUTH_ENABLED=True, all protected endpoints reject unauthenticated calls with 401."""
    # Project endpoints
    r1 = await async_client.get("/api/projects")
    assert r1.status_code == 401
    assert "WWW-Authenticate" in r1.headers

    r2 = await async_client.post("/api/projects", json={"name": "P", "target_url": "https://example.com", "authorization_confirmed": True})
    assert r2.status_code == 401

    r3 = await async_client.get("/api/projects/any-uuid")
    assert r3.status_code == 401

    r4 = await async_client.patch("/api/projects/any-uuid", json={"name": "New Name"})
    assert r4.status_code == 401

    r5 = await async_client.delete("/api/projects/any-uuid")
    assert r5.status_code == 401

    r6 = await async_client.post("/api/projects/any-uuid/scans")
    assert r6.status_code == 401

    r7 = await async_client.post("/api/projects/any-uuid/claim")
    assert r7.status_code == 401

    # Scan endpoints
    r8 = await async_client.get("/api/scans/any-uuid")
    assert r8.status_code == 401

    r9 = await async_client.get("/api/scans/any-uuid/findings")
    assert r9.status_code == 401

    r10 = await async_client.get("/api/scans/any-uuid/summary")
    assert r10.status_code == 401

    # Finding endpoint
    r11 = await async_client.patch("/api/findings/any-uuid", json={"status": "resolved"})
    assert r11.status_code == 401


# =====================================================================
# 2. Project Listing Strictly Scoped to Owner
# =====================================================================

@pytest.mark.asyncio
async def test_project_listing_strictly_scoped_to_owner(async_client: AsyncClient):
    """Users only receive projects where project.owner_id == user.id."""
    user_a, token_a, csrf_a = await create_test_user_session("tenant_a@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("tenant_b@sentriq.io")

    # User A creates 2 projects
    resp_a1 = await async_client.post(
        "/api/projects",
        json={"name": "Project A1", "target_url": "https://a1.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    assert resp_a1.status_code == 201
    p_a1_id = resp_a1.json()["id"]

    resp_a2 = await async_client.post(
        "/api/projects",
        json={"name": "Project A2", "target_url": "https://a2.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    assert resp_a2.status_code == 201
    p_a2_id = resp_a2.json()["id"]

    # User B creates 1 project
    resp_b1 = await async_client.post(
        "/api/projects",
        json={"name": "Project B1", "target_url": "https://b1.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_b),
        cookies=make_auth_cookies(token_b),
    )
    assert resp_b1.status_code == 201
    p_b1_id = resp_b1.json()["id"]

    # User A lists projects -> strictly sees A1 and A2, never B1
    list_a = await async_client.get(
        "/api/projects",
        cookies=make_auth_cookies(token_a),
    )
    assert list_a.status_code == 200
    ids_a = [p["id"] for p in list_a.json()]
    assert p_a1_id in ids_a
    assert p_a2_id in ids_a
    assert p_b1_id not in ids_a

    # User B lists projects -> strictly sees B1, never A1 or A2
    list_b = await async_client.get(
        "/api/projects",
        cookies=make_auth_cookies(token_b),
    )
    assert list_b.status_code == 200
    ids_b = [p["id"] for p in list_b.json()]
    assert p_b1_id in ids_b
    assert p_a1_id not in ids_b
    assert p_a2_id not in ids_b


# =====================================================================
# 3. Cross-User Project Access, Edit, and Deletion Returns 404 (Anti-IDOR)
# =====================================================================

@pytest.mark.asyncio
async def test_cross_user_project_access_returns_404(async_client: AsyncClient):
    """User B attempting to read User A's project receives 404 Not Found."""
    user_a, token_a, csrf_a = await create_test_user_session("owner_a@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("intruder_b@sentriq.io")

    # User A creates Project A
    resp = await async_client.post(
        "/api/projects",
        json={"name": "Secret Project A", "target_url": "https://secret.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    proj_id = resp.json()["id"]

    # User B attempts to read Project A -> 404 Not Found
    read_resp = await async_client.get(
        f"/api/projects/{proj_id}",
        cookies=make_auth_cookies(token_b),
    )
    assert read_resp.status_code == 404
    assert f"Project with ID '{proj_id}' does not exist." in read_resp.json()["detail"]


@pytest.mark.asyncio
async def test_cross_user_project_editing_returns_404(async_client: AsyncClient):
    """User B attempting to edit User A's project receives 404 and project remains unchanged."""
    user_a, token_a, csrf_a = await create_test_user_session("editor_owner@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("editor_intruder@sentriq.io")

    resp = await async_client.post(
        "/api/projects",
        json={"name": "Original Name", "target_url": "https://original.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    proj_id = resp.json()["id"]

    # User B attempts to rename Project A
    edit_resp = await async_client.patch(
        f"/api/projects/{proj_id}",
        json={"name": "Hacked Project Name"},
        headers=make_auth_headers(csrf_b),
        cookies=make_auth_cookies(token_b),
    )
    assert edit_resp.status_code == 404

    # Verify project in DB was untouched
    async with AsyncSessionLocal() as session:
        proj = await session.scalar(select(Project).where(Project.id == proj_id))
        assert proj.name == "Original Name"


@pytest.mark.asyncio
async def test_cross_user_project_deletion_returns_404(async_client: AsyncClient):
    """User B attempting to delete User A's project receives 404 and project is not deleted."""
    user_a, token_a, csrf_a = await create_test_user_session("del_owner@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("del_intruder@sentriq.io")

    resp = await async_client.post(
        "/api/projects",
        json={"name": "Preserved Project", "target_url": "https://preserve.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    proj_id = resp.json()["id"]

    # User B attempts to delete Project A
    del_resp = await async_client.delete(
        f"/api/projects/{proj_id}",
        headers=make_auth_headers(csrf_b),
        cookies=make_auth_cookies(token_b),
    )
    assert del_resp.status_code == 404

    # Project still exists in DB
    async with AsyncSessionLocal() as session:
        proj = await session.scalar(select(Project).where(Project.id == proj_id))
        assert proj is not None


# =====================================================================
# 4. Cross-User Scan and Finding Isolation
# =====================================================================

@pytest.mark.asyncio
async def test_cross_user_scan_creation_returns_404(async_client: AsyncClient):
    """User B cannot trigger scans against User A's project."""
    user_a, token_a, csrf_a = await create_test_user_session("scan_owner@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("scan_intruder@sentriq.io")

    resp = await async_client.post(
        "/api/projects",
        json={"name": "Scan Target", "target_url": "https://scantest.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    proj_id = resp.json()["id"]

    # User B attempts to trigger scan on Project A
    trigger_resp = await async_client.post(
        f"/api/projects/{proj_id}/scans",
        headers=make_auth_headers(csrf_b),
        cookies=make_auth_cookies(token_b),
    )
    assert trigger_resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_user_scan_reading_and_findings_returns_404(async_client: AsyncClient):
    """User B cannot view User A's scan details, findings, or summary."""
    user_a, token_a, csrf_a = await create_test_user_session("scan_data_owner@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("scan_data_intruder@sentriq.io")

    # User A creates project and seeds a scan + finding
    async with AsyncSessionLocal() as session:
        proj = Project(name="Project With Scan", target_url="https://scanfindings.example.com", authorization_confirmed=True, owner_id=user_a.id)
        session.add(proj)
        await session.flush()

        scan = Scan(project_id=proj.id, target_url=proj.target_url, status="completed", overall_score=85, score_grade="B")
        session.add(scan)
        await session.flush()

        finding = Finding(
            scan_id=scan.id,
            category="Security Headers",
            title="Missing HSTS",
            description="Strict-Transport-Security header is missing",
            severity="medium",
            risk_score=40,
            status="open",
        )
        session.add(finding)
        await session.commit()
        scan_id = scan.id
        finding_id = finding.id

    # User B attempts to view Scan A -> 404
    r1 = await async_client.get(f"/api/scans/{scan_id}", cookies=make_auth_cookies(token_b))
    assert r1.status_code == 404

    # User B attempts to view Scan A findings -> 404
    r2 = await async_client.get(f"/api/scans/{scan_id}/findings", cookies=make_auth_cookies(token_b))
    assert r2.status_code == 404

    # User B attempts to view Scan A summary -> 404
    r3 = await async_client.get(f"/api/scans/{scan_id}/summary", cookies=make_auth_cookies(token_b))
    assert r3.status_code == 404

    # User B attempts to update finding status -> 404
    r4 = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "resolved"},
        headers=make_auth_headers(csrf_b),
        cookies=make_auth_cookies(token_b),
    )
    assert r4.status_code == 404

    # User A (owner) CAN view scan, findings, summary, and update finding status -> 200
    r_owner_scan = await async_client.get(f"/api/scans/{scan_id}", cookies=make_auth_cookies(token_a))
    assert r_owner_scan.status_code == 200

    r_owner_findings = await async_client.get(f"/api/scans/{scan_id}/findings", cookies=make_auth_cookies(token_a))
    assert r_owner_findings.status_code == 200
    assert len(r_owner_findings.json()) == 1

    r_owner_patch = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "resolved"},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    assert r_owner_patch.status_code == 200
    assert r_owner_patch.json()["status"] == "resolved"


# =====================================================================
# 5. Superuser Controls & SSRF Invariant Preservation
# =====================================================================

@pytest.mark.asyncio
async def test_superuser_can_access_and_manage_all_tenant_resources(async_client: AsyncClient):
    """Superuser has administrative oversight across all tenant projects, scans, and findings."""
    user_a, token_a, csrf_a = await create_test_user_session("tenant_regular@sentriq.io", is_superuser=False)
    superuser, super_token, super_csrf = await create_test_user_session("admin_super@sentriq.io", is_superuser=True)

    # Regular user creates a project and scan
    async with AsyncSessionLocal() as session:
        proj = Project(name="Tenant A Project", target_url="https://tenant-a.example.com", authorization_confirmed=True, owner_id=user_a.id)
        session.add(proj)
        await session.flush()

        scan = Scan(project_id=proj.id, target_url=proj.target_url, status="completed", overall_score=90, score_grade="A")
        session.add(scan)
        await session.flush()

        finding = Finding(scan_id=scan.id, category="SSL", title="Weak Cipher", description="Test", severity="low", risk_score=20, status="open")
        session.add(finding)
        await session.commit()
        proj_id = proj.id
        scan_id = scan.id
        finding_id = finding.id

    # Superuser lists projects -> sees User A's project
    super_list = await async_client.get("/api/projects", cookies=make_auth_cookies(super_token))
    assert super_list.status_code == 200
    assert any(p["id"] == proj_id for p in super_list.json())

    # Superuser reads project detail -> 200
    super_get = await async_client.get(f"/api/projects/{proj_id}", cookies=make_auth_cookies(super_token))
    assert super_get.status_code == 200
    assert super_get.json()["name"] == "Tenant A Project"

    # Superuser reads scan -> 200
    super_scan = await async_client.get(f"/api/scans/{scan_id}", cookies=make_auth_cookies(super_token))
    assert super_scan.status_code == 200

    # Superuser updates finding status -> 200
    super_patch = await async_client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "in_progress"},
        headers=make_auth_headers(super_csrf),
        cookies=make_auth_cookies(super_token),
    )
    assert super_patch.status_code == 200
    assert super_patch.json()["status"] == "in_progress"

    # Superuser deletes project -> 200
    super_del = await async_client.delete(
        f"/api/projects/{proj_id}",
        headers=make_auth_headers(super_csrf),
        cookies=make_auth_cookies(super_token),
    )
    assert super_del.status_code == 200


@pytest.mark.asyncio
async def test_superuser_privileges_never_bypass_ssrf_protection(async_client: AsyncClient):
    """Superusers are strictly constrained by SSRF validators and input rules."""
    superuser, super_token, super_csrf = await create_test_user_session("admin_ssrf@sentriq.io", is_superuser=True)

    # 1. Superuser attempts to create project targeting loopback / private IP
    r1 = await async_client.post(
        "/api/projects",
        json={"name": "Loopback SSRF", "target_url": "http://127.0.0.1:8000", "authorization_confirmed": True},
        headers=make_auth_headers(super_csrf),
        cookies=make_auth_cookies(super_token),
    )
    assert r1.status_code == 400
    assert "prohibited" in r1.json()["detail"].lower() or "private" in r1.json()["detail"].lower()

    # 2. Superuser attempts cloud metadata SSRF
    r2 = await async_client.post(
        "/api/projects",
        json={"name": "Metadata SSRF", "target_url": "http://169.254.169.254/latest/meta-data/", "authorization_confirmed": True},
        headers=make_auth_headers(super_csrf),
        cookies=make_auth_cookies(super_token),
    )
    assert r2.status_code == 400

    # 3. Superuser creates a valid project then attempts to update target URL to file scheme
    r3 = await async_client.post(
        "/api/projects",
        json={"name": "Valid Target", "target_url": "https://valid.example.com", "authorization_confirmed": True},
        headers=make_auth_headers(super_csrf),
        cookies=make_auth_cookies(super_token),
    )
    proj_id = r3.json()["id"]

    r4 = await async_client.patch(
        f"/api/projects/{proj_id}",
        json={"target_url": "file:///etc/shadow"},
        headers=make_auth_headers(super_csrf),
        cookies=make_auth_cookies(super_token),
    )
    assert r4.status_code == 400


# =====================================================================
# 6. Legacy Project Claiming (Atomic Conditional Update & Race Prevention)
# =====================================================================

@pytest.mark.asyncio
async def test_legacy_project_claim_workflow_and_unclaimed_restriction(async_client: AsyncClient):
    """Unclaimed legacy projects (owner_id IS NULL) are restricted from ordinary users until claimed."""
    user_a, token_a, csrf_a = await create_test_user_session("claimant_a@sentriq.io")
    user_b, token_b, csrf_b = await create_test_user_session("claimant_b@sentriq.io")
    superuser, super_token, super_csrf = await create_test_user_session("super_claim@sentriq.io", is_superuser=True)

    # Seed an unclaimed legacy project
    async with AsyncSessionLocal() as session:
        legacy_proj = Project(
            name="Legacy Project",
            target_url="https://legacy.example.com",
            authorization_confirmed=True,
            owner_id=None,
        )
        session.add(legacy_proj)
        await session.commit()
        legacy_id = legacy_proj.id

    # 1. When unclaimed, ordinary user gets 404 on reading or editing
    r_unclaimed_read = await async_client.get(f"/api/projects/{legacy_id}", cookies=make_auth_cookies(token_a))
    assert r_unclaimed_read.status_code == 404

    r_unclaimed_edit = await async_client.patch(
        f"/api/projects/{legacy_id}",
        json={"name": "Hijacked"},
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    assert r_unclaimed_edit.status_code == 404

    # 2. Superuser CAN see unclaimed project in list
    super_list = await async_client.get("/api/projects", cookies=make_auth_cookies(super_token))
    assert any(p["id"] == legacy_id for p in super_list.json())

    # 3. User A claims the legacy project -> 200 OK
    claim_resp = await async_client.post(
        f"/api/projects/{legacy_id}/claim",
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    assert claim_resp.status_code == 200
    assert claim_resp.json()["owner_id"] == user_a.id

    # 4. User A can now read and manage the claimed project
    r_owner_read = await async_client.get(f"/api/projects/{legacy_id}", cookies=make_auth_cookies(token_a))
    assert r_owner_read.status_code == 200

    # 5. User A attempting to claim again -> 400 Bad Request
    claim_again = await async_client.post(
        f"/api/projects/{legacy_id}/claim",
        headers=make_auth_headers(csrf_a),
        cookies=make_auth_cookies(token_a),
    )
    assert claim_again.status_code == 400
    assert "already claimed by you" in claim_again.json()["detail"].lower()

    # 6. User B attempting to claim already-claimed project receives 404 (eliminates tenant project enumeration)
    claim_b = await async_client.post(
        f"/api/projects/{legacy_id}/claim",
        headers=make_auth_headers(csrf_b),
        cookies=make_auth_cookies(token_b),
    )
    assert claim_b.status_code == 404
    assert f"Project with ID '{legacy_id}' does not exist." in claim_b.json()["detail"]


@pytest.mark.asyncio
async def test_simultaneous_legacy_project_claims_race_condition(async_client: AsyncClient):
    """Concurrent claim requests: exactly one succeeds with 200; the other receives 404."""
    user_1, token_1, csrf_1 = await create_test_user_session("race_user1@sentriq.io")
    user_2, token_2, csrf_2 = await create_test_user_session("race_user2@sentriq.io")

    # Seed unclaimed legacy project
    async with AsyncSessionLocal() as session:
        legacy_proj = Project(
            name="Race Legacy Project",
            target_url="https://race.example.com",
            authorization_confirmed=True,
            owner_id=None,
        )
        session.add(legacy_proj)
        await session.commit()
        legacy_id = legacy_proj.id

    # Fire 2 simultaneous claim requests
    req1 = async_client.post(
        f"/api/projects/{legacy_id}/claim",
        headers=make_auth_headers(csrf_1),
        cookies=make_auth_cookies(token_1),
    )
    req2 = async_client.post(
        f"/api/projects/{legacy_id}/claim",
        headers=make_auth_headers(csrf_2),
        cookies=make_auth_cookies(token_2),
    )

    resp1, resp2 = await asyncio.gather(req1, req2)
    statuses = {resp1.status_code, resp2.status_code}

    # Exactly one must be 200 (winner) and the other must be 404 (anti-enumeration)
    assert statuses == {200, 404}

    # Project in DB has a single owner
    async with AsyncSessionLocal() as session:
        proj = await session.scalar(select(Project).where(Project.id == legacy_id))
        assert proj.owner_id in (user_1.id, user_2.id)


# =====================================================================
# 7. Backward Compatibility with AUTH_ENABLED=False (Dev Mode)
# =====================================================================

@pytest.mark.asyncio
async def test_legacy_project_behavior_with_auth_disabled():
    """When AUTH_ENABLED=False, endpoints allow unauthenticated access for local dev."""
    from unittest.mock import patch
    from httpx import ASGITransport

    transport = ASGITransport(app=app)
    with patch("app.config.get_settings") as mock_settings:
        from app.config import Settings
        dev_settings = Settings(ENVIRONMENT="development", AUTH_ENABLED=False)
        mock_settings.return_value = dev_settings

        with patch("app.security.deps.settings", dev_settings), \
             patch("app.api.projects.settings", dev_settings):

            async with AsyncClient(transport=transport, base_url="http://test") as dev_client:
                # 1. Unauthenticated creation succeeds
                create_resp = await dev_client.post(
                    "/api/projects",
                    json={"name": "Dev Mode Project", "target_url": "https://dev.example.com", "authorization_confirmed": True},
                )
                assert create_resp.status_code == 201
                proj_data = create_resp.json()
                assert proj_data["owner_id"] is None
                proj_id = proj_data["id"]

                # 2. Unauthenticated list succeeds
                list_resp = await dev_client.get("/api/projects")
                assert list_resp.status_code == 200

                # 3. Unauthenticated read succeeds
                get_resp = await dev_client.get(f"/api/projects/{proj_id}")
                assert get_resp.status_code == 200

                # 4. Unauthenticated update succeeds
                update_resp = await dev_client.patch(
                    f"/api/projects/{proj_id}",
                    json={"name": "Updated Dev Name"},
                )
                assert update_resp.status_code == 200
                assert update_resp.json()["name"] == "Updated Dev Name"

                # 5. Unauthenticated delete succeeds
                del_resp = await dev_client.delete(f"/api/projects/{proj_id}")
                assert del_resp.status_code == 200


# =====================================================================
# 8. Database Integrity: Cascade Deletion & User Preservation
# =====================================================================

@pytest.mark.asyncio
async def test_project_deletion_cascades_scans_and_findings_without_deleting_user(async_client: AsyncClient):
    """Deleting a project removes all associated scans and findings, but never deletes user records."""
    user, token, csrf = await create_test_user_session("cascade_tester@sentriq.io")

    # Seed project, 2 scans, 3 findings
    async with AsyncSessionLocal() as session:
        proj = Project(name="Cascade Target", target_url="https://cascade.example.com", authorization_confirmed=True, owner_id=user.id)
        session.add(proj)
        await session.flush()

        s1 = Scan(project_id=proj.id, target_url=proj.target_url, status="completed")
        s2 = Scan(project_id=proj.id, target_url=proj.target_url, status="completed")
        session.add_all([s1, s2])
        await session.flush()

        f1 = Finding(scan_id=s1.id, category="Headers", title="F1", description="D1", severity="high", risk_score=70)
        f2 = Finding(scan_id=s1.id, category="Headers", title="F2", description="D2", severity="low", risk_score=20)
        f3 = Finding(scan_id=s2.id, category="SSL", title="F3", description="D3", severity="medium", risk_score=50)
        session.add_all([f1, f2, f3])
        await session.commit()
        proj_id = proj.id
        s1_id, s2_id = s1.id, s2.id
        f1_id, f2_id, f3_id = f1.id, f2.id, f3.id

    # Owner deletes project
    del_resp = await async_client.delete(
        f"/api/projects/{proj_id}",
        headers=make_auth_headers(csrf),
        cookies=make_auth_cookies(token),
    )
    assert del_resp.status_code == 200

    # Verify cascades in DB
    async with AsyncSessionLocal() as session:
        # Project deleted
        assert (await session.scalar(select(Project).where(Project.id == proj_id))) is None
        # Scans deleted
        assert (await session.scalar(select(Scan).where(Scan.id.in_([s1_id, s2_id])))) is None
        # Findings deleted
        assert (await session.scalar(select(Finding).where(Finding.id.in_([f1_id, f2_id, f3_id])))) is None
        # User PRESERVED
        user_check = await session.scalar(select(User).where(User.id == user.id))
        assert user_check is not None
        assert user_check.email == "cascade_tester@sentriq.io"
