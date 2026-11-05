import uuid
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient
from sqlalchemy import select, update

from app.models.user import User, UserSession, EmailVerificationToken, PasswordResetToken
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.database.session import AsyncSessionLocal
from app.services.email_service import test_outbox, hash_auth_token
from app.config import get_settings

settings = get_settings()


@pytest.fixture(autouse=True)
def clear_outbox():
    """Clear test outbox before each test run."""
    test_outbox.clear()
    yield
    test_outbox.clear()


# =====================================================================
# 1. Registration & Email Verification Tests
# =====================================================================

@pytest.mark.asyncio
async def test_registration_defaults_to_unverified_and_dispatches_email(async_client: AsyncClient):
    """New registrations must default to is_verified=False and dispatch an initial verification token."""
    email = f"unverified_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!", "full_name": "New User"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == email
    assert data["is_verified"] is False, "New registrations must default to is_verified=False"

    # Verify that initial verification email was queued in outbox
    token = test_outbox.get_latest_token_for(email)
    assert token is not None
    assert len(token) >= 32

    # Verify that token hash (not raw token) is in the database
    token_hash = hash_auth_token(token)
    async with AsyncSessionLocal() as session:
        record = await session.scalar(
            select(EmailVerificationToken).where(EmailVerificationToken.token_hash == token_hash)
        )
        assert record is not None
        assert record.is_consumed is False
        assert record.is_expired is False


@pytest.mark.asyncio
async def test_confirm_email_verification_success_and_replay_rejection(async_client: AsyncClient):
    """Valid verification token marks user verified; replaying consumed token is rejected."""
    email = f"verify_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201
    raw_token = test_outbox.get_latest_token_for(email)
    assert raw_token is not None

    # Confirm verification
    confirm_resp = await async_client.post(
        "/api/auth/verify-email/confirm",
        json={"token": raw_token},
        headers={"Origin": "http://localhost:5173"},
    )
    assert confirm_resp.status_code == 200
    assert "successfully" in confirm_resp.json()["message"]

    # Verify user is now verified in DB
    async with AsyncSessionLocal() as session:
        user = await session.scalar(select(User).where(User.email == email))
        assert user is not None
        assert user.is_verified is True

    # Replaying the same token must be rejected as already consumed
    replay_resp = await async_client.post(
        "/api/auth/verify-email/confirm",
        json={"token": raw_token},
        headers={"Origin": "http://localhost:5173"},
    )
    assert replay_resp.status_code == 400
    assert "already been used" in replay_resp.json()["detail"] or "invalid" in replay_resp.json()["detail"]


@pytest.mark.asyncio
async def test_verify_email_resend_cooldown_rate_limit(async_client: AsyncClient):
    """Requesting verification email enforces 120-second cooldown rate limiting."""
    email = f"cooldown_{uuid.uuid4().hex[:8]}@sentriq.io"
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "SecurePassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert reg_resp.status_code == 201

    # Immediate second request should be rejected by cooldown rate limiter (429)
    resend_resp = await async_client.post(
        "/api/auth/verify-email/request",
        json={"email": email},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resend_resp.status_code == 429
    assert "Retry-After" in resend_resp.headers
    assert "recently sent" in resend_resp.json()["detail"]


# =====================================================================
# 2. Password Recovery Tests
# =====================================================================

@pytest.mark.asyncio
async def test_password_reset_request_anti_enumeration(async_client: AsyncClient):
    """Password reset request returns identical generic message for existent and non-existent emails."""
    headers = {"Origin": "http://localhost:5173"}

    # Existing user
    existing_email = f"exist_{uuid.uuid4().hex[:8]}@sentriq.io"
    await async_client.post(
        "/api/auth/register",
        json={"email": existing_email, "password": "OldPassword123!"},
        headers=headers,
    )
    test_outbox.clear()

    resp_exist = await async_client.post(
        "/api/auth/password-reset/request",
        json={"email": existing_email},
        headers=headers,
    )
    assert resp_exist.status_code == 200

    # Non-existent user
    non_exist_email = f"ghost_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp_non_exist = await async_client.post(
        "/api/auth/password-reset/request",
        json={"email": non_exist_email},
        headers=headers,
    )
    assert resp_non_exist.status_code == 200

    # Responses must be completely identical (preventing email enumeration)
    assert resp_exist.json()["message"] == resp_non_exist.json()["message"]

    # Only existing user should receive an email
    assert test_outbox.get_latest_token_for(existing_email) is not None
    assert test_outbox.get_latest_token_for(non_exist_email) is None


@pytest.mark.asyncio
async def test_password_reset_confirm_and_session_revocation(async_client: AsyncClient):
    """Confirming password reset updates credentials and revokes all previously active sessions."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"reset_{uuid.uuid4().hex[:8]}@sentriq.io"
    old_password = "OldPassword123!"
    new_password = "NewBrandPassword456!"

    # 1. Register user and capture initial session
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": old_password},
        headers=headers,
    )
    assert reg_resp.status_code == 201
    initial_cookie = reg_resp.cookies.get(settings.SESSION_COOKIE_NAME)
    assert initial_cookie is not None

    # Verify initial session works
    me_resp1 = await async_client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: initial_cookie},
    )
    assert me_resp1.status_code == 200

    # 2. Request password reset
    test_outbox.clear()
    req_resp = await async_client.post(
        "/api/auth/password-reset/request",
        json={"email": email},
        headers=headers,
    )
    assert req_resp.status_code == 200
    reset_token = test_outbox.get_latest_token_for(email)
    assert reset_token is not None

    # 3. Confirm password reset
    confirm_resp = await async_client.post(
        "/api/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": new_password},
        headers=headers,
    )
    assert confirm_resp.status_code == 200

    # 4. CRITICAL SECURITY INVARIANT: Old session MUST be revoked
    me_resp2 = await async_client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: initial_cookie},
    )
    assert me_resp2.status_code == 401, "Old sessions must be revoked upon password reset"

    # 5. Old password no longer works
    login_old = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": old_password},
        headers=headers,
    )
    assert login_old.status_code == 401

    # 6. New password works successfully
    login_new = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": new_password},
        headers=headers,
    )
    assert login_new.status_code == 200


# =====================================================================
# 3. Two-Account Multi-Tenant Isolation Verification
# =====================================================================

@pytest.mark.asyncio
async def test_two_account_tenant_isolation_projects_scans_findings(async_client: AsyncClient):
    """Verify strict tenant isolation between two distinct registered user accounts."""
    headers = {"Origin": "http://localhost:5173"}

    # Register User A
    email_a = f"usera_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp_a = await async_client.post(
        "/api/auth/register",
        json={"email": email_a, "password": "PasswordUserA123!"},
        headers=headers,
    )
    assert resp_a.status_code == 201
    cookie_a = resp_a.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_a = resp_a.json()["csrf_token"]

    # Register User B
    email_b = f"userb_{uuid.uuid4().hex[:8]}@sentriq.io"
    resp_b = await async_client.post(
        "/api/auth/register",
        json={"email": email_b, "password": "PasswordUserB123!"},
        headers=headers,
    )
    assert resp_b.status_code == 201
    cookie_b = resp_b.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_b = resp_b.json()["csrf_token"]

    # Mark both users verified so they can exercise verified features (project creation, scans, findings)
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(User).where(User.email.in_([email_a, email_b])).values(is_verified=True)
        )
        await session.commit()

    # User A creates a project
    proj_resp_a = await async_client.post(
        "/api/projects",
        json={
            "name": "Project Alpha",
            "target_url": "https://alpha.example.com",
            "authorization_confirmed": True,
        },
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_a},
    )
    assert proj_resp_a.status_code == 201
    proj_a_id = proj_resp_a.json()["id"]

    # User B creates a project
    proj_resp_b = await async_client.post(
        "/api/projects",
        json={
            "name": "Project Beta",
            "target_url": "https://beta.example.com",
            "authorization_confirmed": True,
        },
        cookies={settings.SESSION_COOKIE_NAME: cookie_b},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_b},
    )
    assert proj_resp_b.status_code == 201
    proj_b_id = proj_resp_b.json()["id"]

    # 1. User A lists projects: must ONLY see Project Alpha, NOT Project Beta
    list_a = await async_client.get(
        "/api/projects",
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
    )
    assert list_a.status_code == 200
    ids_a = [p["id"] for p in list_a.json()]
    assert proj_a_id in ids_a
    assert proj_b_id not in ids_a

    # 2. User B lists projects: must ONLY see Project Beta, NOT Project Alpha
    list_b = await async_client.get(
        "/api/projects",
        cookies={settings.SESSION_COOKIE_NAME: cookie_b},
    )
    assert list_b.status_code == 200
    ids_b = [p["id"] for p in list_b.json()]
    assert proj_b_id in ids_b
    assert proj_a_id not in ids_b

    # 3. User A attempts direct access to Project Beta -> 404 (IDOR prevention)
    cross_proj = await async_client.get(
        f"/api/projects/{proj_b_id}",
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
    )
    assert cross_proj.status_code == 404

    # 4. Insert dummy findings directly linked to each project
    async with AsyncSessionLocal() as session:
        # Create scan for project A
        scan_a = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_a_id,
            target_url="https://alpha.example.com",
            status="completed",
            started_at=datetime.now(timezone.utc),
        )
        session.add(scan_a)
        # Create scan for project B
        scan_b = Scan(
            id=str(uuid.uuid4()),
            project_id=proj_b_id,
            target_url="https://beta.example.com",
            status="completed",
            started_at=datetime.now(timezone.utc),
        )
        session.add(scan_b)
        await session.flush()

        finding_a = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_a.id,
            title="Alpha Finding",
            description="Alpha vuln",
            category="Security Headers",
            severity="high",
            confidence=0.9,
            risk_score=75,
            status="open",
            fingerprint="fp-alpha",
        )
        session.add(finding_a)

        finding_b = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_b.id,
            title="Beta Finding",
            description="Beta vuln",
            category="SSL/TLS",
            severity="critical",
            confidence=0.95,
            risk_score=90,
            status="open",
            fingerprint="fp-beta",
        )
        session.add(finding_b)
        await session.commit()
        finding_a_id = finding_a.id
        finding_b_id = finding_b.id

    # 5. User A calls centralized findings API: must only see Alpha Finding
    findings_a = await async_client.get(
        "/api/findings",
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
    )
    assert findings_a.status_code == 200
    finding_ids_seen_by_a = [f["id"] for f in findings_a.json()["items"]]
    assert finding_a_id in finding_ids_seen_by_a
    assert finding_b_id not in finding_ids_seen_by_a

    # 6. User A attempts direct access to Beta Finding -> 404 Not Found
    direct_finding = await async_client.get(
        f"/api/findings/{finding_b_id}",
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
    )
    assert direct_finding.status_code == 404

    # 7. User A attempts to mutate Beta Finding -> 404 Not Found
    mutate_finding = await async_client.patch(
        f"/api/findings/{finding_b_id}",
        json={"status": "resolved"},
        cookies={settings.SESSION_COOKIE_NAME: cookie_a},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_a},
    )
    assert mutate_finding.status_code == 404
