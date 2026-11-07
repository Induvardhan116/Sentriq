import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.config import get_settings
from app.models.user import User, UserSession
from app.database.session import AsyncSessionLocal
from app.security.hasher import hash_password
from app.security.session import generate_session_token, hash_session_token
from app.security.csrf import generate_session_csrf_token

settings = get_settings()


async def create_test_tenant(email: str, is_superuser: bool = False):
    """Helper to create an authenticated tenant user and session."""
    async with AsyncSessionLocal() as session:
        user = User(
            id=str(uuid.uuid4()),
            email=email.strip().lower(),
            hashed_password=hash_password("CloudPass123!"),
            full_name=f"User {email}",
            is_active=True,
            is_verified=True,
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
            user_agent="Sentriq-Cloud-Test",
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


@pytest.mark.asyncio
async def test_create_and_scan_cloud_account(async_client: AsyncClient):
    """Should register cloud account, mask credentials, and execute CSPM posture scan."""
    tenant = await create_test_tenant("cloud_admin@sentriq.io")

    payload = {
        "provider": "aws",
        "name": "Production AWS Infrastructure",
        "account_identifier": "123456789012",
        "role_arn_or_ref": "arn:aws:iam::123456789012:role/SentriqReadOnlyAuditRole",
        "region": "us-east-1"
    }

    create_res = await async_client.post(
        "/api/cloud-security/accounts",
        json=payload,
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert create_res.status_code == 201
    account_data = create_res.json()
    assert account_data["name"] == "Production AWS Infrastructure"
    assert account_data["provider"] == "aws"
    # Ensure role ARN is masked
    assert "SentriqReadOnlyAuditRole" in account_data["role_arn_or_ref"]
    assert "****" in account_data["role_arn_or_ref"]
    account_id = account_data["id"]

    # Trigger CSPM scan
    scan_res = await async_client.post(
        f"/api/cloud-security/accounts/{account_id}/scan",
        json={},
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert scan_res.status_code == 200
    scanned_account = scan_res.json()
    assert scanned_account["last_scanned_at"] is not None
    assert scanned_account["posture_score"] < 100
    assert scanned_account["findings_count"] > 0

    # Fetch findings
    findings_res = await async_client.get(
        f"/api/cloud-security/accounts/{account_id}/findings",
        cookies=tenant["cookies"],
    )
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0
    benchmark_refs = [f["benchmark_ref"] for f in findings]
    assert "CIS-STORAGE-PUBLIC-ACCESS" in benchmark_refs or "CIS-IAM-ROOT-MFA" in benchmark_refs


@pytest.mark.asyncio
async def test_cloud_security_tenant_isolation(async_client: AsyncClient):
    """Tenant B should not have access to Tenant A's cloud accounts or scan results."""
    tenant_a = await create_test_tenant("tenant_cloud_a@sentriq.io")
    tenant_b = await create_test_tenant("tenant_cloud_b@sentriq.io")

    # Tenant A creates account
    res_a = await async_client.post(
        "/api/cloud-security/accounts",
        json={
            "provider": "supabase",
            "name": "Tenant A Secret Database",
            "account_identifier": "sb_proj_12345",
            "role_arn_or_ref": "sb_secret_token_12345678",
            "region": "us-east-1"
        },
        headers=tenant_a["headers"],
        cookies=tenant_a["cookies"],
    )
    assert res_a.status_code == 201
    account_id = res_a.json()["id"]

    # Tenant B tries to fetch account
    res_b = await async_client.get(
        f"/api/cloud-security/accounts/{account_id}",
        cookies=tenant_b["cookies"],
    )
    assert res_b.status_code == 404

    # Tenant B lists accounts - should not include Tenant A's account
    list_b = await async_client.get(
        "/api/cloud-security/accounts",
        cookies=tenant_b["cookies"],
    )
    assert list_b.status_code == 200
    b_ids = [a["id"] for a in list_b.json()]
    assert account_id not in b_ids


@pytest.mark.asyncio
async def test_cloud_finding_triage(async_client: AsyncClient):
    """Should enforce mandatory justification when marking cloud finding as accepted risk."""
    tenant = await create_test_tenant("cspm_analyst@sentriq.io")

    create_res = await async_client.post(
        "/api/cloud-security/accounts",
        json={
            "provider": "aws",
            "name": "Audit Cloud Account",
            "account_identifier": "987654321098",
            "role_arn_or_ref": "arn:aws:iam::987654321098:role/AuditRole",
            "region": "us-east-1"
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    account_id = create_res.json()["id"]

    await async_client.post(
        f"/api/cloud-security/accounts/{account_id}/scan",
        json={},
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )

    findings_res = await async_client.get(
        f"/api/cloud-security/accounts/{account_id}/findings",
        cookies=tenant["cookies"],
    )
    findings = findings_res.json()
    assert len(findings) > 0
    finding_id = findings[0]["id"]

    # Attempt to accept risk with no justification (should fail 400)
    fail_res = await async_client.patch(
        f"/api/cloud-security/findings/{finding_id}",
        json={"status": "accepted_risk", "justification": ""},
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert fail_res.status_code == 400

    # Succeed with valid justification
    ok_res = await async_client.patch(
        f"/api/cloud-security/findings/{finding_id}",
        json={
            "status": "accepted_risk",
            "justification": "Approved risk mitigation by VP of Engineering with WAF boundary."
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert ok_res.status_code == 200
    assert ok_res.json()["status"] == "accepted_risk"
    assert "VP of Engineering" in ok_res.json()["justification"]
