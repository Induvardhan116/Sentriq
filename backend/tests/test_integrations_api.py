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
            hashed_password=hash_password("IntegrationPass123!"),
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
            user_agent="Sentriq-Integration-Test",
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
async def test_webhook_creation_and_ssrf_protection(async_client: AsyncClient):
    """Should enforce SSRF protection on target webhook URL and mask secret token."""
    tenant = await create_test_tenant("webhook_admin@sentriq.io")

    # 1. Attempt SSRF URL (localhost / 127.0.0.1)
    ssrf_payload = {
        "name": "Malicious Webhook",
        "target_url": "http://127.0.0.1:8080/internal-admin",
        "event_types": "scan.completed"
    }
    ssrf_res = await async_client.post(
        "/api/integrations/webhooks",
        json=ssrf_payload,
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert ssrf_res.status_code == 400
    assert "SSRF" in ssrf_res.json()["detail"]

    # 2. Valid HTTPS Webhook
    valid_payload = {
        "name": "Corporate Slack Alerts",
        "target_url": "https://hooks.slack.com/services/T00/B00/XXXX",
        "event_types": "scan.completed,finding.critical",
        "secret_token": "whsec_supersecretkey12345"
    }
    valid_res = await async_client.post(
        "/api/integrations/webhooks",
        json=valid_payload,
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert valid_res.status_code == 201
    wh_data = valid_res.json()
    assert wh_data["name"] == "Corporate Slack Alerts"
    # Ensure secret is masked
    assert "whsec_****" in wh_data["secret_token"] or "****" in wh_data["secret_token"]
    assert "supersecretkey" not in wh_data["secret_token"]


@pytest.mark.asyncio
async def test_scan_schedule_management(async_client: AsyncClient):
    """Should register automated recurring scan schedules."""
    tenant = await create_test_tenant("schedule_user@sentriq.io")

    target_id = str(uuid.uuid4())
    payload = {
        "target_type": "project",
        "target_id": target_id,
        "target_name": "Main Production Web App",
        "frequency": "weekly"
    }

    create_res = await async_client.post(
        "/api/integrations/schedules",
        json=payload,
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert create_res.status_code == 201
    schedule = create_res.json()
    assert schedule["target_name"] == "Main Production Web App"
    assert schedule["frequency"] == "weekly"
    assert schedule["next_run_at"] is not None
    schedule_id = schedule["id"]

    # List schedules
    list_res = await async_client.get(
        "/api/integrations/schedules",
        cookies=tenant["cookies"],
    )
    assert list_res.status_code == 200
    schedules = list_res.json()
    assert any(s["id"] == schedule_id for s in schedules)

    # Execute schedule on demand
    run_res = await async_client.post(
        f"/api/integrations/schedules/{schedule_id}/run",
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["schedule_id"] == schedule_id
    assert run_data["last_run_at"] is not None
    assert run_data["next_run_at"] is not None

    # Delete schedule
    del_res = await async_client.delete(
        f"/api/integrations/schedules/{schedule_id}",
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert del_res.status_code == 204


@pytest.mark.asyncio
async def test_siem_event_generation_cef(async_client: AsyncClient):
    """Should generate security event stream compliant with CEF format."""
    tenant = await create_test_tenant("siem_officer@sentriq.io")

    res = await async_client.get(
        "/api/integrations/siem/events",
        cookies=tenant["cookies"],
    )
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    first_event = events[0]
    assert "CEF:0|Sentriq|ASPM|1.0|" in first_event["cef_string"]
    assert "severity" in first_event
    assert "timestamp" in first_event
