import pytest
import uuid
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient

from app.config import get_settings
from app.models.user import User, UserSession
from app.database.session import AsyncSessionLocal
from app.security.hasher import hash_password, verify_password
from app.security.session import generate_session_token, hash_session_token
from app.security.csrf import generate_session_csrf_token

settings = get_settings()


async def create_test_tenant(email: str, is_superuser: bool = False, initial_password: str = "OldPass123!"):
    """Helper to create an authenticated tenant user and session."""
    async with AsyncSessionLocal() as session:
        user = User(
            id=str(uuid.uuid4()),
            email=email.strip().lower(),
            hashed_password=hash_password(initial_password),
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
            user_agent="Sentriq-Settings-Test",
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
async def test_get_and_update_profile(async_client: AsyncClient):
    """Should retrieve user profile and update display name."""
    tenant = await create_test_tenant("profile_user@sentriq.io")

    # Fetch profile
    get_res = await async_client.get(
        "/api/settings/profile",
        cookies=tenant["cookies"],
    )
    assert get_res.status_code == 200
    profile = get_res.json()
    assert profile["email"] == "profile_user@sentriq.io"

    # Update profile
    patch_res = await async_client.patch(
        "/api/settings/profile",
        json={"full_name": "Chief Security Architect"},
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["full_name"] == "Chief Security Architect"


@pytest.mark.asyncio
async def test_change_password_flow(async_client: AsyncClient):
    """Should validate current password and update with new hash."""
    tenant = await create_test_tenant("pass_change@sentriq.io", initial_password="CurrentSecurePass123!")

    # Attempt with incorrect current password
    bad_res = await async_client.post(
        "/api/settings/password",
        json={
            "current_password": "WrongPassword!",
            "new_password": "BrandNewPassword123!"
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert bad_res.status_code == 400

    # Succeed with correct current password
    ok_res = await async_client.post(
        "/api/settings/password",
        json={
            "current_password": "CurrentSecurePass123!",
            "new_password": "BrandNewPassword123!"
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert ok_res.status_code == 200

    # Verify password was updated in DB
    async with AsyncSessionLocal() as session:
        user = await session.get(User, tenant["id"])
        assert user is not None
        assert verify_password("BrandNewPassword123!", user.hashed_password)


@pytest.mark.asyncio
async def test_active_sessions_and_revocation(async_client: AsyncClient):
    """Should list sessions and allow revoking other active sessions."""
    tenant = await create_test_tenant("sessions_user@sentriq.io")

    # Add a second active session (simulating a mobile login)
    async with AsyncSessionLocal() as session:
        secondary_token = generate_session_token()
        secondary_hash = hash_session_token(secondary_token)
        sec_session = UserSession(
            user_id=tenant["id"],
            token_hash=secondary_hash,
            ip_address="192.168.1.50",
            user_agent="Mobile-Safari",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            revoked_at=None,
        )
        session.add(sec_session)
        await session.commit()
        secondary_id = sec_session.id

    # List sessions
    list_res = await async_client.get(
        "/api/settings/sessions",
        cookies=tenant["cookies"],
    )
    assert list_res.status_code == 200
    sessions = list_res.json()
    assert len(sessions) == 2

    # Verify is_current flag
    current_items = [s for s in sessions if s["is_current"]]
    assert len(current_items) == 1

    # Revoke secondary session
    revoke_res = await async_client.delete(
        f"/api/settings/sessions/{secondary_id}",
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert revoke_res.status_code == 200

    # Verify only 1 active session remains
    list_res_2 = await async_client.get(
        "/api/settings/sessions",
        cookies=tenant["cookies"],
    )
    assert len(list_res_2.json()) == 1


@pytest.mark.asyncio
async def test_user_preferences_persistence(async_client: AsyncClient):
    """Should retrieve default preferences and persist scanner/notification changes."""
    tenant = await create_test_tenant("preferences_user@sentriq.io")

    # Fetch default preferences
    pref_res = await async_client.get(
        "/api/settings/preferences",
        cookies=tenant["cookies"],
    )
    assert pref_res.status_code == 200
    prefs = pref_res.json()
    assert prefs["scanner_timeout_seconds"] == 30
    assert prefs["notify_email_scan_completed"] is True
    assert prefs["default_scan_cadence"] == "weekly"

    # Update preferences
    patch_res = await async_client.patch(
        "/api/settings/preferences",
        json={
            "scanner_timeout_seconds": 45,
            "notify_email_critical_finding": False,
            "default_scan_cadence": "daily",
            "scanner_strict_headers": True,
        },
        headers=tenant["headers"],
        cookies=tenant["cookies"],
    )
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["scanner_timeout_seconds"] == 45
    assert updated["notify_email_critical_finding"] is False
    assert updated["default_scan_cadence"] == "daily"
