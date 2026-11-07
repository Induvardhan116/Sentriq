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
            hashed_password=hash_password("WorkspacePass123!"),
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
            user_agent="Sentriq-Workspace-Test",
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
async def test_workspace_creation_and_member_lifecycle(async_client: AsyncClient):
    """Should create workspace, assign owner role, invite member, and track in audit log."""
    owner = await create_test_tenant("org_owner@sentriq.io")
    analyst = await create_test_tenant("sec_analyst@sentriq.io")

    # 1. Create Workspace
    create_res = await async_client.post(
        "/api/workspaces",
        json={"name": "Enterprise Security Team"},
        headers=owner["headers"],
        cookies=owner["cookies"],
    )
    assert create_res.status_code == 201
    ws = create_res.json()
    assert ws["name"] == "Enterprise Security Team"
    assert ws["role"] == "owner"
    ws_id = ws["id"]

    # 2. Invite Analyst Member
    invite_res = await async_client.post(
        f"/api/workspaces/{ws_id}/members",
        json={"email": "sec_analyst@sentriq.io", "role": "analyst"},
        headers=owner["headers"],
        cookies=owner["cookies"],
    )
    assert invite_res.status_code == 201
    member = invite_res.json()
    assert member["email"] == "sec_analyst@sentriq.io"
    assert member["role"] == "analyst"

    # 3. List Members
    members_res = await async_client.get(
        f"/api/workspaces/{ws_id}/members",
        cookies=owner["cookies"],
    )
    assert members_res.status_code == 200
    members = members_res.json()
    assert len(members) == 2

    # 4. Analyst attempts to invite an outsider (RBAC check - should fail 403)
    outsider = await create_test_tenant("outsider@sentriq.io")
    fail_invite = await async_client.post(
        f"/api/workspaces/{ws_id}/members",
        json={"email": outsider["email"], "role": "analyst"},
        headers=analyst["headers"],
        cookies=analyst["cookies"],
    )
    assert fail_invite.status_code == 403

    # 5. Check Audit Logs
    audit_res = await async_client.get(
        f"/api/workspaces/{ws_id}/audit-logs",
        cookies=owner["cookies"],
    )
    assert audit_res.status_code == 200
    logs = audit_res.json()
    actions = [l["action"] for l in logs]
    assert "workspace.created" in actions
    assert "member.invited" in actions


@pytest.mark.asyncio
async def test_owner_protection_rules(async_client: AsyncClient):
    """Cannot remove or demote the sole remaining workspace owner."""
    owner = await create_test_tenant("sole_owner@sentriq.io")

    create_res = await async_client.post(
        "/api/workspaces",
        json={"name": "Critical Infrastructure Org"},
        headers=owner["headers"],
        cookies=owner["cookies"],
    )
    ws_id = create_res.json()["id"]

    # Attempt to demote sole owner to analyst
    demote_res = await async_client.patch(
        f"/api/workspaces/{ws_id}/members/{owner['id']}",
        json={"role": "analyst"},
        headers=owner["headers"],
        cookies=owner["cookies"],
    )
    assert demote_res.status_code == 400
    assert "sole" in demote_res.json()["detail"].lower() or "remaining" in demote_res.json()["detail"].lower()

    # Attempt to remove sole owner
    remove_res = await async_client.delete(
        f"/api/workspaces/{ws_id}/members/{owner['id']}",
        headers=owner["headers"],
        cookies=owner["cookies"],
    )
    assert remove_res.status_code == 400
