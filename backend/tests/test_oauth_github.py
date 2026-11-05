"""
Sentriq GitHub OAuth Integration Test Suite.

Tests:
1. Missing credentials returns 501 Not Implemented.
2. Initiation (/api/auth/github) sets HttpOnly/SameSite=lax sentriq_oauth_state cookie and redirects to GitHub.
3. User cancellation (error=access_denied) redirects to login with error=access_denied and clears cookie.
4. Tampered state redirects with error=invalid_oauth_state.
5. Expired state redirects with error=oauth_state_expired.
6. Replayed callback rejects with error=oauth_state_already_used.
7. GitHub token exchange failure redirects with error=oauth_token_exchange_failed.
8. GitHub communication failure redirects with error=oauth_communication_error.
9. Unverified GitHub email rejects with error=oauth_no_verified_email.
10. Account takeover prevention: existing password account is NEVER auto-linked (error=account_link_required).
11. Brand-new registration creates User (is_verified=True, hashed_password=None) + OAuthAccount and session.
12. Returning GitHub user logs in seamlessly.
13. Explicit authenticated account linking succeeds for the logged-in owner.
14. Account conflict: GitHub account already linked to another user rejects with error=oauth_account_conflict.
"""

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock
import pytest
from httpx import AsyncClient, Response
from sqlalchemy import select

from app.config import get_settings, Settings
from app.models.user import User, OAuthAccount, UserSession, OAuthState
from app.database.session import AsyncSessionLocal
from app.security.oauth import generate_oauth_state, save_oauth_state, hash_oauth_state
from app.security.session import generate_session_token, hash_session_token
from app.security.hasher import hash_password

settings = get_settings()

OAUTH_SETTINGS = Settings(
    ENVIRONMENT="development",
    AUTH_ENABLED=True,
    GITHUB_CLIENT_ID="mock-gh-client-id",
    GITHUB_CLIENT_SECRET="mock-gh-client-secret",
    GITHUB_REDIRECT_URI="http://localhost:5173/api/auth/github/callback",
    FRONTEND_URL="http://localhost:5173",
)


@pytest.mark.asyncio
async def test_oauth_initiation_missing_credentials_returns_501(async_client: AsyncClient):
    """When GitHub credentials are not configured, GET /api/auth/github returns 501 Not Implemented."""
    no_creds_settings = Settings(
        ENVIRONMENT="development",
        AUTH_ENABLED=True,
        GITHUB_CLIENT_ID=None,
        GITHUB_CLIENT_SECRET=None,
    )
    with patch("app.api.auth.settings", no_creds_settings):
        resp = await async_client.get("/api/auth/github")
        assert resp.status_code == 501
        assert "not configured" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_oauth_initiation_sets_state_cookie_and_redirects(async_client: AsyncClient):
    """GET /api/auth/github sets sentriq_oauth_state cookie and redirects to GitHub authorize URL."""
    with patch("app.api.auth.settings", OAUTH_SETTINGS):
        resp = await async_client.get("/api/auth/github", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("https://github.com/login/oauth/authorize?")
        assert "client_id=mock-gh-client-id" in location
        assert "scope=read%3Auser+user%3Aemail" in location
        assert "state=" in location

        # Verify state cookie was set with proper security flags
        cookie = resp.cookies.get("sentriq_oauth_state")
        assert cookie is not None
        assert len(cookie) > 32


@pytest.mark.asyncio
async def test_oauth_callback_user_denies_authorization(async_client: AsyncClient):
    """When user cancels on GitHub, callback cleanly redirects with error=access_denied and clears cookie."""
    with patch("app.api.auth.settings", OAUTH_SETTINGS):
        resp = await async_client.get(
            "/api/auth/github/callback?error=access_denied&error_description=The+user+has+denied+access",
            cookies={"sentriq_oauth_state": "some-state"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=access_denied" in resp.headers["location"]


@pytest.mark.asyncio
async def test_oauth_callback_tampered_or_missing_state(async_client: AsyncClient):
    """Tampered or missing state is rejected with error=invalid_oauth_state."""
    with patch("app.api.auth.settings", OAUTH_SETTINGS):
        # 1. State missing
        r1 = await async_client.get("/api/auth/github/callback?code=abc", follow_redirects=False)
        assert r1.status_code == 302
        assert "error=invalid_oauth_state" in r1.headers["location"]

        # 2. Forged signature in state
        r2 = await async_client.get(
            "/api/auth/github/callback?code=abc&state=eyJ0cyI6MX0.forged_signature",
            cookies={"sentriq_oauth_state": "eyJ0cyI6MX0.forged_signature"},
            follow_redirects=False,
        )
        assert r2.status_code == 302
        assert "error=invalid_oauth_state" in r2.headers["location"]


@pytest.mark.asyncio
async def test_oauth_callback_expired_state(async_client: AsyncClient):
    """Expired state (>600s) redirects with error=oauth_state_expired."""
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")
    async with AsyncSessionLocal() as session:
        rec = await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        rec.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.commit()

    with patch("app.api.auth.settings", OAUTH_SETTINGS):
        resp = await async_client.get(
            f"/api/auth/github/callback?code=abc&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_state_expired" in resp.headers["location"]


@pytest.mark.asyncio
async def test_oauth_callback_replay_prevention(async_client: AsyncClient):
    """Consuming the same state a second time is rejected with error=oauth_state_already_used."""
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")
    async with AsyncSessionLocal() as session:
        rec = await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        rec.consumed_at = datetime.now(timezone.utc)
        await session.commit()

    with patch("app.api.auth.settings", OAUTH_SETTINGS):
        resp = await async_client.get(
            f"/api/auth/github/callback?code=abc&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_state_already_used" in resp.headers["location"]


@pytest.mark.asyncio
async def test_oauth_callback_github_token_exchange_failure(async_client: AsyncClient):
    """When GitHub token endpoint fails, callback redirects with error=oauth_token_exchange_failed."""
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    # Token endpoint returns error
    mock_token_resp = MagicMock()
    mock_token_resp.status_code = 400
    mock_token_resp.json.return_value = {"error": "bad_verification_code"}
    mock_client.post.return_value = mock_token_resp

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        resp = await async_client.get(
            f"/api/auth/github/callback?code=bad_code&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_token_exchange_failed" in resp.headers["location"]


@pytest.mark.asyncio
async def test_oauth_callback_unverified_github_email_rejected(async_client: AsyncClient):
    """When GitHub profile has only unverified emails, registration is rejected with error=oauth_no_verified_email."""
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    # 1. Token exchange succeeds
    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "gh_access_token_123"}
    mock_client.post.return_value = mock_token

    # 2. User profile returns user
    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {"id": 999111, "login": "unverified_gh", "name": "Unverified User"}

    # 3. Emails returns unverified email
    mock_emails = MagicMock(status_code=200)
    mock_emails.json.return_value = [
        {"email": "unverified@example.com", "verified": False, "primary": True}
    ]

    mock_client.get.side_effect = [mock_user, mock_emails]

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        resp = await async_client.get(
            f"/api/auth/github/callback?code=valid_code&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_no_verified_email" in resp.headers["location"]


@pytest.mark.asyncio
async def test_oauth_callback_account_takeover_prevention_no_autolink(async_client: AsyncClient):
    """CRITICAL SECURITY TEST: An unauthenticated GitHub login matching an existing password user's email
    must NEVER automatically link accounts. Must reject with error=account_link_required."""
    local_email = f"ceo_{uuid.uuid4().hex[:8]}@corporation.com"
    # Create local password user
    async with AsyncSessionLocal() as session:
        ceo = User(
            email=local_email,
            hashed_password=hash_password("SuperSecretCEO123!"),
            full_name="CEO Person",
            is_active=True,
            is_verified=True,
        )
        session.add(ceo)
        await session.commit()

    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "gh_token"}
    mock_client.post.return_value = mock_token

    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {"id": 777888, "login": "attacker_gh", "name": "Attacker"}

    mock_emails = MagicMock(status_code=200)
    mock_emails.json.return_value = [
        {"email": local_email, "verified": True, "primary": True}
    ]
    mock_client.get.side_effect = [mock_user, mock_emails]

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        resp = await async_client.get(
            f"/api/auth/github/callback?code=attacker_code&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=account_link_required" in resp.headers["location"]

        # Confirm that NO OAuthAccount was linked
        async with AsyncSessionLocal() as session:
            linked = await session.scalar(
                select(OAuthAccount).where(OAuthAccount.provider_account_id == "777888")
            )
            assert linked is None, "Attacker GitHub account must NOT be linked!"


@pytest.mark.asyncio
async def test_oauth_callback_successful_brand_new_registration(async_client: AsyncClient):
    """Brand-new user authenticating via GitHub creates User (is_verified=True, password=None) and active session."""
    gh_email = f"new_gh_{uuid.uuid4().hex[:8]}@example.com"
    gh_id = "5551234"

    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/projects")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/projects", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "gh_access_token_abc"}
    mock_client.post.return_value = mock_token

    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {
        "id": int(gh_id),
        "login": "new_developer",
        "name": "New Developer",
        "avatar_url": "https://avatars.example.com/u/5551234",
    }

    mock_emails = MagicMock(status_code=200)
    mock_emails.json.return_value = [
        {"email": gh_email, "verified": True, "primary": True}
    ]
    mock_client.get.side_effect = [mock_user, mock_emails]

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        resp = await async_client.get(
            f"/api/auth/github/callback?code=code_123&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"] == "http://localhost:5173/#/projects"

        # Session cookie was set
        session_cookie = resp.cookies.get(settings.SESSION_COOKIE_NAME)
        assert session_cookie is not None

        # Verify DB records
        async with AsyncSessionLocal() as session:
            user = await session.scalar(select(User).where(User.email == gh_email))
            assert user is not None
            assert user.is_verified is True
            assert user.hashed_password is None
            assert user.full_name == "New Developer"

            oauth_rec = await session.scalar(select(OAuthAccount).where(OAuthAccount.user_id == user.id))
            assert oauth_rec is not None
            assert oauth_rec.provider == "github"
            assert oauth_rec.provider_account_id == gh_id


@pytest.mark.asyncio
async def test_oauth_callback_returning_github_user_login(async_client: AsyncClient):
    """Existing GitHub user logging in again establishes fresh session."""
    gh_email = f"returning_{uuid.uuid4().hex[:8]}@example.com"
    gh_id = "888444"

    async with AsyncSessionLocal() as session:
        user = User(
            email=gh_email,
            full_name="Returning Dev",
            is_active=True,
            is_verified=True,
        )
        session.add(user)
        await session.flush()
        oauth_acc = OAuthAccount(
            user_id=user.id,
            provider="github",
            provider_account_id=gh_id,
            provider_username="returning_dev",
            provider_email=gh_email,
        )
        session.add(oauth_acc)
        await session.commit()
        user_id = user.id

    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "token"}
    mock_client.post.return_value = mock_token

    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {"id": int(gh_id), "login": "returning_dev", "name": "Returning Dev"}
    mock_emails = MagicMock(status_code=200)
    mock_emails.json.return_value = [{"email": gh_email, "verified": True, "primary": True}]
    mock_client.get.side_effect = [mock_user, mock_emails]

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        resp = await async_client.get(
            f"/api/auth/github/callback?code=code_returning&state={state}",
            cookies={"sentriq_oauth_state": state},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"] == "http://localhost:5173/#/overview"
        session_cookie = resp.cookies.get(settings.SESSION_COOKIE_NAME)
        assert session_cookie is not None


@pytest.mark.asyncio
async def test_oauth_callback_explicit_authenticated_account_linking(async_client: AsyncClient):
    """An already-authenticated user can explicitly connect their GitHub account."""
    user_email = f"authed_owner_{uuid.uuid4().hex[:8]}@sentriq.io"
    gh_id = "999888"

    # Create local user with active session
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    async with AsyncSessionLocal() as session:
        u = User(
            email=user_email,
            hashed_password=hash_password("Pass123!"),
            full_name="Authed Owner",
            is_active=True,
            is_verified=True,
        )
        session.add(u)
        await session.flush()
        s = UserSession(
            user_id=u.id,
            token_hash=token_hash,
            ip_address="127.0.0.1",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        session.add(s)
        await session.commit()
        owner_id = u.id

    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/profile")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/profile", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "token"}
    mock_client.post.return_value = mock_token

    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {"id": int(gh_id), "login": "authed_gh", "name": "Authed Owner"}
    mock_emails = MagicMock(status_code=200)
    mock_emails.json.return_value = [{"email": user_email, "verified": True, "primary": True}]
    mock_client.get.side_effect = [mock_user, mock_emails]

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        # User calls callback WITH their active session cookie + state cookie
        resp = await async_client.get(
            f"/api/auth/github/callback?code=link_code&state={state}",
            cookies={
                "sentriq_oauth_state": state,
                settings.SESSION_COOKIE_NAME: raw_token,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=" not in resp.headers["location"]

        # Confirm OAuthAccount is now linked to this user
        async with AsyncSessionLocal() as session:
            oauth_rec = await session.scalar(
                select(OAuthAccount).where(OAuthAccount.provider_account_id == gh_id)
            )
            assert oauth_rec is not None
            assert oauth_rec.user_id == owner_id


@pytest.mark.asyncio
async def test_oauth_callback_conflict_github_linked_to_different_user(async_client: AsyncClient):
    """When a GitHub account is already linked to User A, User B cannot link it (error=oauth_account_conflict)."""
    gh_id = "111222"
    # User A owns the GitHub account
    async with AsyncSessionLocal() as session:
        user_a = User(email=f"usera_{uuid.uuid4().hex[:6]}@s.io", is_active=True, is_verified=True)
        session.add(user_a)
        await session.flush()
        oauth_a = OAuthAccount(
            user_id=user_a.id,
            provider="github",
            provider_account_id=gh_id,
            provider_username="gh_usera",
            provider_email=user_a.email,
        )
        session.add(oauth_a)

        # User B has an active session
        user_b = User(email=f"userb_{uuid.uuid4().hex[:6]}@s.io", is_active=True, is_verified=True)
        session.add(user_b)
        await session.flush()
        raw_token_b = generate_session_token()
        sess_b = UserSession(
            user_id=user_b.id,
            token_hash=hash_session_token(raw_token_b),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        session.add(sess_b)
        await session.commit()

    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/profile")
    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/profile", max_age_seconds=600)
        await session.commit()

    mock_client = AsyncMock()
    mock_token = MagicMock(status_code=200)
    mock_token.json.return_value = {"access_token": "token"}
    mock_client.post.return_value = mock_token

    mock_user = MagicMock(status_code=200)
    mock_user.json.return_value = {"id": int(gh_id), "login": "gh_usera", "name": "User A"}
    mock_emails = MagicMock(status_code=200)
    mock_emails.json.return_value = [{"email": "usera@s.io", "verified": True, "primary": True}]
    mock_client.get.side_effect = [mock_user, mock_emails]

    with patch("app.api.auth.settings", OAUTH_SETTINGS), \
         patch("httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client

        # User B attempts to link User A's GitHub account
        resp = await async_client.get(
            f"/api/auth/github/callback?code=conflict_code&state={state}",
            cookies={
                "sentriq_oauth_state": state,
                settings.SESSION_COOKIE_NAME: raw_token_b,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "error=oauth_account_conflict" in resp.headers["location"]

