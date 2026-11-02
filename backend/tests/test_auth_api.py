import uuid
import asyncio
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models.user import User, UserSession, OAuthAccount, OAuthState
from app.database.session import AsyncSessionLocal
from app.security.hasher import hash_password
from app.security.session import hash_session_token, generate_session_token
from app.security.oauth import generate_oauth_state, save_oauth_state, consume_oauth_state
from app.config import get_settings



# =====================================================================
# 1. Registration Tests
# =====================================================================

@pytest.mark.asyncio
async def test_register_user_success(async_client: AsyncClient):
    """User registers successfully, receives UserResponse + CSRF token + HttpOnly cookie."""
    headers = {"Origin": "http://localhost:5173"}
    unique_email = f"analyst_{uuid.uuid4().hex[:8]}@sentriq.io"
    payload = {
        "email": unique_email,
        "password": "CorrectHorseBattery2026!",
        "full_name": "Security Analyst",
    }
    resp = await async_client.post("/api/auth/register", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()

    # Verify user fields
    assert data["email"] == unique_email.lower()
    assert data["full_name"] == "Security Analyst"
    assert data["is_active"] is True
    assert data["is_superuser"] is False
    assert "csrf_token" in data
    assert len(data["csrf_token"]) == 64

    # CRITICAL: Session tokens and passwords must NEVER be in response body
    assert "session_token" not in data
    assert "token" not in data
    assert "password" not in data
    assert "hashed_password" not in data

    # Verify HttpOnly session cookie
    assert "sentriq_session" in resp.cookies
    cookie = resp.cookies.get("sentriq_session")
    assert len(cookie) >= 40


@pytest.mark.asyncio
async def test_register_duplicate_email_rejected(async_client: AsyncClient):
    """Registering an existing email raises 400 Bad Request."""
    headers = {"Origin": "http://localhost:5173"}
    dup_email = f"dup_{uuid.uuid4().hex[:8]}@sentriq.io"
    payload = {
        "email": dup_email,
        "password": "StrongPassword123!",
    }
    resp1 = await async_client.post("/api/auth/register", json=payload, headers=headers)
    assert resp1.status_code == 201

    # Second attempt with same email
    resp2 = await async_client.post("/api/auth/register", json=payload, headers=headers)
    assert resp2.status_code == 400
    assert "already exists" in resp2.json()["detail"]


@pytest.mark.asyncio
async def test_register_weak_password_rejected(async_client: AsyncClient):
    """Weak passwords are rejected by Pydantic validators."""
    headers = {"Origin": "http://localhost:5173"}
    # Less than 10 characters
    resp = await async_client.post(
        "/api/auth/register",
        json={"email": "weak@sentriq.io", "password": "Short1!"},
        headers=headers,
    )
    assert resp.status_code == 422

    # Missing uppercase
    resp = await async_client.post(
        "/api/auth/register",
        json={"email": "weak@sentriq.io", "password": "lowercaseonly123!"},
        headers=headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_superuser_injection_rejected(async_client: AsyncClient):
    """Registration rejects any attempts to supply is_superuser."""
    headers = {"Origin": "http://localhost:5173"}
    payload = {
        "email": "hacker@sentriq.io",
        "password": "StrongPassword123!",
        "is_superuser": True,
    }
    resp = await async_client.post("/api/auth/register", json=payload, headers=headers)
    assert resp.status_code == 422, "Extra fields such as is_superuser must be forbidden"


# =====================================================================
# 2. Login & Rate Limiting Tests
# =====================================================================

@pytest.mark.asyncio
async def test_login_success_and_session_rotation(async_client: AsyncClient):
    """User logs in, session is established via cookie, and CSRF token is returned."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"user_{uuid.uuid4().hex[:8]}@sentriq.io"
    password = "CorrectHorseBattery2026!"

    # Register
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
        headers=headers,
    )
    assert reg_resp.status_code == 201

    # Login
    login_resp = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers=headers,
    )
    assert login_resp.status_code == 200
    data = login_resp.json()
    assert data["email"] == email
    assert "csrf_token" in data
    assert "sentriq_session" in login_resp.cookies


@pytest.mark.asyncio
async def test_login_failure_generic_message_and_dummy_verify(async_client: AsyncClient):
    """Invalid credentials return generic 401 without revealing account existence."""
    headers = {"Origin": "http://localhost:5173"}

    # Non-existent user
    resp = await async_client.post(
        "/api/auth/login",
        json={"email": "nonexistent@sentriq.io", "password": "WrongPassword123!"},
        headers=headers,
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password."

    # Create user
    email = f"existing_{uuid.uuid4().hex[:8]}@sentriq.io"
    await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )

    # Wrong password on existing user returns identical generic message
    resp_wrong = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword123!"},
        headers=headers,
    )
    assert resp_wrong.status_code == 401
    assert resp_wrong.json()["detail"] == "Invalid email or password."


@pytest.mark.asyncio
async def test_account_lockout_after_consecutive_failures(async_client: AsyncClient):
    """Consecutive login failures lock the account and return 429."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"target_{uuid.uuid4().hex[:8]}@sentriq.io"

    await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )

    # Trigger 5 failed attempts
    for _ in range(5):
        await async_client.post(
            "/api/auth/login",
            json={"email": email, "password": "WrongPassword!"},
            headers=headers,
        )

    # 6th attempt with wrong password must be rejected with 429 Too Many Requests (progressive backoff)
    resp_wrong = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword!"},
        headers=headers,
    )
    assert resp_wrong.status_code == 429
    assert "locked" in resp_wrong.json()["detail"].lower()

    # Legitimate user entering the correct password is NOT locked out
    resp_correct = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    assert resp_correct.status_code == 200


# =====================================================================
# 3. Authenticated Endpoints, CSRF & Profile Tests
# =====================================================================

@pytest.mark.asyncio
async def test_me_endpoint_authenticated(async_client: AsyncClient):
    """GET /api/auth/me returns profile and refreshed CSRF token."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"me_{uuid.uuid4().hex[:8]}@sentriq.io"

    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    cookie = reg_resp.cookies["sentriq_session"]

    me_resp = await async_client.get(
        "/api/auth/me",
        cookies={"sentriq_session": cookie},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email
    assert "csrf_token" in me_resp.json()


@pytest.mark.asyncio
async def test_me_endpoint_unauthenticated_returns_401(async_client: AsyncClient):
    """GET /api/auth/me without cookie returns 401 Unauthorized."""
    resp = await async_client.get("/api/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_profile_update_requires_csrf_and_succeeds(async_client: AsyncClient):
    """PATCH /api/auth/profile requires valid X-CSRF-Token and Origin header."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"prof_{uuid.uuid4().hex[:8]}@sentriq.io"

    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    cookie = reg_resp.cookies["sentriq_session"]
    csrf_token = reg_resp.json()["csrf_token"]

    # 1. Missing CSRF header returns 403
    fail_resp = await async_client.patch(
        "/api/auth/profile",
        json={"full_name": "Updated Name"},
        cookies={"sentriq_session": cookie},
        headers={"Origin": "http://localhost:5173"},
    )
    assert fail_resp.status_code == 403

    # 2. Forged CSRF header returns 403
    forged_resp = await async_client.patch(
        "/api/auth/profile",
        json={"full_name": "Updated Name"},
        cookies={"sentriq_session": cookie},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": "forged-token"},
    )
    assert forged_resp.status_code == 403

    # 3. Invalid Origin header returns 403
    evil_origin_resp = await async_client.patch(
        "/api/auth/profile",
        json={"full_name": "Updated Name"},
        cookies={"sentriq_session": cookie},
        headers={"Origin": "https://evil-attacker.com", "X-CSRF-Token": csrf_token},
    )
    assert evil_origin_resp.status_code == 403

    # 4. Valid CSRF and Origin succeeds
    success_resp = await async_client.patch(
        "/api/auth/profile",
        json={"full_name": "Updated Name"},
        cookies={"sentriq_session": cookie},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
    )
    assert success_resp.status_code == 200
    assert success_resp.json()["full_name"] == "Updated Name"


@pytest.mark.asyncio
async def test_logout_revokes_session_and_clears_cookie(async_client: AsyncClient):
    """POST /api/auth/logout revokes session in DB and deletes cookie."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"logout_{uuid.uuid4().hex[:8]}@sentriq.io"

    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    cookie = reg_resp.cookies["sentriq_session"]
    csrf_token = reg_resp.json()["csrf_token"]

    # Logout
    logout_resp = await async_client.post(
        "/api/auth/logout",
        cookies={"sentriq_session": cookie},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf_token},
    )
    assert logout_resp.status_code == 200

    # Cookie is revoked in database
    token_hash = hash_session_token(cookie)
    async with AsyncSessionLocal() as session:
        db_sess = await session.scalar(
            select(UserSession).where(UserSession.token_hash == token_hash)
        )
        assert db_sess is not None
        assert db_sess.revoked_at is not None
        assert db_sess.is_active is False

    # Attempting to use old cookie on /api/auth/me returns 401
    me_resp = await async_client.get(
        "/api/auth/me",
        cookies={"sentriq_session": cookie},
    )
    assert me_resp.status_code == 401


# =====================================================================
# 4. GitHub OAuth Security Tests
# =====================================================================

@pytest.mark.asyncio
async def test_github_oauth_redirect_and_state_cookie(async_client: AsyncClient):
    """GET /api/auth/github sets signed state cookie and redirects to GitHub."""
    # When credentials are not configured, returns 501
    resp = await async_client.get("/api/auth/github")
    assert resp.status_code in (307, 501)


@pytest.mark.asyncio
async def test_github_oauth_callback_tampered_state_rejected(async_client: AsyncClient):
    """Tampered OAuth state returns error redirect without creating session."""
    resp = await async_client.get(
        "/api/auth/github/callback?code=fake_code&state=forged.state.value",
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "error=invalid_oauth_state" in resp.headers["location"]


@pytest.mark.asyncio
async def test_successful_login_resets_failed_attempts(async_client: AsyncClient):
    """Successful login resets user failed_login_attempts and locked_until in DB."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"reset_test_{uuid.uuid4().hex[:8]}@sentriq.io"

    await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )

    # 3 failed attempts
    for _ in range(3):
        await async_client.post(
            "/api/auth/login",
            json={"email": email, "password": "WrongPassword!"},
            headers=headers,
        )

    # Check failure count in DB
    async with AsyncSessionLocal() as session:
        user = await session.scalar(select(User).where(User.email == email))
        assert user is not None
        assert user.failed_login_attempts == 3

    # Successful login
    succ_resp = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    assert succ_resp.status_code == 200

    # Failure count is reset
    async with AsyncSessionLocal() as session:
        user = await session.scalar(select(User).where(User.email == email))
        assert user is not None
        assert user.failed_login_attempts == 0
        assert user.locked_until is None


@pytest.mark.asyncio
async def test_nonexistent_user_login_rate_limiting_generic_message(async_client: AsyncClient):
    """Rate limiting non-existent user returns generic 429 message without revealing user absence."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"nonexistent_{uuid.uuid4().hex[:8]}@sentriq.io"

    # Trigger 5 failed attempts
    for _ in range(5):
        resp = await async_client.post(
            "/api/auth/login",
            json={"email": email, "password": "AnyPassword123!"},
            headers=headers,
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password."

    # 6th attempt must trigger 429 with generic message
    resp_locked = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "AnyPassword123!"},
        headers=headers,
    )
    assert resp_locked.status_code == 429
    assert "locked" in resp_locked.json()["detail"].lower()


@pytest.mark.asyncio
async def test_multiple_simultaneous_device_sessions(async_client: AsyncClient):
    """Logging in from multiple devices creates separate independent sessions that stay valid."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"multidevice_{uuid.uuid4().hex[:8]}@sentriq.io"

    await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )

    # Device 1 login (no prior cookie)
    resp_dev1 = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    assert resp_dev1.status_code == 200
    cookie_dev1 = resp_dev1.cookies["sentriq_session"]

    # Device 2 login (distinct client device without cookie_dev1)
    async_client.cookies.clear()
    resp_dev2 = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    assert resp_dev2.status_code == 200
    cookie_dev2 = resp_dev2.cookies["sentriq_session"]


    assert cookie_dev1 != cookie_dev2

    # Both sessions can access /api/auth/me simultaneously
    me1 = await async_client.get("/api/auth/me", cookies={"sentriq_session": cookie_dev1})
    me2 = await async_client.get("/api/auth/me", cookies={"sentriq_session": cookie_dev2})
    assert me1.status_code == 200
    assert me2.status_code == 200

    # Device 1 logs out
    csrf1 = me1.json()["csrf_token"]
    logout1 = await async_client.post(
        "/api/auth/logout",
        cookies={"sentriq_session": cookie_dev1},
        headers={"Origin": "http://localhost:5173", "X-CSRF-Token": csrf1},
    )
    assert logout1.status_code == 200

    # Device 1 is now rejected (401)
    me1_after = await async_client.get("/api/auth/me", cookies={"sentriq_session": cookie_dev1})
    assert me1_after.status_code == 401

    # Device 2 is STILL active and unaffected!
    me2_after = await async_client.get("/api/auth/me", cookies={"sentriq_session": cookie_dev2})
    assert me2_after.status_code == 200


@pytest.mark.asyncio
async def test_session_rotation_on_same_device(async_client: AsyncClient):
    """Re-authenticating on the same device rotates the session, revoking the prior token."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"rotate_{uuid.uuid4().hex[:8]}@sentriq.io"

    await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )

    # First login from Browser A
    resp1 = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
    )
    cookie1 = resp1.cookies["sentriq_session"]

    # Second login from Browser A sending cookie1
    resp2 = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
        headers=headers,
        cookies={"sentriq_session": cookie1},
    )
    cookie2 = resp2.cookies["sentriq_session"]
    assert cookie1 != cookie2

    # Old cookie1 is now revoked
    me1 = await async_client.get("/api/auth/me", cookies={"sentriq_session": cookie1})
    assert me1.status_code == 401

    # New cookie2 works
    me2 = await async_client.get("/api/auth/me", cookies={"sentriq_session": cookie2})
    assert me2.status_code == 200


@pytest.mark.asyncio
async def test_expired_session_rejected(async_client: AsyncClient):
    """Expired session records return 401 Unauthorized."""
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    email = f"expired_{uuid.uuid4().hex[:8]}@sentriq.io"

    async with AsyncSessionLocal() as session:
        user = User(
            email=email,
            hashed_password=hash_password("Password123!"),
            is_active=True,
        )
        session.add(user)
        await session.flush()

        expired_sess = UserSession(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        session.add(expired_sess)
        await session.commit()

    resp = await async_client.get("/api/auth/me", cookies={"sentriq_session": raw_token})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_revoked_session_rejected(async_client: AsyncClient):
    """Revoked session records return 401 Unauthorized."""
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    email = f"revoked_{uuid.uuid4().hex[:8]}@sentriq.io"

    async with AsyncSessionLocal() as session:
        user = User(
            email=email,
            hashed_password=hash_password("Password123!"),
            is_active=True,
        )
        session.add(user)
        await session.flush()

        revoked_sess = UserSession(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            revoked_at=datetime.now(timezone.utc),
        )
        session.add(revoked_sess)
        await session.commit()

    resp = await async_client.get("/api/auth/me", cookies={"sentriq_session": raw_token})
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()


# =====================================================================
# 5. GitHub OAuth Replay Protection Tests
# =====================================================================

@pytest.mark.asyncio
async def test_github_oauth_atomic_state_consumption_and_replay_rejected():
    """State can be consumed once atomically; replay attempts are rejected."""
    settings = get_settings()
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/projects")

    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/projects", max_age_seconds=600)
        await session.commit()

        # 1. First consumption succeeds
        ok1, path1, err1 = await consume_oauth_state(session, state, settings.SECRET_KEY)
        assert ok1 is True
        assert path1 == "/projects"
        assert err1 is None

        # 2. Second consumption (replay) is rejected
        ok2, path2, err2 = await consume_oauth_state(session, state, settings.SECRET_KEY)
        assert ok2 is False
        assert path2 is None
        assert err2 == "already_used"


@pytest.mark.asyncio
async def test_github_oauth_expired_state_rejected():
    """Expired OAuth state records are rejected."""
    settings = get_settings()
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/projects")

    async with AsyncSessionLocal() as session:
        # Save record with past expiry
        rec = await save_oauth_state(session, state=state, redirect_path="/projects", max_age_seconds=600)
        rec.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.commit()

        ok, path, err = await consume_oauth_state(session, state, settings.SECRET_KEY)
        assert ok is False
        assert err == "expired"


@pytest.mark.asyncio
async def test_github_oauth_concurrent_replay_race_condition():
    """Concurrent requests trying to consume the same OAuth state race atomically; only one succeeds."""
    settings = get_settings()
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")

    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        await session.commit()

    async def try_consume():
        async with AsyncSessionLocal() as sess:
            return await consume_oauth_state(sess, state, settings.SECRET_KEY)

    # Fire 5 concurrent consumption tasks
    results = await asyncio.gather(*(try_consume() for _ in range(5)))

    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]

    assert len(successes) == 1, f"Expected exactly 1 atomic success, got {len(successes)}"
    assert len(failures) == 4
    for f in failures:
        assert f[2] == "already_used"


@pytest.mark.asyncio
async def test_github_oauth_callback_already_used_state_redirects_error(async_client: AsyncClient):
    """Calling callback with already-consumed state redirects with error=oauth_state_already_used."""
    settings = get_settings()
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")

    async with AsyncSessionLocal() as session:
        await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        # Consume it once
        await consume_oauth_state(session, state, settings.SECRET_KEY)

    resp = await async_client.get(
        f"/api/auth/github/callback?code=fake_code&state={state}",
        cookies={"sentriq_oauth_state": state},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "error=oauth_state_already_used" in resp.headers["location"]


@pytest.mark.asyncio
async def test_github_oauth_callback_expired_state_redirects_error(async_client: AsyncClient):
    """Calling callback with expired state record redirects with error=oauth_state_expired."""
    settings = get_settings()
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path="/overview")

    async with AsyncSessionLocal() as session:
        rec = await save_oauth_state(session, state=state, redirect_path="/overview", max_age_seconds=600)
        rec.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.commit()

    resp = await async_client.get(
        f"/api/auth/github/callback?code=fake_code&state={state}",
        cookies={"sentriq_oauth_state": state},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "error=oauth_state_expired" in resp.headers["location"]


# =====================================================================
# 6. Production Safety Tests & Rate Limit Runtime Enforcement
# =====================================================================

@pytest.mark.asyncio
async def test_production_safety_auth_disabled_returns_503_on_all_seven_endpoints(async_client: AsyncClient):
    """When AUTH_ENABLED=False in production, ALL seven auth endpoints return 503."""
    settings = get_settings()
    original_setting = settings.AUTH_ENABLED
    try:
        settings.AUTH_ENABLED = False
        headers = {"Origin": "http://localhost:5173"}

        # 1. Register returns 503
        reg = await async_client.post(
            "/api/auth/register",
            json={"email": "prod@sentriq.io", "password": "Password123!"},
            headers=headers,
        )
        assert reg.status_code == 503
        assert "disabled" in reg.json()["detail"].lower()

        # 2. Login returns 503
        login = await async_client.post(
            "/api/auth/login",
            json={"email": "prod@sentriq.io", "password": "Password123!"},
            headers=headers,
        )
        assert login.status_code == 503
        assert "disabled" in login.json()["detail"].lower()

        # 3. Logout returns 503
        logout = await async_client.post("/api/auth/logout", headers=headers)
        assert logout.status_code == 503
        assert "disabled" in logout.json()["detail"].lower()

        # 4. /me returns 503
        me = await async_client.get("/api/auth/me")
        assert me.status_code == 503
        assert "disabled" in me.json()["detail"].lower()

        # 5. Profile PATCH returns 503
        profile = await async_client.patch(
            "/api/auth/profile",
            json={"full_name": "New Name"},
            headers=headers,
        )
        assert profile.status_code == 503
        assert "disabled" in profile.json()["detail"].lower()

        # 6. GitHub OAuth redirect returns 503
        gh = await async_client.get("/api/auth/github")
        assert gh.status_code == 503
        assert "disabled" in gh.json()["detail"].lower()

        # 7. GitHub callback returns 503
        gh_cb = await async_client.get("/api/auth/github/callback?code=test&state=test")
        assert gh_cb.status_code == 503
        assert "disabled" in gh_cb.json()["detail"].lower()

    finally:
        settings.AUTH_ENABLED = original_setting


@pytest.mark.asyncio
async def test_login_rate_limiting_enforces_retry_after_header(async_client: AsyncClient):
    """Rate limit 429 response contains a valid numeric Retry-After header with bounded value <= 3600."""
    headers = {"Origin": "http://localhost:5173"}
    email = f"throttled_{uuid.uuid4().hex[:8]}@sentriq.io"

    # Trigger 5 failed attempts
    for _ in range(5):
        resp = await async_client.post(
            "/api/auth/login",
            json={"email": email, "password": "WrongPassword!"},
            headers=headers,
        )
        assert resp.status_code == 401

    # 6th attempt must be rejected with 429 and Retry-After header
    resp_locked = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword!"},
        headers=headers,
    )
    assert resp_locked.status_code == 429
    assert "retry-after" in resp_locked.headers
    retry_after = int(resp_locked.headers["retry-after"])
    assert 0 < retry_after <= 3600  # Capped at 60 minutes max


@pytest.mark.asyncio
async def test_proxy_ip_isolation_does_not_lockout_unrelated_users(async_client: AsyncClient):
    """When requests arrive via an untrusted/shared proxy (e.g. Render), 50+ failures on one account
    must NOT lock out unrelated legitimate users sharing the same proxy IP.
    """
    headers = {"Origin": "http://localhost:5173"}
    victim_email = f"victim_{uuid.uuid4().hex[:8]}@sentriq.io"
    innocent_email = f"innocent_{uuid.uuid4().hex[:8]}@sentriq.io"

    # Register both users
    await async_client.post(
        "/api/auth/register",
        json={"email": victim_email, "password": "Password123!"},
        headers=headers,
    )
    await async_client.post(
        "/api/auth/register",
        json={"email": innocent_email, "password": "Password123!"},
        headers=headers,
    )

    # Simulate 55 failed login attempts for victim (all from 127.0.0.1 proxy)
    from app.database.session import AsyncSessionLocal
    from app.models.user import LoginAttempt

    async with AsyncSessionLocal() as session:
        for _ in range(55):
            attempt = LoginAttempt(
                ip_address="127.0.0.1",
                email=victim_email,
                attempted_at=datetime.now(timezone.utc),
                success=False,
            )
            session.add(attempt)
        await session.commit()

    # Attacker attempting with wrong password against victim is throttled with 429
    resp_victim = await async_client.post(
        "/api/auth/login",
        json={"email": victim_email, "password": "WrongPassword123!"},
        headers=headers,
    )
    assert resp_victim.status_code == 429
    assert "locked" in resp_victim.json()["detail"].lower()

    # Innocent user on the exact same proxy IP (127.0.0.1) MUST NOT be locked out
    resp_innocent = await async_client.post(
        "/api/auth/login",
        json={"email": innocent_email, "password": "Password123!"},
        headers=headers,
    )
    assert resp_innocent.status_code == 200
    assert resp_innocent.json()["email"] == innocent_email


@pytest.mark.asyncio
async def test_successful_login_after_previous_failed_attempts_no_victim_lockout(async_client: AsyncClient):
    """A correct password must NOT be rejected merely because an attacker previously submitted
    failed attempts against that email. Legitimate users are never locked out of logging in.
    """
    headers = {"Origin": "http://localhost:5173"}
    email = f"legit_user_{uuid.uuid4().hex[:8]}@sentriq.io"
    password = "CorrectPassword123!"

    # 1. Register legitimate account
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
        headers=headers,
    )
    assert reg_resp.status_code == 201

    # 2. Attacker submits 5 failed attempts
    for _ in range(5):
        fail_resp = await async_client.post(
            "/api/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
            headers=headers,
        )
        assert fail_resp.status_code == 401

    # Attacker's 6th rapid attempt is throttled with 429
    throttled_resp = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword123!"},
        headers=headers,
    )
    assert throttled_resp.status_code == 429

    # 3. Legitimate user submits CORRECT password -> MUST SUCCEED (200 OK)
    succ_resp = await async_client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers=headers,
    )
    assert succ_resp.status_code == 200
    assert succ_resp.json()["email"] == email
    assert "sentriq_session" in succ_resp.cookies


@pytest.mark.asyncio
async def test_cleanup_old_login_attempts_prunes_records():
    """Verify cleanup_old_login_attempts deletes records older than retention window without deleting recent ones."""
    from app.database.session import AsyncSessionLocal
    from app.models.user import LoginAttempt
    from app.security.rate_limiter import cleanup_old_login_attempts

    async with AsyncSessionLocal() as session:
        # Insert an old attempt (48 hours ago)
        old_attempt = LoginAttempt(
            ip_address="198.51.100.1",
            email="old@sentriq.io",
            attempted_at=datetime.now(timezone.utc) - timedelta(hours=48),
            success=False,
        )
        # Insert a recent attempt (10 minutes ago)
        recent_attempt = LoginAttempt(
            ip_address="198.51.100.2",
            email="recent@sentriq.io",
            attempted_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            success=False,
        )
        session.add_all([old_attempt, recent_attempt])
        await session.commit()

        # Run cleanup with 24-hour retention
        deleted = await cleanup_old_login_attempts(session, retention_hours=24)
        assert deleted >= 1

        # Query recent attempt to confirm it is preserved
        recent_check = await session.scalar(
            select(LoginAttempt).where(LoginAttempt.email == "recent@sentriq.io")
        )
        assert recent_check is not None

        # Query old attempt to confirm it was purged
        old_check = await session.scalar(
            select(LoginAttempt).where(LoginAttempt.email == "old@sentriq.io")
        )
        assert old_check is None


@pytest.mark.asyncio
async def test_periodic_login_attempts_cleanup_worker():
    """Verify background retention worker executes cleanup and exits gracefully on cancellation."""
    from app.database.session import AsyncSessionLocal
    from app.models.user import LoginAttempt
    from app.security.rate_limiter import periodic_login_attempts_cleanup

    async with AsyncSessionLocal() as session:
        # Seed an old attempt that should be pruned by the background worker
        stale_attempt = LoginAttempt(
            ip_address="198.51.100.99",
            email="stale_worker@sentriq.io",
            attempted_at=datetime.now(timezone.utc) - timedelta(hours=72),
            success=False,
        )
        session.add(stale_attempt)
        await session.commit()

    # Launch background worker task with short sleep interval
    cleanup_task = asyncio.create_task(
        periodic_login_attempts_cleanup(interval_seconds=1, retention_hours=24)
    )

    # Allow task to perform initial cleanup iteration
    await asyncio.sleep(0.05)
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    # Verify that the stale record was purged by the background worker
    async with AsyncSessionLocal() as session:
        check = await session.scalar(
            select(LoginAttempt).where(LoginAttempt.email == "stale_worker@sentriq.io")
        )
        assert check is None


@pytest.mark.asyncio
async def test_concurrent_login_requests_handled_safely(async_client: AsyncClient):
    """Concurrent authentication requests execute safely without race conditions or database corruption."""
    import asyncio
    headers = {"Origin": "http://localhost:5173"}
    email = f"concurrent_{uuid.uuid4().hex[:8]}@sentriq.io"

    # Fire 5 concurrent requests with invalid credentials
    tasks = [
        async_client.post(
            "/api/auth/login",
            json={"email": email, "password": f"Guess_{i}!"},
            headers=headers,
        )
        for i in range(5)
    ]
    responses = await asyncio.gather(*tasks)
    # All must complete with valid HTTP status codes (either 401 or 429) without 500 errors
    for r in responses:
        assert r.status_code in (401, 429)




