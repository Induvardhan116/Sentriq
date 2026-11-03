import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.session import get_db
from app.models.user import User, UserSession, OAuthAccount
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserProfileUpdateRequest,
    UserResponse,
    CSRFTokenResponse,
    AuthMessageResponse,
    UserAnonymizeRequest,
    UserAnonymizeResponse,
)
from app.services.account_service import AdminAccountService
from app.security.hasher import hash_password, verify_password, needs_rehash, dummy_verify
from app.security.limiter import is_account_locked
from app.security.session import generate_session_token, hash_session_token
from app.security.csrf import generate_session_csrf_token
from app.security.oauth import (
    generate_oauth_state,
    verify_oauth_state,
    save_oauth_state,
    consume_oauth_state,
    build_github_authorization_url,
    validate_github_account_linking,
)
from app.security.deps import (
    get_current_user_and_session,
    get_current_user,
    require_csrf,
    validate_pre_auth_csrf,
    get_verified_client_ip,
)
from app.security.rate_limiter import (
    check_login_rate_limit,
    on_login_failure,
    on_login_success,
)

logger = logging.getLogger("sentriq.api.auth")
settings = get_settings()


def require_auth_enabled() -> None:
    """Gatekeeper dependency enforcing that authentication is enabled in the current environment."""
    current_settings = get_settings()
    if not current_settings.AUTH_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is currently disabled for production safety until same-origin/same-site architecture is provisioned.",
        )


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    dependencies=[Depends(require_auth_enabled)],
)


def _set_session_cookie(response: Response, raw_token: str) -> None:
    """Set the Secure, HttpOnly session cookie on the response."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_EXPIRE_DAYS * 86400,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    """Clear the session cookie upon logout."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(validate_pre_auth_csrf)],
)
async def register_user(
    payload: UserRegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account with Argon2id password hashing and automatic session establishment."""
    client_ip = get_verified_client_ip(request)

    # 1. Check if email already exists
    existing = await db.scalar(select(User).where(User.email == payload.email))
    if existing:
        logger.warning("Registration attempt rejected: email already exists (%s)", payload.email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    # 2. Hash password with Argon2id (never accept or trust is_superuser from input)
    hashed_pwd = hash_password(payload.password)
    user = User(
        email=payload.email,
        hashed_password=hashed_pwd,
        full_name=payload.full_name,
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    await db.flush()

    # 3. Create initial authenticated session
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent", "")[:512],
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.SESSION_EXPIRE_DAYS),
    )
    db.add(session)
    await db.flush()

    # 4. Set HttpOnly cookie and generate session-bound CSRF token
    _set_session_cookie(response, raw_token)
    csrf_token = generate_session_csrf_token(token_hash, settings.SECRET_KEY)

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at,
        csrf_token=csrf_token,
    )


@router.post(
    "/login",
    response_model=UserResponse,
    dependencies=[Depends(validate_pre_auth_csrf)],
)
async def login_user(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with email and password, establishing an HttpOnly session cookie."""
    client_ip = get_verified_client_ip(request)
    clean_email = payload.email.strip().lower()

    # 1. Lookup user by normalized email
    user = await db.scalar(select(User).where(User.email == clean_email))

    # 2. Check active account status
    if user and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    # 3. Verify credentials with timing equalization
    is_valid_pwd = False
    if user and user.hashed_password:
        is_valid_pwd = verify_password(payload.password, user.hashed_password)
    else:
        dummy_verify()

    # 4. If credentials are NOT valid, enforce progressive throttling and IP flood checks
    if not is_valid_pwd:
        allowed, err_msg, retry_after = await check_login_rate_limit(db, clean_email, client_ip, user)
        await on_login_failure(db, clean_email, client_ip, user)
        if not allowed:
            headers = {}
            if retry_after is not None and retry_after > 0:
                headers["Retry-After"] = str(retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=err_msg,
                headers=headers or None,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    # 5. Credentials are valid!
    # "A correct password must not be rejected merely because someone previously submitted failed attempts against that email."
    if user and is_account_locked(user.locked_until):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is temporarily locked.",
        )

    # Check if password hash needs rehash
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)
        await db.flush()

    # Reset failure counter and clear failed attempts for this email on success
    await on_login_success(db, clean_email, client_ip, user)

    # 7. Session rotation: invalidate any prior session cookie if present
    prior_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if prior_cookie:
        prior_hash = hash_session_token(prior_cookie)
        prior_session = await db.scalar(select(UserSession).where(UserSession.token_hash == prior_hash))
        if prior_session:
            prior_session.revoked_at = datetime.now(timezone.utc)

    # 8. Create new fresh session
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    new_session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent", "")[:512],
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.SESSION_EXPIRE_DAYS),
    )
    db.add(new_session)
    await db.flush()

    _set_session_cookie(response, raw_token)
    csrf_token = generate_session_csrf_token(token_hash, settings.SECRET_KEY)

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at,
        csrf_token=csrf_token,
    )


@router.post(
    "/logout",
    response_model=AuthMessageResponse,
    dependencies=[Depends(require_csrf)],
)
async def logout_user(
    response: Response,
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the current session and clear session cookies."""
    _, session = user_and_session
    session.revoked_at = datetime.now(timezone.utc)
    await db.flush()

    _clear_session_cookie(response)
    return AuthMessageResponse(message="Logged out successfully.")


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
):
    """Retrieve authenticated user profile and refresh the in-memory anti-CSRF token."""
    user, session = user_and_session
    csrf_token = generate_session_csrf_token(session.token_hash, settings.SECRET_KEY)
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at,
        csrf_token=csrf_token,
    )


@router.patch(
    "/profile",
    response_model=UserResponse,
    dependencies=[Depends(require_csrf)],
)
async def update_user_profile(
    payload: UserProfileUpdateRequest,
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    db: AsyncSession = Depends(get_db),
):
    """Update profile metadata (full name, avatar URL) for authenticated user."""
    user, session = user_and_session
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.avatar_url is not None:
        user.avatar_url = payload.avatar_url

    await db.flush()
    csrf_token = generate_session_csrf_token(session.token_hash, settings.SECRET_KEY)

    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at,
        csrf_token=csrf_token,
    )


# =====================================================================
# GitHub OAuth Flow
# =====================================================================

@router.get("/github")
async def github_oauth_redirect(
    response: Response,
    redirect_path: str = "/overview",
    db: AsyncSession = Depends(get_db),
):
    """Initiate GitHub OAuth flow with signed state cookie and server-side state record."""
    if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured on this server.",
        )

    # Generate tamper-resistant signed state token
    state = generate_oauth_state(settings.SECRET_KEY, redirect_path=redirect_path)

    # Persist one-time state record in database for replay protection
    await save_oauth_state(db, state=state, redirect_path=redirect_path, max_age_seconds=600)

    # Set temporary state verification cookie (10 minute lifespan)
    response.set_cookie(
        key="sentriq_oauth_state",
        value=state,
        max_age=600,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    auth_url = build_github_authorization_url(
        client_id=settings.GITHUB_CLIENT_ID,
        redirect_uri=settings.GITHUB_REDIRECT_URI or "",
        state=state,
    )
    return RedirectResponse(auth_url)


@router.get("/github/callback")
async def github_oauth_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Process GitHub OAuth callback, enforce account linking rules, and establish session."""
    client_ip = get_verified_client_ip(request)

    # 1. Server-side atomic state consumption and cryptographic verification
    is_consumed, redirect_path, error_reason = await consume_oauth_state(
        db, state=state, secret_key=settings.SECRET_KEY, max_age_seconds=600
    )
    cookie_state = request.cookies.get("sentriq_oauth_state")

    # One-time replay protection: clean state cookie immediately
    response.delete_cookie(
        key="sentriq_oauth_state",
        path="/",
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
    )

    if not is_consumed or not cookie_state or cookie_state != state:
        logger.warning("GitHub OAuth callback rejected: reason=%s", error_reason)
        err_code = "invalid_oauth_state"
        if error_reason == "already_used":
            err_code = "oauth_state_already_used"
        elif error_reason == "expired":
            err_code = "oauth_state_expired"
        return RedirectResponse(
            f"{settings.FRONTEND_URL}/#/login?error={err_code}",
            status_code=status.HTTP_302_FOUND,
        )

    # 2. Exchange authorization code for access token via server-side backchannel
    token_url = "https://github.com/login/oauth/access_token"
    token_params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
    }
    headers = {"Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(token_url, json=token_params, headers=headers)
            token_data = token_resp.json()
            access_token = token_data.get("access_token")

            if not access_token:
                logger.error("GitHub OAuth code exchange failed: %s", token_data)
                return RedirectResponse(
                    f"{settings.FRONTEND_URL}/#/login?error=oauth_token_exchange_failed",
                    status_code=status.HTTP_302_FOUND,
                )

            # 3. Retrieve GitHub user profile
            user_resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            gh_user = user_resp.json()
            gh_id = str(gh_user.get("id"))
            gh_username = gh_user.get("login")
            gh_name = gh_user.get("name") or gh_username
            gh_avatar = gh_user.get("avatar_url")

            # 4. Retrieve primary verified email
            emails_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            emails_data = emails_resp.json() if emails_resp.status_code == 200 else []
            primary_email = None
            if isinstance(emails_data, list):
                for em in emails_data:
                    if em.get("primary") and em.get("verified"):
                        primary_email = em.get("email")
                        break
            if not primary_email:
                primary_email = gh_user.get("email")

            if not primary_email:
                logger.error("No verified primary email found for GitHub user %s", gh_username)
                return RedirectResponse(
                    f"{settings.FRONTEND_URL}/#/login?error=oauth_no_verified_email",
                    status_code=status.HTTP_302_FOUND,
                )

            primary_email = primary_email.strip().lower()

    except Exception as e:
        logger.exception("GitHub OAuth backchannel request failed: %s", e)
        return RedirectResponse(
            f"{settings.FRONTEND_URL}/#/login?error=oauth_communication_error",
            status_code=status.HTTP_302_FOUND,
        )

    # 5. Check existing user and OAuth link
    existing_oauth = await db.scalar(
        select(OAuthAccount).where(
            OAuthAccount.provider == "github",
            OAuthAccount.provider_account_id == gh_id,
        )
    )
    existing_user = await db.scalar(select(User).where(User.email == primary_email))

    # 6. CRITICAL SECURITY CHECK: Account Linking Enforcement
    allowed, link_err = validate_github_account_linking(existing_user, existing_oauth, primary_email)
    if not allowed:
        logger.warning("OAuth auto-linking blocked: %s", link_err)
        return RedirectResponse(
            f"{settings.FRONTEND_URL}/#/login?error=account_link_required",
            status_code=status.HTTP_302_FOUND,
        )

    # 7. Resolve or create user entity
    if existing_oauth:
        user = await db.scalar(select(User).where(User.id == existing_oauth.user_id))
        if not user or not user.is_active:
            return RedirectResponse(
                f"{settings.FRONTEND_URL}/#/login?error=account_deactivated",
                status_code=status.HTTP_302_FOUND,
            )
    elif existing_user:
        user = existing_user
        # Link GitHub identity
        new_oauth = OAuthAccount(
            user_id=user.id,
            provider="github",
            provider_account_id=gh_id,
            provider_username=gh_username,
            provider_email=primary_email,
        )
        db.add(new_oauth)
        await db.flush()
    else:
        # Create brand-new user via GitHub OAuth (password is NULL)
        user = User(
            email=primary_email,
            hashed_password=None,
            full_name=gh_name,
            avatar_url=gh_avatar,
            is_active=True,
            is_superuser=False,
        )
        db.add(user)
        await db.flush()

        new_oauth = OAuthAccount(
            user_id=user.id,
            provider="github",
            provider_account_id=gh_id,
            provider_username=gh_username,
            provider_email=primary_email,
        )
        db.add(new_oauth)
        await db.flush()

    # 8. Session rotation: invalidate prior session cookie on this client if present
    prior_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if prior_cookie:
        prior_hash = hash_session_token(prior_cookie)
        prior_session = await db.scalar(
            select(UserSession).where(UserSession.token_hash == prior_hash)
        )
        if prior_session:
            prior_session.revoked_at = datetime.now(timezone.utc)

    # 9. Create fresh authenticated session
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent", "")[:512],
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.SESSION_EXPIRE_DAYS),
    )
    db.add(session)
    await db.flush()

    # 10. Redirect cleanly to destination path without any tokens in URL
    target_hash = f"#{redirect_path}" if redirect_path.startswith("/") else f"#/{redirect_path}"
    redirect_target = f"{settings.FRONTEND_URL}/{target_hash}"
    final_response = RedirectResponse(redirect_target, status_code=status.HTTP_302_FOUND)
    _set_session_cookie(final_response, raw_token)

    return final_response


@router.post(
    "/users/{user_id}/anonymize",
    response_model=UserAnonymizeResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_csrf)],
)
async def admin_anonymize_user(
    user_id: str,
    payload: Optional[UserAnonymizeRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
):
    """Authorized administrative account anonymization and deletion endpoint."""
    caller_user, _ = current_user_and_session
    req_nonce = payload.nonce if payload else None
    req_timestamp = payload.timestamp if payload else None
    req_signature = payload.signature if payload else None
    return await AdminAccountService.anonymize_and_delete_user(
        db=db,
        caller_user=caller_user,
        target_user_id=user_id,
        nonce=req_nonce,
        timestamp=req_timestamp,
        signature=req_signature,
    )

