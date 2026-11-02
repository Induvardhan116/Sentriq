from datetime import datetime, timezone
from typing import Optional, Tuple
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.session import get_db
from app.models.user import User, UserSession
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.security.session import hash_session_token, validate_session_token_format
from app.security.csrf import verify_session_csrf_token, validate_request_origin
from app.security.limiter import extract_client_ip, is_account_locked

settings = get_settings()


def get_verified_client_ip(request: Request) -> str:
    """Extract verified client IP address according to trusted proxy security policy."""
    client_host = request.client.host if request.client else "127.0.0.1"
    headers_dict = dict(request.headers)
    return extract_client_ip(
        headers=headers_dict,
        client_host=client_host,
        trusted_proxies=settings.TRUSTED_PROXIES,
        trust_proxy_headers=settings.TRUST_PROXY_HEADERS,
    )


async def get_current_user_and_session(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Tuple[User, UserSession]:
    """Dependency that authenticates the user exclusively via HttpOnly session cookies."""
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not cookie_token or not validate_session_token_format(cookie_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. No valid session cookie found.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    token_hash = hash_session_token(cookie_token)

    query = (
        select(UserSession)
        .options(selectinload(UserSession.user))
        .where(UserSession.token_hash == token_hash)
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session or not session.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid, expired, or revoked.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    user = session.user
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    if is_account_locked(user.locked_until):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is temporarily locked.",
        )

    return user, session


async def get_current_user(
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
) -> User:
    """Convenience dependency returning the authenticated User."""
    return user_and_session[0]


async def get_optional_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Optionally returns authenticated User, or None if unauthenticated."""
    try:
        user, _ = await get_current_user_and_session(request=request, db=db)
        return user
    except HTTPException:
        return None


async def require_csrf(
    request: Request,
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
) -> None:
    """Enforce CSRF validation for state-changing browser requests."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        # 1. Validate Origin / Referer
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        if not validate_request_origin(origin, referer, settings.CORS_ORIGINS):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-origin request rejected: Origin or Referer does not match allowed domains.",
            )

        # 2. Validate session-bound X-CSRF-Token header
        header_csrf = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")
        _, session = user_and_session
        if not verify_session_csrf_token(header_csrf, session.token_hash, settings.SECRET_KEY):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing anti-CSRF token.",
            )


async def validate_pre_auth_csrf(request: Request) -> None:
    """Protect unauthenticated state-changing endpoints (login, register) against login CSRF."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        # For browsers, mutating requests include Origin; must match CORS whitelist
        if not validate_request_origin(origin, referer, settings.CORS_ORIGINS):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-origin request rejected: Origin or Referer does not match allowed domains.",
            )


async def get_authenticated_user_or_dev_mode(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Dependency for multi-tenant resource endpoints (projects, scans, findings).

    Security Invariants (Phase 3.4):
    - When AUTH_ENABLED=True: Strictly enforces user authentication. Any missing,
      expired, or revoked session cookie immediately raises HTTP 401 Unauthorized.
      Optional fallback is prohibited when auth is active.
    - When AUTH_ENABLED=False: Preserves backward compatibility for local development.
      Returns the authenticated User if a valid session exists, otherwise returns None.
    """
    if settings.AUTH_ENABLED:
        user, _ = await get_current_user_and_session(request=request, db=db)
        return user
    else:
        try:
            user, _ = await get_current_user_and_session(request=request, db=db)
            return user
        except HTTPException:
            return None


def verify_project_access(
    project: Optional[Project],
    user: Optional[User],
    project_id: Optional[str] = None,
) -> Project:
    """Enforce ownership isolation on a project.

    Returns the project if accessible.
    Raises HTTPException(404 Not Found) if:
    - Project does not exist.
    - settings.AUTH_ENABLED is True and the caller is neither a superuser nor the owner.

    Returning 404 for unowned projects eliminates cross-tenant resource enumeration (IDOR).
    """
    detail_msg = f"Project with ID '{project_id}' does not exist." if project_id else "Project not found."
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail_msg,
        )

    if settings.AUTH_ENABLED:
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. No valid session cookie found.",
                headers={"WWW-Authenticate": "Cookie"},
            )
        if not user.is_superuser and project.owner_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=detail_msg,
            )

    return project


def verify_scan_access(
    scan: Optional[Scan],
    user: Optional[User],
    scan_id: Optional[str] = None,
) -> Scan:
    """Enforce ownership isolation on a scan through its parent Project."""
    detail_msg = f"Scan with ID '{scan_id}' does not exist." if scan_id else "Scan not found."
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail_msg,
        )
    if not scan.project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parent project not found.",
        )
    verify_project_access(scan.project, user, scan.project_id)
    return scan


def verify_finding_access(
    finding: Optional[Finding],
    user: Optional[User],
    finding_id: Optional[str] = None,
) -> Finding:
    """Enforce ownership isolation on a finding through its parent Scan and Project."""
    detail_msg = f"Finding with ID '{finding_id}' does not exist." if finding_id else "Finding not found."
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail_msg,
        )
    if not finding.scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parent scan not found.",
        )
    verify_scan_access(finding.scan, user, finding.scan_id)
    return finding


async def require_csrf_if_auth_enabled(
    request: Request,
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
) -> None:
    """Enforce CSRF validation for mutating requests when authentication is active."""
    if settings.AUTH_ENABLED and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        if origin or referer:
            if not validate_request_origin(origin, referer, settings.CORS_ORIGINS):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-origin request rejected: Origin or Referer does not match allowed domains.",
                )

        cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if cookie_token and validate_session_token_format(cookie_token):
            header_csrf = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")
            token_hash = hash_session_token(cookie_token)
            if not verify_session_csrf_token(header_csrf, token_hash, settings.SECRET_KEY):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid or missing anti-CSRF token.",
                )
