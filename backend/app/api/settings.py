import logging
from typing import Optional, List, Dict, Any, Tuple
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User, UserSession
from app.schemas.settings import (
    UserProfileUpdate,
    UserProfileResponse,
    PasswordChangeRequest,
    UserSessionItem,
    UserSettingsResponse,
    UserSettingsUpdate,
)
from app.services.settings_service import SettingsService
from app.security.deps import (
    get_current_user_and_session,
    require_csrf_if_auth_enabled,
)

logger = logging.getLogger("sentriq.api.settings")
router = APIRouter(prefix="/settings", tags=["Settings & Session Management"])


@router.get("/profile", response_model=UserProfileResponse)
async def get_profile(
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
):
    """Retrieve profile details of the authenticated user."""
    user, _ = user_and_session
    return await SettingsService.get_profile(user)


@router.patch("/profile", response_model=UserProfileResponse)
async def update_profile(
    payload: UserProfileUpdate,
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update profile information (e.g. full display name)."""
    user, _ = user_and_session
    return await SettingsService.update_profile(db=db, user=user, payload=payload)


@router.post("/password")
async def change_password(
    payload: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Change user password, verifying existing password first."""
    user, _ = user_and_session
    return await SettingsService.change_password(db=db, user=user, payload=payload)


@router.get("/sessions", response_model=List[UserSessionItem])
async def list_active_sessions(
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
):
    """List all active unexpired and unrevoked user sessions."""
    user, current_session = user_and_session
    return await SettingsService.list_active_sessions(
        db=db, user=user, current_token_hash=current_session.token_hash
    )


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Revoke a specific active user session."""
    user, _ = user_and_session
    return await SettingsService.revoke_session(db=db, user=user, session_id=session_id)


@router.post("/sessions/revoke-others")
async def revoke_other_sessions(
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Revoke all active sessions belonging to the user except the current session."""
    user, current_session = user_and_session
    return await SettingsService.revoke_all_other_sessions(
        db=db, user=user, current_token_hash=current_session.token_hash
    )


@router.get("/preferences", response_model=UserSettingsResponse)
async def get_user_preferences(
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
):
    """Retrieve scanner, notification, and account preferences."""
    user, _ = user_and_session
    return await SettingsService.get_or_create_user_settings(db=db, user=user)


@router.patch("/preferences", response_model=UserSettingsResponse)
async def update_user_preferences(
    payload: UserSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user_and_session: Tuple[User, UserSession] = Depends(get_current_user_and_session),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update scanner, notification, and account preferences."""
    user, _ = user_and_session
    return await SettingsService.update_user_settings(db=db, user=user, payload=payload)
