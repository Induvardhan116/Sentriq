import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserSession
from app.models.settings import UserSettings
from app.schemas.settings import (
    UserProfileUpdate,
    PasswordChangeRequest,
    UserSessionItem,
    UserSettingsResponse,
    UserSettingsUpdate,
)
from app.security.hasher import hash_password, verify_password

logger = logging.getLogger("sentriq.services.settings")


class SettingsService:
    @classmethod
    async def get_profile(cls, user: User) -> User:
        """Return the current user profile."""
        return user

    @classmethod
    async def update_profile(
        cls, db: AsyncSession, user: User, payload: UserProfileUpdate
    ) -> User:
        """Update user profile display attributes."""
        user.full_name = payload.full_name.strip()
        await db.commit()
        await db.refresh(user)
        return user

    @classmethod
    async def change_password(
        cls, db: AsyncSession, user: User, payload: PasswordChangeRequest
    ) -> Dict[str, str]:
        """Validate existing password and update with strong hashed password."""
        if not user.hashed_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account authenticated via OAuth does not have a local password set.",
            )

        if not verify_password(payload.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password provided.",
            )

        if len(payload.new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 8 characters long.",
            )

        user.hashed_password = hash_password(payload.new_password)
        await db.commit()
        return {"message": "Password changed successfully."}

    @classmethod
    async def list_active_sessions(
        cls, db: AsyncSession, user: User, current_token_hash: Optional[str]
    ) -> List[UserSessionItem]:
        """List active unrevoked and unexpired user sessions."""
        now = datetime.now(timezone.utc)
        stmt = (
            select(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
            )
            .order_by(UserSession.created_at.desc())
        )
        result = await db.execute(stmt)
        sessions = result.scalars().all()

        output: List[UserSessionItem] = []
        for s in sessions:
            is_current = bool(current_token_hash and s.token_hash == current_token_hash)
            output.append(
                UserSessionItem(
                    id=s.id,
                    ip_address=s.ip_address,
                    user_agent=s.user_agent,
                    created_at=s.created_at,
                    expires_at=s.expires_at,
                    is_current=is_current,
                )
            )
        return output

    @classmethod
    async def revoke_session(
        cls, db: AsyncSession, user: User, session_id: str
    ) -> Dict[str, str]:
        """Revoke a specific active user session."""
        stmt = select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user.id,
        )
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or access denied.",
            )

        session.revoked_at = datetime.now(timezone.utc)
        await db.commit()
        return {"message": "Session revoked successfully."}

    @classmethod
    async def revoke_all_other_sessions(
        cls, db: AsyncSession, user: User, current_token_hash: Optional[str]
    ) -> Dict[str, Any]:
        """Revoke all active sessions belonging to the user except the current one."""
        now = datetime.now(timezone.utc)
        stmt = (
            update(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
                UserSession.token_hash != current_token_hash if current_token_hash else True,
            )
            .values(revoked_at=now)
        )
        result = await db.execute(stmt)
        await db.commit()
        return {"message": "All other sessions revoked successfully.", "revoked_count": result.rowcount}

    @classmethod
    async def get_or_create_user_settings(
        cls, db: AsyncSession, user: User
    ) -> UserSettings:
        """Fetch or initialize default preferences for the user."""
        stmt = select(UserSettings).where(UserSettings.user_id == user.id)
        result = await db.execute(stmt)
        settings_row = result.scalar_one_or_none()
        if not settings_row:
            settings_row = UserSettings(user_id=user.id)
            db.add(settings_row)
            await db.commit()
            await db.refresh(settings_row)
        return settings_row

    @classmethod
    async def update_user_settings(
        cls, db: AsyncSession, user: User, payload: UserSettingsUpdate
    ) -> UserSettings:
        """Update scanner, notification, and account preferences."""
        settings_row = await cls.get_or_create_user_settings(db, user)
        update_data = payload.model_dump(exclude_unset=True)
        for key, val in update_data.items():
            if val is not None:
                setattr(settings_row, key, val)
        await db.commit()
        await db.refresh(settings_row)
        return settings_row
