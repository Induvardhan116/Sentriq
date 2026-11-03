import hmac
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from fastapi import HTTPException, status
from sqlalchemy import select, update, delete
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.user import User
from app.models.finding_status_event import (
    FindingStatusEvent,
    AuditAnonymizationTicket,
    AuditConsumedNonce,
)

settings = get_settings()


def generate_anonymization_hmac(
    target_user_id: str,
    admin_user_id: str,
    nonce: str,
    secret_key: Optional[Any] = None,
    timestamp: Optional[int] = None,
) -> str:
    """Generate a constant-time HMAC-SHA256 signature for authorized audit anonymization."""
    if secret_key is None:
        key = settings.SECRET_KEY.encode("utf-8")
    elif isinstance(secret_key, str):
        key = secret_key.encode("utf-8")
    else:
        key = secret_key

    ts_part = f":{timestamp}" if timestamp is not None else ""
    payload = f"{target_user_id}:{admin_user_id}:{nonce}{ts_part}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_anonymization_hmac(
    target_user_id: str,
    admin_user_id: str,
    nonce: str,
    received_signature: str,
    secret_key: Optional[Any] = None,
    timestamp: Optional[int] = None,
) -> bool:
    """Verify an anonymization HMAC signature using double-digest constant-time comparison."""
    expected_sig = generate_anonymization_hmac(
        target_user_id=target_user_id,
        admin_user_id=admin_user_id,
        nonce=nonce,
        secret_key=secret_key,
        timestamp=timestamp,
    )
    # Double-digest comparison eliminates timing side-channel attacks
    d1 = hashlib.sha256(received_signature.encode("utf-8")).digest()
    d2 = hashlib.sha256(expected_sig.encode("utf-8")).digest()
    return hmac.compare_digest(d1, d2)


def anonymize_and_delete_user_sync(
    db: Session,
    caller_user: User,
    target_user_id: str,
    nonce: Optional[str] = None,
    timestamp: Optional[int] = None,
    signature: Optional[str] = None,
    secret_key: Optional[Any] = None,
) -> dict:
    """Synchronous authorized administrative account deletion and audit anonymization service."""
    if not caller_user.is_active or not caller_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Superuser privilege required for account anonymization.",
        )

    if caller_user.id == target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Safety Violation: Administrators cannot anonymize their own active account.",
        )

    target_user = db.get(User, target_user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target user with ID '{target_user_id}' does not exist.",
        )

    try:
        active_nonce = nonce or str(uuid.uuid4())

        # Cryptographic Verification if signature provided
        if signature is not None:
            if timestamp is not None:
                now_epoch = int(datetime.now(timezone.utc).timestamp())
                if abs(now_epoch - timestamp) > 60:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cryptographic verification failed: timestamp outside validity window.",
                    )

            if not verify_anonymization_hmac(
                target_user_id, caller_user.id, active_nonce, signature, secret_key=secret_key, timestamp=timestamp
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cryptographic verification failed: invalid authorization signature.",
                )

        # Persistent Nonce Replay Check
        existing_nonce = db.get(AuditConsumedNonce, active_nonce)
        if existing_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security Violation: Authorization nonce '{active_nonce}' has already been consumed.",
            )

        # Persistently record consumed nonce
        consumed_nonce_rec = AuditConsumedNonce(
            nonce=active_nonce,
            consumed_by=caller_user.id,
            consumed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        db.add(consumed_nonce_rec)
        db.flush()

        # Issue transient authorization ticket in the active transaction
        ticket_id = str(uuid.uuid4())
        ticket = AuditAnonymizationTicket(
            ticket_id=ticket_id,
            user_id=target_user_id,
            authorized_by=caller_user.id,
            nonce=active_nonce,
            created_at=datetime.now(timezone.utc),
        )
        db.add(ticket)
        db.flush()

        # Update finding_status_events: set user_id = NULL
        update_stmt = (
            update(FindingStatusEvent)
            .where(FindingStatusEvent.user_id == target_user_id)
            .values(user_id=None)
        )
        result = db.execute(update_stmt)
        events_anonymized = result.rowcount

        # Consume ticket
        del_ticket_stmt = delete(AuditAnonymizationTicket).where(
            AuditAnonymizationTicket.ticket_id == ticket_id
        )
        db.execute(del_ticket_stmt)

        # Delete target user record
        db.delete(target_user)

        db.commit()
        return {
            "target_user_id": target_user_id,
            "events_anonymized": events_anonymized,
            "nonce": active_nonce,
            "status": "anonymized",
        }
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete user anonymization and account deletion.",
        ) from exc


async def anonymize_and_delete_user(
    db: AsyncSession,
    caller_user: User,
    target_user_id: str,
    nonce: Optional[str] = None,
    timestamp: Optional[int] = None,
    signature: Optional[str] = None,
    secret_key: Optional[Any] = None,
) -> dict:
    """Async authorized administrative account deletion and audit anonymization service."""
    if not caller_user.is_active or not caller_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Superuser privilege required for account anonymization.",
        )

    if caller_user.id == target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Safety Violation: Administrators cannot anonymize their own active account.",
        )

    target_stmt = select(User).where(User.id == target_user_id)
    target_user = (await db.execute(target_stmt)).scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target user with ID '{target_user_id}' does not exist.",
        )

    try:
        active_nonce = nonce or str(uuid.uuid4())

        # Cryptographic Verification if signature provided
        if signature is not None:
            if timestamp is not None:
                now_epoch = int(datetime.now(timezone.utc).timestamp())
                if abs(now_epoch - timestamp) > 60:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cryptographic verification failed: timestamp outside validity window.",
                    )

            if not verify_anonymization_hmac(
                target_user_id, caller_user.id, active_nonce, signature, secret_key=secret_key, timestamp=timestamp
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cryptographic verification failed: invalid authorization signature.",
                )

        # Persistent Nonce Replay Check
        nonce_stmt = select(AuditConsumedNonce).where(AuditConsumedNonce.nonce == active_nonce)
        existing_nonce = (await db.execute(nonce_stmt)).scalar_one_or_none()
        if existing_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security Violation: Authorization nonce '{active_nonce}' has already been consumed.",
            )

        # Persistently record consumed nonce
        consumed_nonce_rec = AuditConsumedNonce(
            nonce=active_nonce,
            consumed_by=caller_user.id,
            consumed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        db.add(consumed_nonce_rec)
        await db.flush()

        # Issue transient authorization ticket in the active transaction
        ticket_id = str(uuid.uuid4())
        ticket = AuditAnonymizationTicket(
            ticket_id=ticket_id,
            user_id=target_user_id,
            authorized_by=caller_user.id,
            nonce=active_nonce,
            created_at=datetime.now(timezone.utc),
        )
        db.add(ticket)
        await db.flush()

        # Update finding_status_events: set user_id = NULL
        update_stmt = (
            update(FindingStatusEvent)
            .where(FindingStatusEvent.user_id == target_user_id)
            .values(user_id=None)
        )
        result = await db.execute(update_stmt)
        events_anonymized = result.rowcount

        # Consume ticket
        del_ticket_stmt = delete(AuditAnonymizationTicket).where(
            AuditAnonymizationTicket.ticket_id == ticket_id
        )
        await db.execute(del_ticket_stmt)

        # Delete target user record
        del_user_stmt = delete(User).where(User.id == target_user_id)
        await db.execute(del_user_stmt)

        await db.commit()
        return {
            "target_user_id": target_user_id,
            "events_anonymized": events_anonymized,
            "nonce": active_nonce,
            "status": "anonymized",
        }
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete user anonymization and account deletion.",
        ) from exc


class AdminAccountService:
    """Unified application authorization boundary for administrative user management."""

    @staticmethod
    def anonymize_and_delete_user(
        db: Any,
        caller_user: Optional[User] = None,
        target_user_id: str = "",
        nonce: Optional[str] = None,
        timestamp: Optional[int] = None,
        signature: Optional[str] = None,
        secret_key: Optional[Any] = None,
        current_user: Optional[User] = None,
    ) -> Any:
        actor = caller_user or current_user
        if actor is None:
            raise ValueError("Caller user must be provided.")
        if isinstance(db, Session):
            return anonymize_and_delete_user_sync(
                db=db,
                caller_user=actor,
                target_user_id=target_user_id,
                nonce=nonce,
                timestamp=timestamp,
                signature=signature,
                secret_key=secret_key,
            )
        return anonymize_and_delete_user(
            db=db,
            caller_user=actor,
            target_user_id=target_user_id,
            nonce=nonce,
            timestamp=timestamp,
            signature=signature,
            secret_key=secret_key,
        )
