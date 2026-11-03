import uuid
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING
from sqlalchemy import String, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.user import User


class FindingStatusEvent(Base):
    """Immutable audit record capturing status transitions and justification for security findings."""

    __tablename__ = "finding_status_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    previous_status: Mapped[str] = mapped_column(String(32), nullable=False)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="status_events")
    user: Mapped[Optional["User"]] = relationship("User", lazy="selectin")


class AuditAnonymizationTicket(Base):
    """Transient authorization ticket for account anonymization within an active transaction."""

    __tablename__ = "audit_anonymization_ticket"

    ticket_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    authorized_by: Mapped[str] = mapped_column(String(36), nullable=False)
    nonce: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AuditConsumedNonce(Base):
    """Persistent ledger of consumed authorization nonces preventing replay attacks."""

    __tablename__ = "audit_consumed_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    consumed_by: Mapped[str] = mapped_column(String(36), nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
