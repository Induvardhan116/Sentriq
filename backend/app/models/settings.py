import uuid
from typing import Optional
from sqlalchemy import String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class UserSettings(Base, TimestampMixin):
    """User preferences entity storing scanner, notification, and account security controls."""

    __tablename__ = "user_settings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )

    # Scanner Preferences
    scanner_timeout_seconds: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    scanner_max_redirects: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    scanner_verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scanner_strict_headers: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Notification Preferences
    notify_email_scan_completed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_email_critical_finding: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_webhook_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Default Project Settings & UI
    default_scan_cadence: Mapped[str] = mapped_column(String(32), default="weekly", nullable=False)
    theme: Mapped[str] = mapped_column(String(32), default="dark", nullable=False)

    # Account Security Controls
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, default=10080, nullable=False)
