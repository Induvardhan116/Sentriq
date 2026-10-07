from datetime import datetime, timezone
from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, declared_attr


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy models."""

    @declared_attr.directive
    def __tablename__(cls) -> str:
        # Default table name: lowercase class name + 's'
        return f"{cls.__name__.lower()}s"


class TimestampMixin:
    """Provides created_at and updated_at datetime tracking."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
