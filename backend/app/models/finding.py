import uuid
from typing import Optional, TYPE_CHECKING
from sqlalchemy import String, Integer, Float, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class Finding(Base, TimestampMixin):
    """Normalized security finding produced by scanner checks."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String(32), default="web", nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default="open", nullable=False, index=True
    )  # open, in_progress, resolved, false_positive

    # Relationship
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
