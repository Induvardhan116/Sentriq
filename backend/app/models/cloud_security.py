import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import String, Integer, Float, Boolean, Text, ForeignKey, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class CloudAccount(Base, TimestampMixin):
    """Registered cloud environment or PaaS tenant for CSPM posture checks."""

    __tablename__ = "cloud_accounts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # aws, gcp, supabase, azure
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    account_identifier: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g. AWS 12-digit ID or project ref
    role_arn_or_ref: Mapped[str] = mapped_column(String(255), nullable=False)  # Read-only audit IAM role ARN or ref
    region: Mapped[str] = mapped_column(String(64), default="us-east-1", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    posture_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    findings: Mapped[List["CloudFinding"]] = relationship(
        "CloudFinding",
        back_populates="account",
        cascade="all, delete-orphan",
        order_by="desc(CloudFinding.risk_score)",
        lazy="selectin",
    )


class CloudFinding(Base, TimestampMixin):
    """CSPM configuration compliance violation mapped to CIS benchmark or cloud security standard."""

    __tablename__ = "cloud_findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    service: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # s3, iam, ec2, rds, storage, rls
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    benchmark_ref: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # CIS-AWS-1.4, etc.

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # critical, high, medium, low
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="findings")
