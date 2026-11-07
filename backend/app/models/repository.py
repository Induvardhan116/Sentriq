import uuid
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User


class Repository(Base, TimestampMixin):
    """Monitored source code repository target."""

    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "org/repo"
    clone_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(64), default="main", nullable=False)
    languages: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)  # JSON or comma-separated
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    owner_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    latest_posture_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    latest_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    owner: Mapped[Optional["User"]] = relationship("User", lazy="selectin")
    scans: Mapped[List["RepoScan"]] = relationship(
        "RepoScan",
        back_populates="repository",
        cascade="all, delete-orphan",
        order_by="desc(RepoScan.created_at)",
        lazy="selectin",
    )


class RepoScan(Base, TimestampMixin):
    """Source code repository security assessment scan."""

    __tablename__ = "repo_scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True
    )
    branch: Mapped[str] = mapped_column(String(64), default="main", nullable=False)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default="queued", nullable=False, index=True
    )  # queued, running, completed, failed

    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Posture scoring & metrics
    posture_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    secret_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sast_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sca_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    repository: Mapped["Repository"] = relationship("Repository", back_populates="scans")
    findings: Mapped[List["RepoFinding"]] = relationship(
        "RepoFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="desc(RepoFinding.risk_score)",
        lazy="selectin",
    )


class RepoFinding(Base, TimestampMixin):
    """Normalized security finding discovered within source code or dependencies."""

    __tablename__ = "repo_findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repo_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # secret, sast, sca
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # critical, high, medium, low, informational
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    cwe: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cve: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Code evidence snippet (secrets strictly masked)
    snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default="open", nullable=False, index=True
    )  # open, resolved, false_positive, accepted_risk
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    scan: Mapped["RepoScan"] = relationship("RepoScan", back_populates="findings")
