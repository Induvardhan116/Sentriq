import uuid
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User


class ApiSpec(Base, TimestampMixin):
    """Imported OpenAPI / Swagger specification target."""

    __tablename__ = "api_specs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), default="1.0.0", nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    spec_format: Mapped[str] = mapped_column(String(32), default="openapi_3", nullable=False)  # openapi_3, swagger_2
    raw_spec: Mapped[str] = mapped_column(Text, nullable=False)

    endpoint_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    posture_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    owner_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Relationships
    owner: Mapped[Optional["User"]] = relationship("User", lazy="selectin")
    endpoints: Mapped[List["ApiEndpoint"]] = relationship(
        "ApiEndpoint",
        back_populates="spec",
        cascade="all, delete-orphan",
        order_by="ApiEndpoint.path",
        lazy="selectin",
    )
    findings: Mapped[List["ApiFinding"]] = relationship(
        "ApiFinding",
        back_populates="spec",
        cascade="all, delete-orphan",
        order_by="desc(ApiFinding.risk_score)",
        lazy="selectin",
    )


class ApiEndpoint(Base, TimestampMixin):
    """Discovered API endpoint route and method."""

    __tablename__ = "api_endpoints"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    spec_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("api_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # GET, POST, etc.
    summary: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    auth_type: Mapped[str] = mapped_column(String(64), default="none", nullable=False)
    parameters_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    has_request_body: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tags: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationship
    spec: Mapped["ApiSpec"] = relationship("ApiSpec", back_populates="endpoints")


class ApiFinding(Base, TimestampMixin):
    """Vulnerability finding mapped to OWASP API Security Top 10."""

    __tablename__ = "api_findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    spec_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("api_specs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    owasp_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    spec: Mapped["ApiSpec"] = relationship("ApiSpec", back_populates="findings")
