import uuid
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.user import User


class Project(Base, TimestampMixin):
    """Authorized cybersecurity assessment target project."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    owner_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Owner user relationship (nullable for unassigned legacy projects)
    owner: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="projects",
        lazy="selectin",
    )

    # Scans associated with this project
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="desc(Scan.created_at)",
        lazy="selectin",
    )
