import uuid
from typing import List, TYPE_CHECKING
from sqlalchemy import String, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


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

    # Scans associated with this project
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="desc(Scan.created_at)",
        lazy="selectin",
    )
