from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
from app.schemas.scan import ScanResponse


class ProjectCreate(BaseModel):
    """Payload to create a new authorized assessment target project."""

    name: str = Field(..., min_length=2, max_length=255, description="Project name")
    target_url: str = Field(
        ..., min_length=4, max_length=1024, description="Target website URL (e.g. https://example.com)"
    )
    authorization_confirmed: bool = Field(
        ..., description="Explicit confirmation of target ownership or authorization"
    )

    @field_validator("authorization_confirmed")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must explicitly confirm target ownership or authorization to proceed."
            )
        return v


class ProjectResponse(BaseModel):
    """Project representation with latest scan preview."""

    id: str
    name: str
    target_url: str
    authorization_confirmed: bool
    latest_scan: Optional[ScanResponse] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ProjectDetailResponse(ProjectResponse):
    """Detailed project representation with full scan history."""

    scans: List[ScanResponse] = []
