from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field


class FindingStatusUpdate(BaseModel):
    """Schema for updating a security finding's resolution status."""

    status: Literal["open", "in_progress", "resolved", "false_positive"] = Field(
        ..., description="Resolution status"
    )


class FindingResponse(BaseModel):
    """Normalized security finding payload."""

    id: str
    scan_id: str
    source: str
    category: str
    title: str
    description: str
    severity: str
    confidence: float
    risk_score: int
    cwe: Optional[str] = None
    endpoint: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
