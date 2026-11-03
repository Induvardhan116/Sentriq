from datetime import datetime
from typing import Optional, Literal, List, Dict
from pydantic import BaseModel, Field


class FindingStatusUpdate(BaseModel):
    """Schema for updating a security finding's resolution status."""

    status: Literal["open", "in_progress", "resolved", "false_positive", "accepted_risk"] = Field(
        ..., description="Resolution status"
    )
    justification: Optional[str] = Field(None, description="Triage rationale or justification")
    expected_version: Optional[int] = Field(None, description="Expected finding version for OCC")


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
    fingerprint: Optional[str] = None
    version: int = 1
    justification: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    # Relational metadata for centralized hub views
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    target_url: Optional[str] = None

    model_config = {"from_attributes": True}


class FindingStatusEventResponse(BaseModel):
    """Normalized immutable audit log payload for a status transition."""

    id: str
    finding_id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    previous_status: str
    new_status: str
    justification: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class PaginatedFindingsResponse(BaseModel):
    """Paginated list of normalized findings for the centralized findings hub."""

    items: List[FindingResponse]
    total: int = Field(..., ge=0, description="Total matching findings count")
    limit: int = Field(..., ge=1, description="Page size limit")
    offset: int = Field(..., ge=0, description="Pagination offset")


class FindingsSummaryResponse(BaseModel):
    """Aggregated finding metrics across accessible projects."""

    total: int = Field(..., ge=0, description="Total findings count")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="Counts broken down by severity")
    by_status: Dict[str, int] = Field(default_factory=dict, description="Counts broken down by status")
    by_category: Dict[str, int] = Field(default_factory=dict, description="Counts broken down by category")


