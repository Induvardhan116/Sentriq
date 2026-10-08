from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel
from app.schemas.finding import FindingResponse


class ScanResponse(BaseModel):
    """Schema representing a scan instance."""

    id: str
    project_id: str
    target_url: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    overall_score: Optional[int] = None
    score_grade: Optional[str] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanResponse):
    """Detailed scan response including all associated findings."""

    findings: List[FindingResponse] = []


class ScanSummaryResponse(BaseModel):
    """Aggregated scan summary metrics."""

    id: str
    project_id: str
    target_url: str
    status: str
    overall_score: Optional[int] = None
    score_grade: Optional[str] = None
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    top_risks: List[FindingResponse] = []
    completed_at: Optional[datetime] = None
