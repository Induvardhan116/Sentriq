from datetime import datetime
from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class StatusDistribution(BaseModel):
    open: int = 0
    in_progress: int = 0
    resolved: int = 0
    accepted_risk: int = 0
    false_positive: int = 0


class DomainScore(BaseModel):
    domain: str
    finding_count: int
    critical_count: int
    high_count: int
    health_status: Literal["healthy", "warning", "critical"]
    description: str


class RemediationMetrics(BaseModel):
    remediation_rate_percent: float = 0.0
    total_findings_discovered: int = 0
    active_findings_count: int = 0
    resolved_findings_count: int = 0
    mean_time_to_remediate_days: Optional[float] = None
    oldest_open_finding_days: Optional[float] = None
    avg_finding_age_days: Optional[float] = None


class RiskSummaryResponse(BaseModel):
    overall_posture_score: int = Field(..., ge=0, le=100)
    grade: str
    evaluated_at: datetime
    total_projects: int
    total_scans: int
    total_findings: int
    active_findings: int
    severity_distribution: SeverityDistribution
    status_distribution: StatusDistribution
    domain_breakdown: List[DomainScore]
    remediation_metrics: RemediationMetrics
    score_formula_explanation: str
    active_caps_applied: List[str]


class PostureTrendPoint(BaseModel):
    scan_id: str
    project_id: str
    project_name: str
    scan_date: datetime
    date_label: str
    posture_score: int
    grade: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    active_findings_count: int


class PostureTrendsResponse(BaseModel):
    total_points: int
    timeframe_days: int
    trend_direction: Literal["improving", "degrading", "stable", "insufficient_data"]
    score_delta: int
    data_points: List[PostureTrendPoint]


class ProjectRiskRankingItem(BaseModel):
    rank: int
    project_id: str
    project_name: str
    target_url: str
    posture_score: int
    risk_index: int
    grade: str
    trend: Literal["improving", "degrading", "stable", "new"]
    critical_findings: int
    high_findings: int
    total_active_findings: int
    last_scanned_at: Optional[datetime] = None
    exposure_days: Optional[float] = None


class ProjectRankingsResponse(BaseModel):
    total_projects: int
    highest_risk_project: Optional[str] = None
    rankings: List[ProjectRiskRankingItem]
