from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, HttpUrl


class RepositoryCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Repository display name")
    full_name: str = Field(..., min_length=3, max_length=255, description="Repository identifier (e.g., owner/repo)")
    clone_url: str = Field(..., description="Git clone URL (HTTPS)")
    default_branch: str = Field("main", max_length=64, description="Default git branch")
    languages: Optional[str] = Field(None, description="Comma-separated primary languages")
    is_private: bool = Field(False, description="Whether repository is private")
    authorization_confirmed: bool = Field(True, description="Explicit authorization confirmation")


class RepositoryResponse(BaseModel):
    id: str
    name: str
    full_name: str
    clone_url: str
    default_branch: str
    languages: Optional[str] = None
    is_private: bool
    authorization_confirmed: bool
    owner_id: Optional[str] = None
    last_scanned_at: Optional[datetime] = None
    latest_posture_score: int
    latest_risk_score: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RepoFindingResponse(BaseModel):
    id: str
    scan_id: str
    scan_type: str
    title: str
    description: str
    severity: str
    confidence: float
    risk_score: int
    file_path: str
    line_number: Optional[int] = None
    rule_id: str
    cwe: Optional[str] = None
    cve: Optional[str] = None
    snippet: Optional[str] = None
    remediation: Optional[str] = None
    status: str
    justification: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RepoScanResponse(BaseModel):
    id: str
    repository_id: str
    branch: str
    commit_hash: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    posture_score: int
    findings_count: int
    secret_count: int
    sast_count: int
    sca_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RepoFindingStatusUpdate(BaseModel):
    status: Literal["open", "resolved", "false_positive", "accepted_risk"]
    justification: Optional[str] = None
