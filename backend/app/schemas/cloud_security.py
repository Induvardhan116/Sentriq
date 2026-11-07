from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


class CloudAccountCreate(BaseModel):
    provider: Literal["aws", "gcp", "supabase", "azure"] = Field(..., description="Cloud or PaaS provider")
    name: str = Field(..., min_length=2, max_length=255, description="Human friendly account name")
    account_identifier: str = Field(..., min_length=3, max_length=128, description="AWS 12-digit Account ID or Supabase project ref")
    role_arn_or_ref: str = Field(..., min_length=3, max_length=255, description="Read-only audit IAM Role ARN or credentials reference")
    region: str = Field("us-east-1", max_length=64, description="Primary default cloud region")


class CloudFindingResponse(BaseModel):
    id: str
    account_id: str
    service: str
    resource_id: str
    resource_type: str
    benchmark_ref: str
    title: str
    description: str
    severity: str
    confidence: float
    risk_score: int
    remediation: Optional[str] = None
    status: str
    justification: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CloudAccountResponse(BaseModel):
    id: str
    provider: str
    name: str
    account_identifier: str
    role_arn_or_ref: str
    region: str
    is_active: bool
    posture_score: int
    risk_score: int
    findings_count: int = 0
    connection_status: str = "Awaiting Live Cloud Credentials"
    audit_mode: Optional[str] = "Simulated CIS Baseline Audit"
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CloudScanTrigger(BaseModel):
    config_data: Optional[Dict[str, Any]] = Field(
        None, description="Optional simulated or extracted resource configuration dictionary"
    )


class CloudFindingStatusUpdate(BaseModel):
    status: Literal["open", "resolved", "false_positive", "accepted_risk"]
    justification: Optional[str] = None
