from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field


class WebhookCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Webhook channel name (e.g. Slack Security Alert)")
    target_url: str = Field(..., min_length=8, max_length=1024, description="Destination webhook HTTPS URL")
    event_types: str = Field("scan.completed,finding.critical,posture.degraded", description="Comma-separated event topics")
    secret_token: Optional[str] = Field(None, max_length=255, description="Optional custom HMAC signing secret")


class WebhookResponse(BaseModel):
    id: str
    name: str
    target_url: str
    secret_token: str  # Masked e.g. "whsec_****1234"
    event_types: str
    is_active: bool
    last_dispatched_at: Optional[datetime] = None
    last_status_code: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class WebhookTestResult(BaseModel):
    success: bool
    status_code: Optional[int] = None
    message: str
    delivered_payload: Dict[str, Any]


class ScanScheduleCreate(BaseModel):
    target_type: Literal["project", "repository", "cloud_account"] = Field(..., description="Target asset category")
    target_id: str = Field(..., min_length=1, max_length=36, description="Target asset UUID")
    target_name: str = Field(..., min_length=1, max_length=255, description="Target asset display name")
    frequency: Literal["daily", "weekly", "monthly"] = Field("weekly", description="Execution cadence")


class ScanScheduleResponse(BaseModel):
    id: str
    target_type: str
    target_id: str
    target_name: str
    frequency: str
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SiemLogItem(BaseModel):
    timestamp: str
    event_id: str
    severity: str
    source: str
    asset: str
    message: str
    cef_string: str
