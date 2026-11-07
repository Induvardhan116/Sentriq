from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class ApiSpecImport(BaseModel):
    title: str = Field(..., min_length=2, max_length=255, description="API specification title")
    version: str = Field("1.0.0", max_length=64, description="API schema version")
    raw_spec: str = Field(..., min_length=10, description="Raw OpenAPI or Swagger schema text (JSON or YAML)")
    base_url: Optional[str] = Field(None, description="Optional target base URL")


class ApiEndpointResponse(BaseModel):
    id: str
    spec_id: str
    path: str
    method: str
    summary: Optional[str] = None
    auth_required: bool
    auth_type: str
    parameters_count: int
    has_request_body: bool
    tags: Optional[str] = None

    model_config = {"from_attributes": True}


class ApiFindingResponse(BaseModel):
    id: str
    spec_id: str
    endpoint_id: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    owasp_category: str
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


class ApiSpecResponse(BaseModel):
    id: str
    title: str
    version: str
    description: Optional[str] = None
    base_url: Optional[str] = None
    spec_format: str
    endpoint_count: int
    posture_score: int
    risk_score: int
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ApiFindingStatusUpdate(BaseModel):
    status: Literal["open", "resolved", "false_positive", "accepted_risk"]
    justification: Optional[str] = None
