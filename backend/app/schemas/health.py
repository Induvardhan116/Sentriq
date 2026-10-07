from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class SystemHealthResponse(BaseModel):
    """Normalized schema for system health reporting."""

    status: Literal["healthy", "degraded"] = Field(
        ..., description="Overall platform operating health status"
    )
    database: Literal["connected", "disconnected"] = Field(
        ..., description="Database connectivity probe status"
    )
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application release version")
    environment: str = Field(..., description="Deployment environment (development/production)")
    timestamp: datetime = Field(..., description="Server timestamp of health verification")
