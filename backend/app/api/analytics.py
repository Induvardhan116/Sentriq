import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.schemas.analytics import (
    RiskSummaryResponse,
    PostureTrendsResponse,
    ProjectRankingsResponse,
)
from app.services.analytics_service import AnalyticsService
from app.security.deps import get_authenticated_user_or_dev_mode

logger = logging.getLogger("sentriq.api.analytics")
router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/risk-summary", response_model=RiskSummaryResponse)
async def get_risk_summary(
    project_id: Optional[str] = Query(None, description="Optional filter by project ID"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve overall security posture score, domain breakdowns, and remediation velocity."""
    return await AnalyticsService.get_risk_summary(
        db=db,
        user=user,
        project_id=project_id,
    )


@router.get("/posture-trends", response_model=PostureTrendsResponse)
async def get_posture_trends(
    project_id: Optional[str] = Query(None, description="Optional filter by project ID"),
    days: int = Query(30, ge=1, le=365, description="Historical timeframe in days"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve chronological posture trend data points across historical security assessments."""
    return await AnalyticsService.get_posture_trends(
        db=db,
        user=user,
        project_id=project_id,
        days=days,
    )


@router.get("/project-rankings", response_model=ProjectRankingsResponse)
async def get_project_rankings(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of projects to return"),
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Retrieve projects ranked by calculated risk index, exposure age, and critical finding density."""
    return await AnalyticsService.get_project_rankings(
        db=db,
        user=user,
        limit=limit,
    )
