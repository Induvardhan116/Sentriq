from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingResponse, FindingStatusUpdate
from app.security.deps import (
    get_authenticated_user_or_dev_mode,
    verify_finding_access,
    require_csrf_if_auth_enabled,
)

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
    _csrf: None = Depends(require_csrf_if_auth_enabled),
):
    """Update a security finding's lifecycle status with strict project ownership check."""
    stmt = (
        select(Finding)
        .options(selectinload(Finding.scan).selectinload(Scan.project))
        .where(Finding.id == finding_id)
    )
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    verify_finding_access(finding, user, finding_id)

    finding.status = payload.status
    await db.commit()
    await db.refresh(finding)
    return finding
