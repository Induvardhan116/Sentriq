from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingResponse, FindingStatusUpdate

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a security finding's lifecycle status (open, in_progress, resolved, false_positive)."""
    stmt = select(Finding).where(Finding.id == finding_id)
    result = await db.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' does not exist.",
        )

    finding.status = payload.status
    await db.commit()
    await db.refresh(finding)
    return finding
