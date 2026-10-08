from typing import List, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.schemas.scan import ScanDetailResponse, ScanSummaryResponse
from app.schemas.finding import FindingResponse

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve scan status, metrics, and complete findings."""
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' does not exist.",
        )

    return scan


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve normalized findings for a specific scan."""
    stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())
    result = await db.execute(stmt)
    findings = result.scalars().all()
    return findings


@router.get("/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve aggregated risk and category summary for a scan."""
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' does not exist.",
        )

    # Calculate category breakdown
    category_breakdown: Dict[str, int] = {}
    for f in scan.findings:
        category_breakdown[f.category] = category_breakdown.get(f.category, 0) + 1

    severity_breakdown = {
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "informational": scan.info_count,
    }

    # Top risks (top 5 highest risk score)
    top_risks = [FindingResponse.model_validate(f) for f in scan.findings[:5]]

    return ScanSummaryResponse(
        id=scan.id,
        project_id=scan.project_id,
        target_url=scan.target_url,
        status=scan.status,
        overall_score=scan.overall_score,
        score_grade=scan.score_grade,
        severity_breakdown=severity_breakdown,
        category_breakdown=category_breakdown,
        top_risks=top_risks,
        completed_at=scan.completed_at,
    )
