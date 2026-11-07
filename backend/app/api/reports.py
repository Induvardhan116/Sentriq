import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.models.user import User
from app.services.report_service import ReportService
from app.security.deps import get_authenticated_user_or_dev_mode

logger = logging.getLogger("sentriq.api.reports")
router = APIRouter(prefix="/reports", tags=["Reports & Export"])


@router.get("/summary", response_model=Dict[str, Any])
async def get_report_summary(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Fetch high-level report metadata and KPI summary for frontend dashboard."""
    return await ReportService.gather_tenant_data(db=db, user=user)


@router.get("/executive", response_class=HTMLResponse)
async def get_executive_report(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Generate standalone printable executive cybersecurity report."""
    html_content = await ReportService.generate_executive_html(db=db, user=user)
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


@router.get("/export/pdf")
async def export_report_pdf(
    report_type: str = "executive",
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Download authentic multi-page PDF security report."""
    valid_types = {"executive", "project", "vulnerability", "risk", "repo", "api", "cloud", "compliance"}
    cleaned_type = report_type.lower().strip()
    if cleaned_type not in valid_types:
        cleaned_type = "executive"

    pdf_bytes = await ReportService.generate_report_pdf(db=db, user=user, report_type=cleaned_type)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="sentriq_{cleaned_type}_report.pdf"',
            "Cache-Control": "no-cache",
        },
    )


@router.get("/export/csv")
async def export_findings_csv(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Download findings across all assets as a UTF-8 CSV spreadsheet with BOM."""
    csv_content = await ReportService.generate_findings_csv(db=db, user=user)
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": "attachment; filename=sentriq_findings_export.csv",
            "Cache-Control": "no-cache",
        },
    )


@router.get("/export/json")
async def export_posture_json(
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_authenticated_user_or_dev_mode),
):
    """Download full cybersecurity posture package in JSON format."""
    json_data = await ReportService.generate_posture_json(db=db, user=user)
    return JSONResponse(
        content=json_data,
        headers={
            "Content-Disposition": "attachment; filename=sentriq_posture_bundle.json",
            "Cache-Control": "no-cache",
        },
    )
