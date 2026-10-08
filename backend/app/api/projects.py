import asyncio
import datetime
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db, AsyncSessionLocal
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.schemas.project import ProjectCreate, ProjectResponse, ProjectDetailResponse
from app.schemas.scan import ScanResponse
from app.scanners.web.validator import validate_target_url
from app.scanners.web.scanner import WebsiteScanner

logger = logging.getLogger("sentriq.api.projects")
router = APIRouter(prefix="/projects", tags=["Projects"])


async def run_scan_background(scan_id: str, target_url: str):
    """Background execution runner for website security assessment."""
    async with AsyncSessionLocal() as session:
        scan_stmt = select(Scan).where(Scan.id == scan_id)
        result = await session.execute(scan_stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error("Scan %s not found for background execution", scan_id)
            return

        scan.status = "running"
        scan.started_at = datetime.datetime.now(datetime.timezone.utc)
        await session.commit()

        scanner = WebsiteScanner()
        try:
            scan_result = await scanner.scan(target_url)

            if not scan_result["success"]:
                scan.status = "failed"
                scan.error_message = scan_result.get("error", "Scan execution failed")
                scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
                await session.commit()
                return

            # Persist findings
            findings_data = scan_result["findings"]
            for f_data in findings_data:
                finding = Finding(
                    scan_id=scan.id,
                    source=f_data["source"],
                    category=f_data["category"],
                    title=f_data["title"],
                    description=f_data["description"],
                    severity=f_data["severity"],
                    confidence=f_data["confidence"],
                    risk_score=f_data["risk_score"],
                    cwe=f_data.get("cwe"),
                    endpoint=f_data.get("endpoint"),
                    evidence=f_data.get("evidence"),
                    remediation=f_data.get("remediation"),
                    status="open",
                )
                session.add(finding)

            counts = scan_result["counts"]
            scan.overall_score = scan_result["overall_score"]
            scan.score_grade = scan_result["score_grade"]
            scan.findings_count = len(findings_data)
            scan.critical_count = counts.get("critical", 0)
            scan.high_count = counts.get("high", 0)
            scan.medium_count = counts.get("medium", 0)
            scan.low_count = counts.get("low", 0)
            scan.info_count = counts.get("informational", 0)
            scan.status = "completed"
            scan.completed_at = datetime.datetime.now(datetime.timezone.utc)

            await session.commit()
            logger.info("Scan %s completed successfully with score %s", scan_id, scan.overall_score)
        except Exception as e:
            logger.exception("Unexpected error during scan %s execution", scan_id)
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
            await session.commit()


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(payload: ProjectCreate, db: AsyncSession = Depends(get_db)):
    """Create a new authorized security target project."""
    is_valid, error, normalized_url = validate_target_url(payload.target_url)
    if not is_valid or not normalized_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error or "Invalid or prohibited target URL.",
        )

    project = Project(
        name=payload.name.strip(),
        target_url=normalized_url,
        authorization_confirmed=payload.authorization_confirmed,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    return ProjectResponse(
        id=project.id,
        name=project.name,
        target_url=project.target_url,
        authorization_confirmed=project.authorization_confirmed,
        latest_scan=None,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.get("", response_model=List[ProjectResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    """List all projects with their latest scan summary."""
    stmt = select(Project).order_by(Project.created_at.desc())
    result = await db.execute(stmt)
    projects = result.scalars().all()

    response_list: List[ProjectResponse] = []
    for p in projects:
        latest = p.scans[0] if p.scans else None
        latest_scan_schema = ScanResponse.model_validate(latest) if latest else None
        response_list.append(
            ProjectResponse(
                id=p.id,
                name=p.name,
                target_url=p.target_url,
                authorization_confirmed=p.authorization_confirmed,
                latest_scan=latest_scan_schema,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
        )

    return response_list


@router.get("/{project_id}", response_model=ProjectDetailResponse)
async def get_project(project_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve detailed project information and scan history."""
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{project_id}' does not exist.",
        )

    latest = project.scans[0] if project.scans else None
    latest_scan_schema = ScanResponse.model_validate(latest) if latest else None
    scans_schemas = [ScanResponse.model_validate(s) for s in project.scans]

    return ProjectDetailResponse(
        id=project.id,
        name=project.name,
        target_url=project.target_url,
        authorization_confirmed=project.authorization_confirmed,
        latest_scan=latest_scan_schema,
        scans=scans_schemas,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.post("/{project_id}/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_project_scan(project_id: str, db: AsyncSession = Depends(get_db)):
    """Initiate a safe, non-destructive security scan against an authorized project target."""
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{project_id}' does not exist.",
        )

    if not project.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scanning unauthorized targets is prohibited.",
        )

    # Create scan record in queued state
    scan = Scan(
        project_id=project.id,
        target_url=project.target_url,
        status="queued",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch background scan execution
    asyncio.create_task(run_scan_background(scan.id, scan.target_url))

    return scan
