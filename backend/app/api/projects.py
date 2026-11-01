import asyncio
import datetime
import logging
from typing import List, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db, AsyncSessionLocal
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse, ProjectDetailResponse
from app.schemas.scan import ScanResponse
from app.scanners.web.validator import validate_target_url
from app.scanners.web.scanner import WebsiteScanner
from app.risk.fingerprint import compute_finding_fingerprint

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

            # Retrieve previous findings across prior scans for this project to preserve workflow statuses
            prev_findings_stmt = (
                select(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .where(
                    Scan.project_id == scan.project_id,
                    Scan.id != scan.id,
                )
                .order_by(Scan.created_at.desc(), Finding.updated_at.desc())
            )
            prev_findings_result = await session.execute(prev_findings_stmt)
            prev_findings = prev_findings_result.scalars().all()

            # Map stable fingerprint -> most recent finding status
            prior_statuses: Dict[str, str] = {}
            for pf in prev_findings:
                fp = pf.fingerprint or compute_finding_fingerprint(
                    target_url=scan.target_url,
                    category=pf.category,
                    check_rule_id=pf.title,
                    affected_resource=pf.endpoint or scan.target_url,
                )
                if fp not in prior_statuses:
                    prior_statuses[fp] = pf.status

            # Persist findings with persistent statuses
            findings_data = scan_result["findings"]
            for f_data in findings_data:
                category = f_data["category"]
                title = f_data["title"]
                rule_id = f_data.get("rule_id") or f_data.get("rule") or title
                endpoint = f_data.get("endpoint") or scan.target_url

                fp = compute_finding_fingerprint(
                    target_url=scan.target_url,
                    category=category,
                    check_rule_id=rule_id,
                    affected_resource=endpoint,
                )

                # Preserve Resolved, False Positive, and In Progress statuses for matching findings.
                # New findings start as Open.
                prior_status = prior_statuses.get(fp)
                if prior_status in ("resolved", "false_positive", "in_progress"):
                    assigned_status = prior_status
                else:
                    assigned_status = "open"

                finding = Finding(
                    scan_id=scan.id,
                    source=f_data["source"],
                    category=category,
                    title=title,
                    description=f_data["description"],
                    severity=f_data["severity"],
                    confidence=f_data["confidence"],
                    risk_score=f_data["risk_score"],
                    cwe=f_data.get("cwe"),
                    endpoint=f_data.get("endpoint"),
                    evidence=f_data.get("evidence"),
                    remediation=f_data.get("remediation"),
                    status=assigned_status,
                    fingerprint=fp,
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


@router.patch("/{project_id}", response_model=ProjectResponse)
@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update project name and/or target website URL with strict SSRF validation."""
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{project_id}' does not exist.",
        )

    if payload.name is not None:
        clean_name = payload.name.strip()
        if len(clean_name) < 2:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Project name must be at least 2 characters.",
            )
        project.name = clean_name

    if payload.target_url is not None:
        is_valid, error, normalized_url = validate_target_url(payload.target_url)
        if not is_valid or not normalized_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error or "Invalid or prohibited target URL.",
            )
        project.target_url = normalized_url

    project.updated_at = datetime.datetime.now(datetime.timezone.utc)
    await db.commit()
    await db.refresh(project)

    latest = project.scans[0] if project.scans else None
    latest_scan_schema = ScanResponse.model_validate(latest) if latest else None

    return ProjectResponse(
        id=project.id,
        name=project.name,
        target_url=project.target_url,
        authorization_confirmed=project.authorization_confirmed,
        latest_scan=latest_scan_schema,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.delete("/{project_id}", status_code=status.HTTP_200_OK)
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db)):
    """Safely delete a project and all associated scans and findings within a database transaction."""
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with ID '{project_id}' does not exist.",
        )

    project_name = project.name

    # Safe transactional cascade deletion
    scan_ids_stmt = select(Scan.id).where(Scan.project_id == project_id)
    scan_ids_result = await db.execute(scan_ids_stmt)
    scan_ids = scan_ids_result.scalars().all()

    if scan_ids:
        await db.execute(delete(Finding).where(Finding.scan_id.in_(scan_ids)))
        await db.execute(delete(Scan).where(Scan.project_id == project_id))

    await db.execute(delete(Project).where(Project.id == project_id))
    await db.commit()

    logger.info("Project '%s' (%s) and associated records deleted successfully", project_name, project_id)

    return {
        "success": True,
        "message": f"Project '{project_name}' and all associated scan history and findings were deleted successfully.",
        "deleted_id": project_id,
    }

