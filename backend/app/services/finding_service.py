import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple, Any
from fastapi import HTTPException, status
from sqlalchemy import select, func, distinct, case, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.project import Project
from app.models.user import User
from app.models.finding_status_event import FindingStatusEvent
from app.schemas.finding import (
    FindingResponse,
    FindingStatusUpdate,
    FindingStatusEventResponse,
    PaginatedFindingsResponse,
    FindingsSummaryResponse,
)
from app.security.deps import verify_finding_access, verify_scan_access

logger = logging.getLogger("sentriq.services.finding")
settings = get_settings()

VALID_STATUSES = {"open", "in_progress", "resolved", "false_positive", "accepted_risk"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


class FindingService:
    """Centralized service layer for security finding lifecycle, queries, and audit management."""

    @staticmethod
    def _format_finding_response(finding: Finding) -> FindingResponse:
        """Enrich a Finding model into FindingResponse with relational project/scan context."""
        proj_id = None
        proj_name = None
        target_url = None
        if finding.scan and finding.scan.project:
            proj_id = finding.scan.project.id
            proj_name = finding.scan.project.name
            target_url = finding.scan.project.target_url
        elif finding.scan:
            target_url = finding.scan.target_url

        return FindingResponse(
            id=finding.id,
            scan_id=finding.scan_id,
            source=finding.source,
            category=finding.category,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=finding.confidence,
            risk_score=finding.risk_score,
            cwe=finding.cwe,
            endpoint=finding.endpoint,
            evidence=finding.evidence,
            remediation=finding.remediation,
            status=finding.status,
            fingerprint=finding.fingerprint,
            version=finding.version or 1,
            justification=finding.justification,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            project_id=proj_id,
            project_name=proj_name,
            target_url=target_url,
        )

    @classmethod
    async def list_findings(
        cls,
        db: AsyncSession,
        user: Optional[User],
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        sort_by: str = "risk_score",
        sort_order: str = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedFindingsResponse:
        """List findings across tenant-accessible projects with multi-criteria filtering, sorting, and pagination."""
        try:
            # 1. Base tenant query joining Finding -> Scan -> Project
            base_stmt = (
                select(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .join(Project, Scan.project_id == Project.id)
                .options(selectinload(Finding.scan).selectinload(Scan.project))
            )

            # 2. Strict Tenant Ownership Filtering
            if settings.AUTH_ENABLED:
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required. No valid session cookie found.",
                    )
                if not user.is_superuser:
                    base_stmt = base_stmt.where(Project.owner_id == user.id)
            else:
                # Local development mode: filter if regular user is specified, otherwise allow all
                if user and not user.is_superuser:
                    base_stmt = base_stmt.where(
                        or_(Project.owner_id == user.id, Project.owner_id.is_(None))
                    )

            # 3. Apply Multi-Attribute Filters
            if project_id:
                base_stmt = base_stmt.where(Project.id == project_id)
            if scan_id:
                base_stmt = base_stmt.where(Finding.scan_id == scan_id)
            if status_filter:
                st = status_filter.strip().lower()
                if st in VALID_STATUSES:
                    base_stmt = base_stmt.where(Finding.status == st)
                else:
                    return PaginatedFindingsResponse(items=[], total=0, limit=limit, offset=offset)
            if severity_filter:
                sev = severity_filter.strip().lower()
                if sev in VALID_SEVERITIES:
                    base_stmt = base_stmt.where(Finding.severity == sev)
                else:
                    return PaginatedFindingsResponse(items=[], total=0, limit=limit, offset=offset)
            if category_filter:
                base_stmt = base_stmt.where(Finding.category == category_filter.strip().lower())
            if search_query:
                term = f"%{search_query.strip().lower()}%"
                base_stmt = base_stmt.where(
                    or_(
                        func.lower(Finding.title).like(term),
                        func.lower(Finding.description).like(term),
                        func.lower(Finding.endpoint).like(term),
                    )
                )

            # 4. Total Count Computation
            count_subq = base_stmt.subquery()
            count_stmt = select(func.count()).select_from(count_subq)
            total = (await db.execute(count_stmt)).scalar() or 0

            # 5. Dynamic Sorting
            order_col = Finding.risk_score
            if sort_by == "severity":
                # Order severity logically: critical > high > medium > low > informational
                order_col = case(
                    (Finding.severity == "critical", 5),
                    (Finding.severity == "high", 4),
                    (Finding.severity == "medium", 3),
                    (Finding.severity == "low", 2),
                    (Finding.severity == "informational", 1),
                    else_=0,
                )
            elif sort_by == "created_at":
                order_col = Finding.created_at
            elif sort_by == "updated_at":
                order_col = Finding.updated_at
            elif sort_by == "title":
                order_col = Finding.title
            elif sort_by == "status":
                order_col = Finding.status

            if sort_order.lower() == "asc":
                query_stmt = base_stmt.order_by(order_col.asc(), Finding.id.asc())
            else:
                query_stmt = base_stmt.order_by(order_col.desc(), Finding.id.desc())

            # 6. Apply Pagination
            sanitized_limit = max(1, min(limit, 200))
            sanitized_offset = max(0, offset)
            query_stmt = query_stmt.limit(sanitized_limit).offset(sanitized_offset)

            result = await db.execute(query_stmt)
            findings = result.scalars().all()

            items = [cls._format_finding_response(f) for f in findings]
            return PaginatedFindingsResponse(
                items=items,
                total=total,
                limit=sanitized_limit,
                offset=sanitized_offset,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to list findings: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve findings due to an internal error.",
            ) from exc

    @classmethod
    async def get_finding_by_id(
        cls,
        db: AsyncSession,
        finding_id: str,
        user: Optional[User],
    ) -> FindingResponse:
        """Retrieve full details of a specific finding with strict tenant ownership check."""
        try:
            stmt = (
                select(Finding)
                .options(selectinload(Finding.scan).selectinload(Scan.project))
                .where(Finding.id == finding_id)
            )
            result = await db.execute(stmt)
            finding = result.scalar_one_or_none()

            verify_finding_access(finding, user, finding_id)
            return cls._format_finding_response(finding)
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to retrieve finding %s: %s", finding_id, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve finding details.",
            ) from exc

    @classmethod
    async def get_findings_summary(
        cls,
        db: AsyncSession,
        user: Optional[User],
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> FindingsSummaryResponse:
        """Compute aggregated metrics across accessible findings (by severity, status, category)."""
        try:
            base_stmt = (
                select(Finding.severity, Finding.status, Finding.category)
                .join(Scan, Finding.scan_id == Scan.id)
                .join(Project, Scan.project_id == Project.id)
            )

            # Strict Tenant Isolation
            if settings.AUTH_ENABLED:
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required. No valid session cookie found.",
                    )
                if not user.is_superuser:
                    base_stmt = base_stmt.where(Project.owner_id == user.id)
            else:
                if user and not user.is_superuser:
                    base_stmt = base_stmt.where(
                        or_(Project.owner_id == user.id, Project.owner_id.is_(None))
                    )

            if project_id:
                base_stmt = base_stmt.where(Project.id == project_id)
            if scan_id:
                base_stmt = base_stmt.where(Finding.scan_id == scan_id)

            rows = (await db.execute(base_stmt)).all()

            by_severity: Dict[str, int] = {k: 0 for k in VALID_SEVERITIES}
            by_status: Dict[str, int] = {k: 0 for k in VALID_STATUSES}
            by_category: Dict[str, int] = {}

            for sev, st, cat in rows:
                if sev in by_severity:
                    by_severity[sev] += 1
                else:
                    by_severity[sev] = 1

                if st in by_status:
                    by_status[st] += 1
                else:
                    by_status[st] = 1

                cat_key = cat or "other"
                by_category[cat_key] = by_category.get(cat_key, 0) + 1

            return FindingsSummaryResponse(
                total=len(rows),
                by_severity=by_severity,
                by_status=by_status,
                by_category=by_category,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to compute findings summary: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to compute findings summary.",
            ) from exc

    @classmethod
    async def update_finding_status(
        cls,
        db: AsyncSession,
        finding_id: str,
        payload: FindingStatusUpdate,
        user: Optional[User],
    ) -> FindingResponse:
        """Update finding status with OCC version checking, justification rules, and immutable audit event creation."""
        try:
            stmt = (
                select(Finding)
                .options(selectinload(Finding.scan).selectinload(Scan.project))
                .where(Finding.id == finding_id)
            )
            result = await db.execute(stmt)
            finding = result.scalar_one_or_none()

            verify_finding_access(finding, user, finding_id)

            # 1. Optimistic Concurrency Control (OCC) Check
            if payload.expected_version is not None and finding.version != payload.expected_version:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "message": "Concurrency conflict: finding has been modified by another user.",
                        "current_version": finding.version,
                        "expected_version": payload.expected_version,
                    },
                )

            # 2. Mandatory justification validation
            if (payload.status == "accepted_risk" or (payload.status == "false_positive" and payload.expected_version is not None)):
                if not (payload.justification and payload.justification.strip()):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"A non-empty justification is mandatory when transitioning finding to '{payload.status}'.",
                    )

            previous_status = finding.status
            now_utc = datetime.now(timezone.utc)

            # 3. Update Finding Entity
            finding.status = payload.status
            finding.version = (finding.version or 1) + 1
            if payload.justification is not None:
                finding.justification = payload.justification.strip() or None
            finding.updated_at = now_utc

            # 4. Insert Immutable Audit Log
            event = FindingStatusEvent(
                finding_id=finding.id,
                user_id=user.id if user else None,
                previous_status=previous_status,
                new_status=payload.status,
                justification=payload.justification.strip() if payload.justification else None,
                created_at=now_utc,
            )
            db.add(event)

            await db.commit()
            await db.refresh(finding)
            return cls._format_finding_response(finding)
        except HTTPException:
            await db.rollback()
            raise
        except Exception as exc:
            await db.rollback()
            logger.exception("Failed to update status for finding %s: %s", finding_id, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update finding status.",
            ) from exc

    @classmethod
    async def get_finding_history(
        cls,
        db: AsyncSession,
        finding_id: str,
        user: Optional[User],
    ) -> List[FindingStatusEventResponse]:
        """Retrieve immutable chronological audit history for a finding with tenant ownership enforcement."""
        try:
            stmt = (
                select(Finding)
                .options(selectinload(Finding.scan).selectinload(Scan.project))
                .where(Finding.id == finding_id)
            )
            result = await db.execute(stmt)
            finding = result.scalar_one_or_none()

            verify_finding_access(finding, user, finding_id)

            events_stmt = (
                select(FindingStatusEvent)
                .options(selectinload(FindingStatusEvent.user))
                .where(FindingStatusEvent.finding_id == finding_id)
                .order_by(FindingStatusEvent.created_at.desc())
            )
            events_res = await db.execute(events_stmt)
            events = events_res.scalars().all()

            return [
                FindingStatusEventResponse(
                    id=e.id,
                    finding_id=e.finding_id,
                    user_id=e.user_id,
                    user_email=e.user.email if e.user else None,
                    previous_status=e.previous_status,
                    new_status=e.new_status,
                    justification=e.justification,
                    created_at=e.created_at,
                )
                for e in events
            ]
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to retrieve history for finding %s: %s", finding_id, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve finding history.",
            ) from exc

    @classmethod
    async def get_scan_findings(
        cls,
        db: AsyncSession,
        scan_id: str,
        user: Optional[User],
    ) -> List[FindingResponse]:
        """Retrieve all findings for a specific scan with parent project ownership validation."""
        try:
            scan_stmt = (
                select(Scan)
                .options(selectinload(Scan.project))
                .where(Scan.id == scan_id)
            )
            scan_res = await db.execute(scan_stmt)
            scan = scan_res.scalar_one_or_none()

            verify_scan_access(scan, user, scan_id)

            stmt = (
                select(Finding)
                .options(selectinload(Finding.scan).selectinload(Scan.project))
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.risk_score.desc())
            )
            result = await db.execute(stmt)
            findings = result.scalars().all()
            return [cls._format_finding_response(f) for f in findings]
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to retrieve findings for scan %s: %s", scan_id, exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve scan findings.",
            ) from exc
