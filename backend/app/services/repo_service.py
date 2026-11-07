import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.models.user import User
from app.models.repository import Repository, RepoScan, RepoFinding
from app.schemas.repository import RepositoryCreate, RepoFindingStatusUpdate
from app.scanners.web.validator import validate_target_url
from app.scanners.repo.engine import RepoSecurityScanner

logger = logging.getLogger("sentriq.services.repository")


class RepoService:
    """Service providing repository management, SAST, secret detection, and SCA auditing."""

    @classmethod
    def _apply_tenant_isolation(cls, stmt, user: Optional[User]):
        """Filter queries by tenant ownership when auth is active."""
        settings = get_settings()
        if settings.AUTH_ENABLED:
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required. No valid session found.",
                )
            if not user.is_superuser:
                stmt = stmt.where(Repository.owner_id == user.id)
        return stmt

    @classmethod
    async def create_repository(
        cls,
        db: AsyncSession,
        payload: RepositoryCreate,
        user: Optional[User],
    ) -> Repository:
        """Register a new code repository with SSRF validation on the clone URL."""
        # 1. SSRF Safety Check on Clone URL
        is_valid, err, normalized_url = validate_target_url(payload.clone_url)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security violation: Repository clone URL rejected ({err}).",
            )

        now_utc = datetime.now(timezone.utc)
        repo = Repository(
            id=str(uuid.uuid4()),
            name=payload.name.strip(),
            full_name=payload.full_name.strip(),
            clone_url=normalized_url or payload.clone_url.strip(),
            default_branch=payload.default_branch.strip() or "main",
            languages=payload.languages.strip() if payload.languages else None,
            is_private=payload.is_private,
            authorization_confirmed=payload.authorization_confirmed,
            owner_id=user.id if user else None,
            latest_posture_score=100,
            latest_risk_score=0,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(repo)
        await db.commit()
        await db.refresh(repo)
        return repo

    @classmethod
    async def list_repositories(
        cls,
        db: AsyncSession,
        user: Optional[User],
    ) -> List[Repository]:
        """List all accessible repositories for tenant."""
        stmt = select(Repository).order_by(desc(Repository.created_at))
        stmt = cls._apply_tenant_isolation(stmt, user)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def get_repository_by_id(
        cls,
        db: AsyncSession,
        repo_id: str,
        user: Optional[User],
    ) -> Repository:
        """Get repository detail with tenant isolation."""
        stmt = select(Repository).where(Repository.id == repo_id)
        stmt = cls._apply_tenant_isolation(stmt, user)
        res = await db.execute(stmt)
        repo = res.scalar_one_or_none()
        if not repo:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found or access denied.",
            )
        return repo

    @classmethod
    async def delete_repository(
        cls,
        db: AsyncSession,
        repo_id: str,
        user: Optional[User],
    ) -> Dict[str, Any]:
        """Delete repository and all cascaded scans/findings."""
        repo = await cls.get_repository_by_id(db, repo_id, user)
        await db.delete(repo)
        await db.commit()
        return {"success": True, "message": "Repository deleted successfully.", "deleted_id": repo_id}

    @classmethod
    async def run_repository_scan(
        cls,
        db: AsyncSession,
        repo_id: str,
        user: Optional[User],
        files_payload: Optional[Dict[str, str]] = None,
        branch: str = "main",
    ) -> RepoScan:
        """Execute SAST, Secret Detection, and SCA on repository files."""
        repo = await cls.get_repository_by_id(db, repo_id, user)
        now_utc = datetime.now(timezone.utc)

        scan = RepoScan(
            id=str(uuid.uuid4()),
            repository_id=repo.id,
            branch=branch,
            status="running",
            started_at=now_utc,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        try:
            # 1. Scan virtual files or local files
            files_to_scan = files_payload if files_payload is not None else {}
            score, counts, raw_findings = RepoSecurityScanner.scan_virtual_files(files_to_scan)

            completed_at = datetime.now(timezone.utc)
            scan.status = "completed"
            scan.completed_at = completed_at
            scan.posture_score = score
            scan.findings_count = counts["findings_count"]
            scan.secret_count = counts["secret_count"]
            scan.sast_count = counts["sast_count"]
            scan.sca_count = counts["sca_count"]
            scan.critical_count = counts["critical_count"]
            scan.high_count = counts["high_count"]
            scan.medium_count = counts["medium_count"]
            scan.low_count = counts["low_count"]
            scan.updated_at = completed_at

            # 2. Persist findings
            for rf in raw_findings:
                finding = RepoFinding(
                    id=str(uuid.uuid4()),
                    scan_id=scan.id,
                    scan_type=rf["scan_type"],
                    title=rf["title"],
                    description=rf["description"],
                    severity=rf["severity"],
                    confidence=rf["confidence"],
                    risk_score=rf["risk_score"],
                    file_path=rf["file_path"],
                    line_number=rf.get("line_number"),
                    rule_id=rf["rule_id"],
                    cwe=rf.get("cwe"),
                    cve=rf.get("cve"),
                    snippet=rf.get("snippet"),
                    remediation=rf.get("remediation"),
                    status="open",
                    created_at=completed_at,
                    updated_at=completed_at,
                )
                db.add(finding)

            # 3. Update Repository summary
            repo.last_scanned_at = completed_at
            repo.latest_posture_score = score
            repo.latest_risk_score = max(0, min(100, 100 - score))
            repo.updated_at = completed_at

            await db.commit()
            await db.refresh(scan)
            return scan
        except Exception as exc:
            logger.exception("Repository scan failed: %s", exc)
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Scan execution failed: {exc}",
            ) from exc

    @classmethod
    async def list_repo_scans(
        cls,
        db: AsyncSession,
        repo_id: str,
        user: Optional[User],
    ) -> List[RepoScan]:
        """List scan history for repository."""
        await cls.get_repository_by_id(db, repo_id, user)
        stmt = (
            select(RepoScan)
            .where(RepoScan.repository_id == repo_id)
            .order_by(desc(RepoScan.created_at))
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def list_repo_findings(
        cls,
        db: AsyncSession,
        repo_id: str,
        user: Optional[User],
        scan_type: Optional[str] = None,
        severity: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> List[RepoFinding]:
        """List findings across scans for a repository."""
        await cls.get_repository_by_id(db, repo_id, user)
        stmt = (
            select(RepoFinding)
            .join(RepoScan, RepoFinding.scan_id == RepoScan.id)
            .where(RepoScan.repository_id == repo_id)
            .order_by(desc(RepoFinding.risk_score), desc(RepoFinding.created_at))
        )
        if scan_type:
            stmt = stmt.where(RepoFinding.scan_type == scan_type)
        if severity:
            stmt = stmt.where(RepoFinding.severity == severity)
        if status_filter:
            stmt = stmt.where(RepoFinding.status == status_filter)

        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def update_finding_status(
        cls,
        db: AsyncSession,
        finding_id: str,
        payload: RepoFindingStatusUpdate,
        user: Optional[User],
    ) -> RepoFinding:
        """Update resolution status of a repository finding with mandatory justification."""
        stmt = (
            select(RepoFinding)
            .options(selectinload(RepoFinding.scan).selectinload(RepoScan.repository))
            .where(RepoFinding.id == finding_id)
        )
        res = await db.execute(stmt)
        finding = res.scalar_one_or_none()
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found.",
            )

        # Enforce tenant isolation on finding's parent repository
        repo = finding.scan.repository
        settings = get_settings()
        if settings.AUTH_ENABLED and user and not user.is_superuser:
            if repo.owner_id != user.id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Finding not found or access denied.",
                )

        if payload.status in ("accepted_risk", "false_positive") and not (
            payload.justification and payload.justification.strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A non-empty justification is mandatory when setting status to '{payload.status}'.",
            )

        finding.status = payload.status
        if payload.justification:
            finding.justification = payload.justification.strip()
        finding.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(finding)
        return finding
