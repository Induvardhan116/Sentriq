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
from app.models.api_security import ApiSpec, ApiEndpoint, ApiFinding
from app.schemas.api_security import ApiSpecImport, ApiFindingStatusUpdate
from app.scanners.api_sec.analyzer import ApiSecurityAnalyzer

logger = logging.getLogger("sentriq.services.api_security")


class ApiSecurityService:
    """Service providing OpenAPI/Swagger ingestion, endpoint inventory, and OWASP API audits."""

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
                stmt = stmt.where(ApiSpec.owner_id == user.id)
        return stmt

    @classmethod
    async def import_spec(
        cls,
        db: AsyncSession,
        payload: ApiSpecImport,
        user: Optional[User],
    ) -> ApiSpec:
        """Parse, ingest, and analyze an OpenAPI/Swagger schema."""
        try:
            parsed_data, fmt = ApiSecurityAnalyzer.parse_spec_content(payload.raw_spec)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )

        # Extract endpoints and assess vulnerabilities
        endpoints_data, findings_data, posture_score = (
            ApiSecurityAnalyzer.extract_endpoints_and_findings(parsed_data)
        )

        now_utc = datetime.now(timezone.utc)
        spec_info = parsed_data.get("info", {})
        title = payload.title.strip() or spec_info.get("title", "Imported API Specification")
        version = payload.version.strip() or spec_info.get("version", "1.0.0")
        desc = spec_info.get("description")

        spec = ApiSpec(
            id=str(uuid.uuid4()),
            title=title,
            version=version,
            description=desc,
            base_url=payload.base_url.strip() if payload.base_url else None,
            spec_format="openapi_3" if "openapi" in parsed_data else "swagger_2",
            raw_spec=payload.raw_spec,
            endpoint_count=len(endpoints_data),
            posture_score=posture_score,
            risk_score=max(0, min(100, 100 - posture_score)),
            last_scanned_at=now_utc,
            owner_id=user.id if user else None,
            created_at=now_utc,
            updated_at=now_utc,
        )
        db.add(spec)
        await db.flush()

        # Insert endpoints
        for ep in endpoints_data:
            endpoint_row = ApiEndpoint(
                id=str(uuid.uuid4()),
                spec_id=spec.id,
                path=ep["path"],
                method=ep["method"],
                summary=ep["summary"],
                auth_required=ep["auth_required"],
                auth_type=ep["auth_type"],
                parameters_count=ep["parameters_count"],
                has_request_body=ep["has_request_body"],
                tags=ep["tags"],
                created_at=now_utc,
                updated_at=now_utc,
            )
            db.add(endpoint_row)

        # Insert findings
        for f in findings_data:
            finding_row = ApiFinding(
                id=str(uuid.uuid4()),
                spec_id=spec.id,
                path=f.get("path"),
                method=f.get("method"),
                owasp_category=f["owasp_category"],
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                confidence=f["confidence"],
                risk_score=f["risk_score"],
                remediation=f.get("remediation"),
                status="open",
                created_at=now_utc,
                updated_at=now_utc,
            )
            db.add(finding_row)

        await db.commit()
        await db.refresh(spec)
        return spec

    @classmethod
    async def list_specs(
        cls,
        db: AsyncSession,
        user: Optional[User],
    ) -> List[ApiSpec]:
        """List all accessible API specifications for tenant."""
        stmt = select(ApiSpec).order_by(desc(ApiSpec.created_at))
        stmt = cls._apply_tenant_isolation(stmt, user)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def get_spec_by_id(
        cls,
        db: AsyncSession,
        spec_id: str,
        user: Optional[User],
    ) -> ApiSpec:
        """Get API specification detail with tenant isolation."""
        stmt = select(ApiSpec).where(ApiSpec.id == spec_id)
        stmt = cls._apply_tenant_isolation(stmt, user)
        res = await db.execute(stmt)
        spec = res.scalar_one_or_none()
        if not spec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API specification not found or access denied.",
            )
        return spec

    @classmethod
    async def list_spec_endpoints(
        cls,
        db: AsyncSession,
        spec_id: str,
        user: Optional[User],
    ) -> List[ApiEndpoint]:
        """List all discovered endpoints for a specification."""
        await cls.get_spec_by_id(db, spec_id, user)
        stmt = (
            select(ApiEndpoint)
            .where(ApiEndpoint.spec_id == spec_id)
            .order_by(ApiEndpoint.path, ApiEndpoint.method)
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def list_spec_findings(
        cls,
        db: AsyncSession,
        spec_id: str,
        user: Optional[User],
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[ApiFinding]:
        """List findings mapped to OWASP API Security Top 10."""
        await cls.get_spec_by_id(db, spec_id, user)
        stmt = (
            select(ApiFinding)
            .where(ApiFinding.spec_id == spec_id)
            .order_by(desc(ApiFinding.risk_score), desc(ApiFinding.created_at))
        )
        if category:
            stmt = stmt.where(ApiFinding.owasp_category == category)
        if severity:
            stmt = stmt.where(ApiFinding.severity == severity)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def update_finding_status(
        cls,
        db: AsyncSession,
        finding_id: str,
        payload: ApiFindingStatusUpdate,
        user: Optional[User],
    ) -> ApiFinding:
        """Update resolution status of an API finding with mandatory justification."""
        stmt = (
            select(ApiFinding)
            .options(selectinload(ApiFinding.spec))
            .where(ApiFinding.id == finding_id)
        )
        res = await db.execute(stmt)
        finding = res.scalar_one_or_none()
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API finding not found.",
            )

        # Enforce tenant isolation on finding's parent spec
        spec = finding.spec
        settings = get_settings()
        if settings.AUTH_ENABLED and user and not user.is_superuser:
            if spec.owner_id != user.id:
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

    @classmethod
    async def delete_spec(
        cls,
        db: AsyncSession,
        spec_id: str,
        user: Optional[User],
    ) -> Dict[str, Any]:
        """Delete an API specification and its endpoints/findings."""
        spec = await cls.get_spec_by_id(db, spec_id, user)
        await db.delete(spec)
        await db.commit()
        return {"success": True, "message": "API specification deleted successfully.", "deleted_id": spec_id}
