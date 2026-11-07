import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_security import CloudAccount, CloudFinding
from app.models.user import User
from app.schemas.cloud_security import (
    CloudAccountCreate,
    CloudScanTrigger,
    CloudFindingStatusUpdate,
)
from app.scanners.cloud.cspm_analyzer import CspmAnalyzer, mask_cloud_credential

logger = logging.getLogger("sentriq.services.cloud_security")


class CloudSecurityService:
    @staticmethod
    def _enforce_tenant_filter(query, user: Optional[User]):
        """Enforce tenant isolation on cloud account queries."""
        if user is None:
            return query
        if getattr(user, "is_superuser", False):
            return query
        return query.where(CloudAccount.user_id == user.id)

    @classmethod
    async def create_account(
        cls, db: AsyncSession, payload: CloudAccountCreate, user: Optional[User]
    ) -> CloudAccount:
        """Register a new cloud account with masked credentials."""
        user_id = user.id if user else None
        masked_role = mask_cloud_credential(payload.role_arn_or_ref)

        account = CloudAccount(
            id=str(uuid.uuid4()),
            user_id=user_id,
            provider=payload.provider.lower(),
            name=payload.name.strip(),
            account_identifier=payload.account_identifier.strip(),
            role_arn_or_ref=masked_role,
            region=payload.region.strip(),
            is_active=True,
            posture_score=100,
            risk_score=0,
        )

        db.add(account)
        await db.commit()
        await db.refresh(account)
        return account

    @classmethod
    async def list_accounts(
        cls, db: AsyncSession, user: Optional[User]
    ) -> List[Dict[str, Any]]:
        """List cloud accounts belonging to the authenticated tenant."""
        stmt = select(CloudAccount).order_by(CloudAccount.created_at.desc())
        stmt = cls._enforce_tenant_filter(stmt, user)
        result = await db.execute(stmt)
        accounts = result.scalars().all()

        output = []
        for acc in accounts:
            open_findings = [f for f in acc.findings if f.status == "open"]
            data = {
                "id": acc.id,
                "provider": acc.provider,
                "name": acc.name,
                "account_identifier": acc.account_identifier,
                "role_arn_or_ref": acc.role_arn_or_ref,
                "region": acc.region,
                "is_active": acc.is_active,
                "posture_score": acc.posture_score,
                "risk_score": acc.risk_score,
                "findings_count": len(open_findings),
                "connection_status": "Awaiting Live Cloud Credentials",
                "audit_mode": "Infrastructure Config Audit" if acc.last_scanned_at else "Awaiting Configuration",
                "last_scanned_at": acc.last_scanned_at,
                "created_at": acc.created_at,
                "updated_at": acc.updated_at,
            }
            output.append(data)
        return output

    @classmethod
    async def get_account(
        cls, db: AsyncSession, account_id: str, user: Optional[User]
    ) -> CloudAccount:
        """Fetch single cloud account ensuring tenant authorization."""
        stmt = select(CloudAccount).where(CloudAccount.id == account_id)
        stmt = cls._enforce_tenant_filter(stmt, user)
        result = await db.execute(stmt)
        account = result.scalar_one_or_none()
        if not account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud account not found or access denied.",
            )
        return account

    @classmethod
    async def delete_account(
        cls, db: AsyncSession, account_id: str, user: Optional[User]
    ) -> None:
        """Delete cloud account and cascade delete findings."""
        account = await cls.get_account(db, account_id, user)
        await db.delete(account)
        await db.commit()

    @classmethod
    async def scan_account(
        cls,
        db: AsyncSession,
        account_id: str,
        payload: CloudScanTrigger,
        user: Optional[User],
    ) -> CloudAccount:
        """Run CSPM audit on cloud account using submitted or default baseline configuration."""
        account = await cls.get_account(db, account_id, user)

        # Baseline demo configuration if none provided
        config_data = payload.config_data or {
            "buckets": [
                {
                    "name": f"{account.name.lower().replace(' ', '-')}-assets",
                    "public_access_block": False,
                    "is_public": True,
                    "encryption_enabled": False,
                    "versioning_enabled": False,
                }
            ],
            "iam": {
                "root_mfa_enabled": False,
                "policies": [
                    {
                        "name": "AdministratorAccessUnscoped",
                        "has_wildcard_admin": True,
                    }
                ],
                "access_keys": [
                    {"id": "AKIAIOSFODNN7EXAMPLE", "age_days": 120, "is_active": True}
                ],
            },
            "security_groups": [
                {
                    "id": "sg-public-ingress",
                    "inbound_rules": [
                        {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22},
                        {"cidr": "0.0.0.0/0", "from_port": 5432, "to_port": 5432},
                    ],
                }
            ],
            "supabase": {
                "tables": [
                    {"name": "user_profiles", "rls_enabled": False},
                    {"name": "billing_records", "rls_enabled": False},
                ],
                "ssl_enforced": False,
            },
        }

        # Clear existing open findings to refresh scan results
        await db.execute(
            delete(CloudFinding).where(
                CloudFinding.account_id == account_id,
                CloudFinding.status == "open",
            )
        )

        detected_findings = CspmAnalyzer.audit_configuration(
            provider=account.provider,
            account_identifier=account.account_identifier,
            config_data=config_data,
        )

        # Insert new findings
        total_risk_penalty = 0
        for f in detected_findings:
            db_finding = CloudFinding(
                id=str(uuid.uuid4()),
                account_id=account.id,
                service=f["service"],
                resource_id=f["resource_id"],
                resource_type=f["resource_type"],
                benchmark_ref=f["benchmark_ref"],
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                confidence=f["confidence"],
                risk_score=f["risk_score"],
                remediation=f["remediation"],
                status="open",
            )
            db.add(db_finding)
            total_risk_penalty += f["risk_score"]

        # Calculate Posture Score
        calculated_posture = max(0, 100 - min(100, int(total_risk_penalty * 0.4)))
        account.posture_score = calculated_posture
        account.risk_score = 100 - calculated_posture
        account.last_scanned_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(account)
        return account

    @classmethod
    async def list_findings(
        cls,
        db: AsyncSession,
        account_id: str,
        service: Optional[str],
        severity: Optional[str],
        status_filter: Optional[str],
        user: Optional[User],
    ) -> List[CloudFinding]:
        """Fetch findings for cloud account with filters."""
        # Check tenant access
        await cls.get_account(db, account_id, user)

        stmt = select(CloudFinding).where(CloudFinding.account_id == account_id)
        if service:
            stmt = stmt.where(CloudFinding.service == service.lower())
        if severity:
            stmt = stmt.where(CloudFinding.severity == severity.lower())
        if status_filter:
            stmt = stmt.where(CloudFinding.status == status_filter.lower())

        stmt = stmt.order_by(CloudFinding.risk_score.desc())
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @classmethod
    async def update_finding_status(
        cls,
        db: AsyncSession,
        finding_id: str,
        payload: CloudFindingStatusUpdate,
        user: Optional[User],
    ) -> CloudFinding:
        """Triage finding status with mandatory justification for accepted risk or false positive."""
        stmt = (
            select(CloudFinding)
            .join(CloudAccount)
            .where(CloudFinding.id == finding_id)
        )
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(CloudAccount.user_id == user.id)

        result = await db.execute(stmt)
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud finding not found or access denied.",
            )

        if payload.status in ["accepted_risk", "false_positive"]:
            if not payload.justification or len(payload.justification.strip()) < 10:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A detailed justification of at least 10 characters is mandatory for accepted risk or false positive status.",
                )

        finding.status = payload.status
        finding.justification = payload.justification.strip() if payload.justification else None
        await db.commit()
        await db.refresh(finding)
        return finding
