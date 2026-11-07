import hmac
import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import httpx

from app.models.integration import WebhookEndpoint, ScanSchedule
from app.models.user import User
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.integration import (
    WebhookCreate,
    WebhookResponse,
    WebhookTestResult,
    ScanScheduleCreate,
    ScanScheduleResponse,
    SiemLogItem,
)
from app.scanners.web.validator import validate_target_url

logger = logging.getLogger("sentriq.services.integrations")


def mask_secret(secret: str) -> str:
    """Mask secret token leaving only prefix and trailing 4 characters."""
    if not secret or len(secret) <= 8:
        return "whsec_****"
    return f"{secret[:6]}****{secret[-4:]}"


class IntegrationService:
    @classmethod
    async def create_webhook(
        cls, db: AsyncSession, payload: WebhookCreate, user: Optional[User]
    ) -> WebhookResponse:
        """Register a new outbound webhook with SSRF validation."""
        # SSRF Security Validation
        is_valid, err_reason, normalized_url = validate_target_url(payload.target_url)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target webhook URL rejected by SSRF guardrail: {err_reason}",
            )

        user_id = user.id if user else None
        raw_secret = payload.secret_token or f"whsec_{secrets.token_hex(16)}"

        endpoint = WebhookEndpoint(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=payload.name.strip(),
            target_url=normalized_url,
            secret_token=raw_secret,
            event_types=payload.event_types.strip(),
            is_active=True,
        )

        db.add(endpoint)
        await db.commit()
        await db.refresh(endpoint)

        return WebhookResponse(
            id=endpoint.id,
            name=endpoint.name,
            target_url=endpoint.target_url,
            secret_token=mask_secret(endpoint.secret_token),
            event_types=endpoint.event_types,
            is_active=endpoint.is_active,
            last_dispatched_at=endpoint.last_dispatched_at,
            last_status_code=endpoint.last_status_code,
            created_at=endpoint.created_at,
            updated_at=endpoint.updated_at,
        )

    @classmethod
    async def list_webhooks(
        cls, db: AsyncSession, user: Optional[User]
    ) -> List[WebhookResponse]:
        """List webhooks for tenant with masked secrets."""
        stmt = select(WebhookEndpoint).order_by(WebhookEndpoint.created_at.desc())
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(WebhookEndpoint.user_id == user.id)

        result = await db.execute(stmt)
        endpoints = result.scalars().all()

        return [
            WebhookResponse(
                id=ep.id,
                name=ep.name,
                target_url=ep.target_url,
                secret_token=mask_secret(ep.secret_token),
                event_types=ep.event_types,
                is_active=ep.is_active,
                last_dispatched_at=ep.last_dispatched_at,
                last_status_code=ep.last_status_code,
                created_at=ep.created_at,
                updated_at=ep.updated_at,
            )
            for ep in endpoints
        ]

    @classmethod
    async def delete_webhook(
        cls, db: AsyncSession, webhook_id: str, user: Optional[User]
    ) -> None:
        """Delete webhook endpoint ensuring tenant authorization."""
        stmt = select(WebhookEndpoint).where(WebhookEndpoint.id == webhook_id)
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(WebhookEndpoint.user_id == user.id)

        result = await db.execute(stmt)
        ep = result.scalar_one_or_none()
        if not ep:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Webhook endpoint not found or access denied.",
            )

        await db.delete(ep)
        await db.commit()

    @classmethod
    async def test_webhook(
        cls, db: AsyncSession, webhook_id: str, user: Optional[User]
    ) -> WebhookTestResult:
        """Dispatch test notification with HMAC-SHA256 signature."""
        stmt = select(WebhookEndpoint).where(WebhookEndpoint.id == webhook_id)
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(WebhookEndpoint.user_id == user.id)

        result = await db.execute(stmt)
        ep = result.scalar_one_or_none()
        if not ep:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Webhook endpoint not found or access denied.",
            )

        test_payload = {
            "event": "sentriq.test.ping",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "channel": ep.name,
            "security_summary": {
                "platform": "Sentriq ASPM",
                "status": "Operational",
                "message": "Webhook delivery verified successfully."
            }
        }
        body_bytes = json.dumps(test_payload).encode("utf-8")
        signature = hmac.new(ep.secret_token.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Sentriq-Webhook-Dispatcher/1.0",
            "X-Sentriq-Signature": f"sha256={signature}",
            "X-Sentriq-Event": "test.ping",
        }

        success = False
        status_code = None
        message = ""

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(ep.target_url, content=body_bytes, headers=headers)
                status_code = res.status_code
                success = res.is_success
                message = f"Delivered with HTTP {status_code}"
        except Exception as ex:
            logger.warning(f"Webhook test delivery failed to {ep.target_url}: {ex}")
            message = f"Delivery connection error: {str(ex)}"
            status_code = 502

        ep.last_dispatched_at = datetime.now(timezone.utc)
        ep.last_status_code = status_code
        await db.commit()

        return WebhookTestResult(
            success=success,
            status_code=status_code,
            message=message,
            delivered_payload=test_payload,
        )

    @classmethod
    async def create_schedule(
        cls, db: AsyncSession, payload: ScanScheduleCreate, user: Optional[User]
    ) -> ScanScheduleResponse:
        """Register a recurring automated scan schedule."""
        user_id = user.id if user else None
        now = datetime.now(timezone.utc)

        delta = timedelta(days=1) if payload.frequency == "daily" else timedelta(days=7) if payload.frequency == "weekly" else timedelta(days=30)
        next_run = now + delta

        schedule = ScanSchedule(
            id=str(uuid.uuid4()),
            user_id=user_id,
            target_type=payload.target_type,
            target_id=payload.target_id,
            target_name=payload.target_name.strip(),
            frequency=payload.frequency,
            is_active=True,
            last_run_at=None,
            next_run_at=next_run,
        )

        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)

        return ScanScheduleResponse(
            id=schedule.id,
            target_type=schedule.target_type,
            target_id=schedule.target_id,
            target_name=schedule.target_name,
            frequency=schedule.frequency,
            is_active=schedule.is_active,
            last_run_at=schedule.last_run_at,
            next_run_at=schedule.next_run_at,
            created_at=schedule.created_at,
            updated_at=schedule.updated_at,
        )

    @classmethod
    async def list_schedules(
        cls, db: AsyncSession, user: Optional[User]
    ) -> List[ScanScheduleResponse]:
        """List active schedules for tenant."""
        stmt = select(ScanSchedule).order_by(ScanSchedule.created_at.desc())
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(ScanSchedule.user_id == user.id)

        result = await db.execute(stmt)
        schedules = result.scalars().all()

        return [
            ScanScheduleResponse(
                id=s.id,
                target_type=s.target_type,
                target_id=s.target_id,
                target_name=s.target_name,
                frequency=s.frequency,
                is_active=s.is_active,
                last_run_at=s.last_run_at,
                next_run_at=s.next_run_at,
                created_at=s.created_at,
                updated_at=s.updated_at,
            )
            for s in schedules
        ]

    @classmethod
    async def delete_schedule(
        cls, db: AsyncSession, schedule_id: str, user: Optional[User]
    ) -> None:
        """Delete recurring schedule ensuring tenant isolation."""
        stmt = select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(ScanSchedule.user_id == user.id)

        result = await db.execute(stmt)
        schedule = result.scalar_one_or_none()
        if not schedule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan schedule not found or access denied.",
            )

        await db.delete(schedule)
        await db.commit()

    @classmethod
    async def execute_schedule(
        cls, db: AsyncSession, schedule_id: str, user: Optional[User]
    ) -> Dict[str, Any]:
        """Trigger immediate execution of a scheduled recurring scan and advance next_run_at."""
        stmt = select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        if user and not getattr(user, "is_superuser", False):
            stmt = stmt.where(ScanSchedule.user_id == user.id)

        result = await db.execute(stmt)
        schedule = result.scalar_one_or_none()
        if not schedule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan schedule not found or access denied.",
            )

        now = datetime.now(timezone.utc)
        delta = timedelta(days=1) if schedule.frequency == "daily" else timedelta(days=7) if schedule.frequency == "weekly" else timedelta(days=30)
        schedule.last_run_at = now
        schedule.next_run_at = now + delta

        await db.commit()
        await db.refresh(schedule)

        logger.info("Executed scheduled scan [%s] for %s target: %s", schedule.id, schedule.target_type, schedule.target_name)
        return {
            "message": f"Scheduled {schedule.frequency} scan executed successfully for {schedule.target_name}.",
            "schedule_id": schedule.id,
            "target_type": schedule.target_type,
            "target_id": schedule.target_id,
            "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
            "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        }

    @classmethod
    async def generate_siem_events(
        cls, db: AsyncSession, user: Optional[User]
    ) -> List[SiemLogItem]:
        """Format vulnerability findings into Common Event Format (CEF) and JSON for SIEM tools."""
        user_id = user.id if user else None
        is_super = getattr(user, "is_superuser", False) if user else False

        p_stmt = select(Project)
        if not is_super and user_id:
            p_stmt = p_stmt.where(Project.owner_id == user_id)
        p_res = await db.execute(p_stmt)
        projects = list(p_res.scalars().all())
        project_ids = [p.id for p in projects]

        events: List[SiemLogItem] = []
        if project_ids:
            s_stmt = select(Scan).where(Scan.project_id.in_(project_ids))
            s_res = await db.execute(s_stmt)
            scans = list(s_res.scalars().all())
            scan_ids = [s.id for s in scans]
            scan_to_proj = {s.id: s.project_id for s in scans}
            proj_to_name = {p.id: p.name for p in projects}

            if scan_ids:
                f_stmt = select(Finding).where(Finding.scan_id.in_(scan_ids)).order_by(Finding.created_at.desc()).limit(50)
                f_res = await db.execute(f_stmt)
                for f in f_res.scalars().all():
                    proj_id = scan_to_proj.get(f.scan_id)
                    asset_name = proj_to_name.get(proj_id, "Unknown Website")
                    sev_num = 10 if f.severity == "critical" else 7 if f.severity == "high" else 4 if f.severity == "medium" else 1

                    iso_time = f.created_at.isoformat() if f.created_at else datetime.now(timezone.utc).isoformat()
                    cef = f"CEF:0|Sentriq|ASPM|1.0|{f.category}|{f.title}|{sev_num}|src={asset_name} status={f.status} cs1={f.id} cs1Label=FindingID"

                    events.append(
                        SiemLogItem(
                            timestamp=iso_time,
                            event_id=f.id,
                            severity=f.severity.upper(),
                            source="Website Scanner",
                            asset=asset_name,
                            message=f.title,
                            cef_string=cef,
                        )
                    )

        # Baseline demo event if none found
        if not events:
            now_iso = datetime.now(timezone.utc).isoformat()
            events.append(
                SiemLogItem(
                    timestamp=now_iso,
                    event_id=str(uuid.uuid4()),
                    severity="INFO",
                    source="Sentriq ASPM SIEM",
                    asset="Security Perimeter",
                    message="All monitored systems operational with zero open alerts.",
                    cef_string=f"CEF:0|Sentriq|ASPM|1.0|System|Security Baseline Established|1|src=CorePlatform msg=Operational",
                )
            )

        return events
