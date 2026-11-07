import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple
from fastapi import HTTPException, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.risk.engine import (
    SEVERITY_DEDUCTIONS,
    map_score_to_grade,
    calculate_posture_score,
)
from app.schemas.analytics import (
    RiskSummaryResponse,
    SeverityDistribution,
    StatusDistribution,
    DomainScore,
    RemediationMetrics,
    PostureTrendPoint,
    PostureTrendsResponse,
    ProjectRiskRankingItem,
    ProjectRankingsResponse,
)

logger = logging.getLogger("sentriq.services.analytics")

KNOWN_DOMAINS = {
    "https": ("TLS & Cryptography", "Evaluates SSL/TLS certificates, protocols, and secure transport redirects."),
    "headers": ("Security Response Headers", "Checks HSTS, Content-Security-Policy, anti-clickjacking, and sniffing protections."),
    "cookies": ("Cookie Security & Privacy", "Audits Secure, HttpOnly, and SameSite attributes with zero raw token storage."),
    "cors": ("Cross-Origin Resource Sharing", "Analyzes wildcard origins, arbitrary reflection, and credential exposure."),
    "exposure": ("Information Disclosure", "Detects software banner leaks, debug stack traces, and public source maps."),
    "configuration": ("Security Configuration", "Verifies RFC 9116 security.txt, robots.txt boundaries, and mixed content."),
}


class AnalyticsService:
    """Service providing deep risk analytics, historical trend tracking, and project risk rankings."""

    @classmethod
    def _apply_tenant_isolation(cls, stmt, user: Optional[User]):
        """Ensure tenant isolation on queries involving Project."""
        settings = get_settings()
        if settings.AUTH_ENABLED:
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required. No valid session found.",
                )
            if not user.is_superuser:
                stmt = stmt.where(Project.owner_id == user.id)
        return stmt

    @classmethod
    async def get_risk_summary(
        cls,
        db: AsyncSession,
        user: Optional[User],
        project_id: Optional[str] = None,
    ) -> RiskSummaryResponse:
        """Compute platform or project-level security posture score, domain breakdowns, and remediation KPIs."""
        try:
            now_utc = datetime.now(timezone.utc)

            # 1. Base Project Query with Tenant Filter
            proj_stmt = select(Project)
            proj_stmt = cls._apply_tenant_isolation(proj_stmt, user)
            if project_id:
                proj_stmt = proj_stmt.where(Project.id == project_id)

            proj_res = await db.execute(proj_stmt)
            projects = proj_res.scalars().all()
            total_projects = len(projects)

            if total_projects == 0:
                # Return pristine baseline state if no projects exist
                return RiskSummaryResponse(
                    overall_posture_score=100,
                    grade="Excellent",
                    evaluated_at=now_utc,
                    total_projects=0,
                    total_scans=0,
                    total_findings=0,
                    active_findings=0,
                    severity_distribution=SeverityDistribution(),
                    status_distribution=StatusDistribution(),
                    domain_breakdown=[],
                    remediation_metrics=RemediationMetrics(
                        remediation_rate_percent=100.0,
                        total_findings_discovered=0,
                        active_findings_count=0,
                        resolved_findings_count=0,
                    ),
                    score_formula_explanation="No projects registered yet. Baseline security posture initialized to 100/100.",
                    active_caps_applied=[],
                )

            project_ids = [p.id for p in projects]

            # 2. Fetch completed scans for these projects
            scan_stmt = select(Scan).where(
                Scan.project_id.in_(project_ids),
                Scan.status == "completed",
            )
            scan_res = await db.execute(scan_stmt)
            scans = scan_res.scalars().all()
            total_scans = len(scans)

            # 3. Fetch all findings across these projects
            find_stmt = (
                select(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .where(Scan.project_id.in_(project_ids))
            )
            find_res = await db.execute(find_stmt)
            all_findings = find_res.scalars().all()
            total_findings = len(all_findings)

            # Separate active findings vs resolved/closed
            active_findings = [f for f in all_findings if f.status in ("open", "in_progress")]
            resolved_findings = [f for f in all_findings if f.status == "resolved"]

            # Compute Severity Distribution of ACTIVE findings
            sev_dist = SeverityDistribution()
            for f in active_findings:
                s = (f.severity or "informational").lower()
                if s == "critical":
                    sev_dist.critical += 1
                elif s == "high":
                    sev_dist.high += 1
                elif s == "medium":
                    sev_dist.medium += 1
                elif s == "low":
                    sev_dist.low += 1
                else:
                    sev_dist.informational += 1

            # Compute Status Distribution
            st_dist = StatusDistribution()
            for f in all_findings:
                st = (f.status or "open").lower()
                if st == "open":
                    st_dist.open += 1
                elif st == "in_progress":
                    st_dist.in_progress += 1
                elif st == "resolved":
                    st_dist.resolved += 1
                elif st == "accepted_risk":
                    st_dist.accepted_risk += 1
                elif st == "false_positive":
                    st_dist.false_positive += 1

            # 4. Compute Overall Posture Score using the Active Findings
            active_dicts = [{"severity": f.severity} for f in active_findings]
            score, grade, _ = calculate_posture_score(active_dicts)

            caps_applied: List[str] = []
            if sev_dist.critical > 0:
                caps_applied.append("Critical Finding Ceiling: Score capped at maximum 49 (Poor)")
            elif sev_dist.high > 0:
                caps_applied.append("High Finding Ceiling: Score capped at maximum 74 (Needs Improvement)")

            # 5. Domain Breakdown
            domain_stats: Dict[str, Dict[str, int]] = {}
            for f in active_findings:
                cat = (f.category or "configuration").lower()
                if cat not in domain_stats:
                    domain_stats[cat] = {"total": 0, "critical": 0, "high": 0}
                domain_stats[cat]["total"] += 1
                if f.severity == "critical":
                    domain_stats[cat]["critical"] += 1
                elif f.severity == "high":
                    domain_stats[cat]["high"] += 1

            domain_list: List[DomainScore] = []
            for dom_key, (dom_name, dom_desc) in KNOWN_DOMAINS.items():
                stats = domain_stats.get(dom_key, {"total": 0, "critical": 0, "high": 0})
                if stats["critical"] > 0:
                    health = "critical"
                elif stats["high"] > 0 or stats["total"] > 2:
                    health = "warning"
                else:
                    health = "healthy"

                domain_list.append(
                    DomainScore(
                        domain=dom_name,
                        finding_count=stats["total"],
                        critical_count=stats["critical"],
                        high_count=stats["high"],
                        health_status=health,
                        description=dom_desc,
                    )
                )

            # 6. Remediation Metrics & Exposure Times
            remediation_rate = (
                (len(resolved_findings) / total_findings * 100.0)
                if total_findings > 0
                else 100.0
            )

            # Mean time to remediate (for resolved findings)
            mttr_days: Optional[float] = None
            resolved_durations: List[float] = []
            for f in resolved_findings:
                if f.created_at and f.updated_at and f.updated_at >= f.created_at:
                    created = f.created_at if f.created_at.tzinfo else f.created_at.replace(tzinfo=timezone.utc)
                    updated = f.updated_at if f.updated_at.tzinfo else f.updated_at.replace(tzinfo=timezone.utc)
                    delta_d = (updated - created).total_seconds() / 86400.0
                    resolved_durations.append(delta_d)
            if resolved_durations:
                mttr_days = round(sum(resolved_durations) / len(resolved_durations), 1)

            # Open findings exposure age
            open_ages: List[float] = []
            for f in active_findings:
                if f.created_at:
                    created = f.created_at if f.created_at.tzinfo else f.created_at.replace(tzinfo=timezone.utc)
                    age_d = max(0.0, (now_utc - created).total_seconds() / 86400.0)
                    open_ages.append(age_d)

            oldest_age = round(max(open_ages), 1) if open_ages else None
            avg_age = round(sum(open_ages) / len(open_ages), 1) if open_ages else None

            remediation_metrics = RemediationMetrics(
                remediation_rate_percent=round(remediation_rate, 1),
                total_findings_discovered=total_findings,
                active_findings_count=len(active_findings),
                resolved_findings_count=len(resolved_findings),
                mean_time_to_remediate_days=mttr_days,
                oldest_open_finding_days=oldest_age,
                avg_finding_age_days=avg_age,
            )

            formula_exp = (
                f"Calculated from {len(active_findings)} active security findings across {total_projects} projects. "
                f"Base score: 100. Deductions: -25/crit, -15/high, -8/med, -3/low, -1/info (max 5)."
            )

            return RiskSummaryResponse(
                overall_posture_score=score,
                grade=grade,
                evaluated_at=now_utc,
                total_projects=total_projects,
                total_scans=total_scans,
                total_findings=total_findings,
                active_findings=len(active_findings),
                severity_distribution=sev_dist,
                status_distribution=st_dist,
                domain_breakdown=domain_list,
                remediation_metrics=remediation_metrics,
                score_formula_explanation=formula_exp,
                active_caps_applied=caps_applied,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to calculate risk summary: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to calculate risk summary metrics.",
            ) from exc

    @classmethod
    async def get_posture_trends(
        cls,
        db: AsyncSession,
        user: Optional[User],
        project_id: Optional[str] = None,
        days: int = 30,
    ) -> PostureTrendsResponse:
        """Compute chronological security posture trend points across historical scans."""
        try:
            now_utc = datetime.now(timezone.utc)
            cutoff = now_utc - timedelta(days=max(1, min(days, 365)))

            # 1. Base project tenant isolation
            proj_stmt = select(Project)
            proj_stmt = cls._apply_tenant_isolation(proj_stmt, user)
            if project_id:
                proj_stmt = proj_stmt.where(Project.id == project_id)

            proj_res = await db.execute(proj_stmt)
            projects = {p.id: p.name for p in proj_res.scalars().all()}

            if not projects:
                return PostureTrendsResponse(
                    total_points=0,
                    timeframe_days=days,
                    trend_direction="insufficient_data",
                    score_delta=0,
                    data_points=[],
                )

            # 2. Query completed scans in chronological order
            scan_stmt = (
                select(Scan)
                .options(selectinload(Scan.findings))
                .where(
                    Scan.project_id.in_(list(projects.keys())),
                    Scan.status == "completed",
                    Scan.created_at >= cutoff,
                )
                .order_by(Scan.created_at.asc())
            )
            scan_res = await db.execute(scan_stmt)
            scans = scan_res.scalars().all()

            # If no scans in cutoff timeframe, fetch up to 20 most recent scans anyway
            if not scans:
                fallback_stmt = (
                    select(Scan)
                    .options(selectinload(Scan.findings))
                    .where(
                        Scan.project_id.in_(list(projects.keys())),
                        Scan.status == "completed",
                    )
                    .order_by(Scan.created_at.asc())
                    .limit(20)
                )
                fallback_res = await db.execute(fallback_stmt)
                scans = fallback_res.scalars().all()

            if not scans:
                return PostureTrendsResponse(
                    total_points=0,
                    timeframe_days=days,
                    trend_direction="insufficient_data",
                    score_delta=0,
                    data_points=[],
                )

            data_points: List[PostureTrendPoint] = []
            for scan in scans:
                active_findings = [f for f in scan.findings if f.status in ("open", "in_progress")]
                crits = sum(1 for f in active_findings if f.severity == "critical")
                highs = sum(1 for f in active_findings if f.severity == "high")
                meds = sum(1 for f in active_findings if f.severity == "medium")
                lows = sum(1 for f in active_findings if f.severity == "low")

                scan_dt = scan.created_at if scan.created_at.tzinfo else scan.created_at.replace(tzinfo=timezone.utc)
                data_points.append(
                    PostureTrendPoint(
                        scan_id=scan.id,
                        project_id=scan.project_id,
                        project_name=projects.get(scan.project_id, "Unknown"),
                        scan_date=scan_dt,
                        date_label=scan_dt.strftime("%b %d, %H:%M"),
                        posture_score=scan.overall_score or 100,
                        grade=map_score_to_grade(scan.overall_score or 100),
                        critical_count=crits,
                        high_count=highs,
                        medium_count=meds,
                        low_count=lows,
                        active_findings_count=len(active_findings),
                    )
                )

            # Determine trend direction from oldest to latest
            score_delta = 0
            if len(data_points) >= 2:
                first_score = data_points[0].posture_score
                last_score = data_points[-1].posture_score
                score_delta = last_score - first_score
                if score_delta > 3:
                    trend_dir = "improving"
                elif score_delta < -3:
                    trend_dir = "degrading"
                else:
                    trend_dir = "stable"
            elif len(data_points) == 1:
                trend_dir = "stable"
            else:
                trend_dir = "insufficient_data"

            return PostureTrendsResponse(
                total_points=len(data_points),
                timeframe_days=days,
                trend_direction=trend_dir,
                score_delta=score_delta,
                data_points=data_points,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to calculate posture trends: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve posture trends.",
            ) from exc

    @classmethod
    async def get_project_rankings(
        cls,
        db: AsyncSession,
        user: Optional[User],
        limit: int = 50,
    ) -> ProjectRankingsResponse:
        """Rank all projects by calculated risk index to prioritize security remediation."""
        try:
            now_utc = datetime.now(timezone.utc)

            # 1. Fetch accessible projects
            proj_stmt = (
                select(Project)
                .options(selectinload(Project.scans).selectinload(Scan.findings))
            )
            proj_stmt = cls._apply_tenant_isolation(proj_stmt, user)
            proj_res = await db.execute(proj_stmt)
            projects = proj_res.scalars().all()

            if not projects:
                return ProjectRankingsResponse(
                    total_projects=0,
                    highest_risk_project=None,
                    rankings=[],
                )

            items: List[ProjectRiskRankingItem] = []

            for proj in projects:
                # Get completed scans sorted by created_at desc
                completed_scans = sorted(
                    [s for s in proj.scans if s.status == "completed"],
                    key=lambda s: s.created_at,
                    reverse=True,
                )

                if completed_scans:
                    latest_scan = completed_scans[0]
                    posture_score = latest_scan.overall_score or 100
                    last_scanned_at = (
                        latest_scan.created_at
                        if latest_scan.created_at.tzinfo
                        else latest_scan.created_at.replace(tzinfo=timezone.utc)
                    )

                    # Determine project trend from last two scans
                    if len(completed_scans) >= 2:
                        prev_score = completed_scans[1].overall_score or 100
                        if posture_score > prev_score + 2:
                            trend = "improving"
                        elif posture_score < prev_score - 2:
                            trend = "degrading"
                        else:
                            trend = "stable"
                    else:
                        trend = "stable"

                    # Calculate active findings on latest scan
                    active_findings = [
                        f for f in latest_scan.findings if f.status in ("open", "in_progress")
                    ]
                    crits = sum(1 for f in active_findings if f.severity == "critical")
                    highs = sum(1 for f in active_findings if f.severity == "high")

                    # Exposure days
                    earliest_dt = None
                    for f in active_findings:
                        if f.created_at:
                            f_dt = f.created_at if f.created_at.tzinfo else f.created_at.replace(tzinfo=timezone.utc)
                            if earliest_dt is None or f_dt < earliest_dt:
                                earliest_dt = f_dt
                    exposure_d = (
                        round(max(0.0, (now_utc - earliest_dt).total_seconds() / 86400.0), 1)
                        if earliest_dt
                        else None
                    )
                else:
                    posture_score = 100
                    last_scanned_at = None
                    trend = "new"
                    crits = 0
                    highs = 0
                    active_findings = []
                    exposure_d = None

                risk_index = max(0, min(100, 100 - posture_score))
                grade = map_score_to_grade(posture_score)

                items.append(
                    ProjectRiskRankingItem(
                        rank=0,  # will assign after sorting
                        project_id=proj.id,
                        project_name=proj.name,
                        target_url=proj.target_url,
                        posture_score=posture_score,
                        risk_index=risk_index,
                        grade=grade,
                        trend=trend,
                        critical_findings=crits,
                        high_findings=highs,
                        total_active_findings=len(active_findings),
                        last_scanned_at=last_scanned_at,
                        exposure_days=exposure_d,
                    )
                )

            # Sort descending by risk_index (highest risk first), then critical findings, then high findings
            items.sort(
                key=lambda x: (x.risk_index, x.critical_findings, x.high_findings, x.total_active_findings),
                reverse=True,
            )

            # Assign sequential ranks 1..N
            for i, itm in enumerate(items, start=1):
                itm.rank = i

            highest_risk_name = items[0].project_name if items and items[0].risk_index > 0 else None

            sanitized_limit = max(1, min(limit, 200))
            return ProjectRankingsResponse(
                total_projects=len(items),
                highest_risk_project=highest_risk_name,
                rankings=items[:sanitized_limit],
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to calculate project rankings: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve project risk rankings.",
            ) from exc
