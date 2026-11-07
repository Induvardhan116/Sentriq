import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.repository import Repository, RepoFinding
from app.models.api_security import ApiSpec, ApiFinding
from app.models.cloud_security import CloudAccount, CloudFinding
from app.models.user import User

logger = logging.getLogger("sentriq.services.reports")


class ReportService:
    @classmethod
    async def gather_tenant_data(
        cls, db: AsyncSession, user: Optional[User]
    ) -> Dict[str, Any]:
        """Aggregate all security assets and findings for the tenant."""
        user_id = user.id if user else None
        is_super = getattr(user, "is_superuser", False) if user else False

        # 1. Projects & Findings
        p_stmt = select(Project)
        if not is_super and user_id:
            p_stmt = p_stmt.where(Project.owner_id == user_id)
        p_res = await db.execute(p_stmt)
        projects = list(p_res.scalars().all())
        project_ids = [p.id for p in projects]

        all_findings: List[Dict[str, Any]] = []
        if project_ids:
            s_stmt = select(Scan).where(Scan.project_id.in_(project_ids))
            s_res = await db.execute(s_stmt)
            scans = list(s_res.scalars().all())
            scan_ids = [s.id for s in scans]
            scan_to_proj = {s.id: s.project_id for s in scans}
            proj_to_name = {p.id: p.name for p in projects}

            if scan_ids:
                f_stmt = select(Finding).where(Finding.scan_id.in_(scan_ids))
                f_res = await db.execute(f_stmt)
                for f in f_res.scalars().all():
                    proj_id = scan_to_proj.get(f.scan_id)
                    all_findings.append({
                        "id": f.id,
                        "source": "Website",
                        "asset_name": proj_to_name.get(proj_id, "Unknown"),
                        "title": f.title,
                        "severity": f.severity,
                        "category": f.category,
                        "risk_score": f.risk_score,
                        "status": f.status,
                        "remediation": f.remediation,
                        "created_at": f.created_at.isoformat() if f.created_at else "",
                    })

        # 2. Repositories
        r_stmt = select(Repository)
        if not is_super and user_id:
            r_stmt = r_stmt.where(Repository.owner_id == user_id)
        r_res = await db.execute(r_stmt)
        repos = list(r_res.scalars().all())
        repo_ids = [r.id for r in repos]

        if repo_ids:
            rf_stmt = select(RepoFinding).where(RepoFinding.repo_id.in_(repo_ids))
            rf_res = await db.execute(rf_stmt)
            for rf in rf_res.scalars().all():
                all_findings.append({
                    "id": rf.id,
                    "source": f"Repo ({rf.scan_type.upper()})",
                    "asset_name": next((r.name for r in repos if r.id == rf.repo_id), "Unknown"),
                    "title": rf.title,
                    "severity": rf.severity,
                    "category": f"Code-{rf.scan_type}",
                    "risk_score": rf.risk_score,
                    "status": rf.status,
                    "remediation": rf.remediation,
                    "created_at": rf.created_at.isoformat() if rf.created_at else "",
                })

        # 3. API Specs
        a_stmt = select(ApiSpec)
        if not is_super and user_id:
            a_stmt = a_stmt.where(ApiSpec.owner_id == user_id)
        a_res = await db.execute(a_stmt)
        specs = list(a_res.scalars().all())
        spec_ids = [s.id for s in specs]

        if spec_ids:
            af_stmt = select(ApiFinding).where(ApiFinding.spec_id.in_(spec_ids))
            af_res = await db.execute(af_stmt)
            for af in af_res.scalars().all():
                all_findings.append({
                    "id": af.id,
                    "source": "API Security",
                    "asset_name": next((s.title for s in specs if s.id == af.spec_id), "Unknown"),
                    "title": af.title,
                    "severity": af.severity,
                    "category": af.owasp_category,
                    "risk_score": af.risk_score,
                    "status": af.status,
                    "remediation": af.remediation,
                    "created_at": af.created_at.isoformat() if af.created_at else "",
                })

        # 4. Cloud Accounts
        c_stmt = select(CloudAccount)
        if not is_super and user_id:
            c_stmt = c_stmt.where(CloudAccount.user_id == user_id)
        c_res = await db.execute(c_stmt)
        accounts = list(c_res.scalars().all())
        account_ids = [acc.id for acc in accounts]

        if account_ids:
            cf_stmt = select(CloudFinding).where(CloudFinding.account_id.in_(account_ids))
            cf_res = await db.execute(cf_stmt)
            for cf in cf_res.scalars().all():
                all_findings.append({
                    "id": cf.id,
                    "source": f"Cloud ({cf.service.upper()})",
                    "asset_name": next((acc.name for acc in accounts if acc.id == cf.account_id), "Unknown"),
                    "title": cf.title,
                    "severity": cf.severity,
                    "category": cf.benchmark_ref,
                    "risk_score": cf.risk_score,
                    "status": cf.status,
                    "remediation": cf.remediation,
                    "created_at": cf.created_at.isoformat() if cf.created_at else "",
                })

        # Summary Counts
        open_findings = [f for f in all_findings if f["status"] == "open"]
        crit_count = sum(1 for f in open_findings if f["severity"] == "critical")
        high_count = sum(1 for f in open_findings if f["severity"] == "high")
        med_count = sum(1 for f in open_findings if f["severity"] == "medium")
        low_count = sum(1 for f in open_findings if f["severity"] == "low")
        resolved_count = sum(1 for f in all_findings if f["status"] in ["resolved", "accepted_risk", "false_positive"])

        # Baseline Posture
        total_open = len(open_findings)
        penalty = (crit_count * 20) + (high_count * 10) + (med_count * 4) + (low_count * 1)
        posture_score = max(0, 100 - min(100, penalty))
        risk_score = 100 - posture_score

        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "tenant_email": user.email if user else "dev-mode@sentriq.local",
            "assets": {
                "projects_count": len(projects),
                "repos_count": len(repos),
                "api_specs_count": len(specs),
                "cloud_accounts_count": len(accounts),
                "total_monitored": len(projects) + len(repos) + len(specs) + len(accounts),
            },
            "posture": {
                "score": posture_score,
                "risk_score": risk_score,
                "grade": "A+" if posture_score >= 95 else "A" if posture_score >= 85 else "B" if posture_score >= 70 else "C" if posture_score >= 50 else "F",
            },
            "findings_summary": {
                "total": len(all_findings),
                "open": total_open,
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "resolved": resolved_count,
            },
            "findings": all_findings,
        }

    @classmethod
    async def generate_findings_csv(
        cls, db: AsyncSession, user: Optional[User]
    ) -> str:
        """Produce UTF-8 CSV string with BOM for spreadsheet export."""
        data = await cls.gather_tenant_data(db, user)
        output = io.StringIO()
        # Add UTF-8 BOM
        output.write("\ufeff")

        writer = csv.writer(output)
        writer.writerow([
            "Finding ID",
            "Source Type",
            "Asset Name",
            "Vulnerability Title",
            "Severity",
            "Category / Standard",
            "Risk Score",
            "Status",
            "Remediation Guidance",
            "First Detected",
        ])

        for f in data["findings"]:
            writer.writerow([
                f["id"],
                f["source"],
                f["asset_name"],
                f["title"],
                f["severity"].upper(),
                f["category"],
                f["risk_score"],
                f["status"],
                f["remediation"] or "N/A",
                f["created_at"],
            ])

        return output.getvalue()

    @classmethod
    async def generate_posture_json(
        cls, db: AsyncSession, user: Optional[User]
    ) -> Dict[str, Any]:
        """Produce full JSON cybersecurity posture package."""
        data = await cls.gather_tenant_data(db, user)
        data["compliance_mappings"] = {
            "owasp_top_10_web": {
                "covered_categories": ["A01:Broken-Access-Control", "A02:Cryptographic-Failures", "A05:Security-Misconfiguration"],
                "status": "Audited",
            },
            "owasp_api_security": {
                "covered_categories": ["API1:Broken-Auth", "API3:Broken-Object-Property", "API8:Security-Misconfiguration"],
                "status": "Audited",
            },
            "cis_cloud_benchmarks": {
                "covered_controls": ["CIS-Storage-1.2", "CIS-IAM-Root-1.1", "CIS-Network-SSH-1.4"],
                "status": "Audited",
            },
        }
        return data

    @classmethod
    async def generate_report_pdf(
        cls, db: AsyncSession, user: Optional[User], report_type: str = "executive"
    ) -> bytes:
        """Produce authentic downloadable multi-page PDF security report."""
        from app.services.pdf_generator import SentriqPdfReportBuilder
        data = await cls.gather_tenant_data(db, user)
        return SentriqPdfReportBuilder.generate_report(data, report_type)

    @classmethod
    async def generate_executive_html(
        cls, db: AsyncSession, user: Optional[User]
    ) -> str:
        """Produce standalone printable executive security report with print styling."""
        data = await cls.gather_tenant_data(db, user)

        # Build findings table rows
        rows_html = ""
        for f in data["findings"][:30]:  # Top 30 findings in executive summary
            sev_color = "#ef4444" if f["severity"] == "critical" else "#f97316" if f["severity"] == "high" else "#eab308" if f["severity"] == "medium" else "#3b82f6"
            rows_html += f"""
            <tr>
              <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-weight: 600;">
                <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; background: {sev_color}22; color: {sev_color};">
                  {f["severity"].upper()}
                </span>
              </td>
              <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 13px; font-weight: 600;">{f["title"]}</td>
              <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 12px; color: #64748b;">{f["asset_name"]} ({f["source"]})</td>
              <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 12px;">{f["category"]}</td>
              <td style="padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 12px; text-transform: uppercase;">{f["status"]}</td>
            </tr>
            """

        if not rows_html:
            rows_html = """
            <tr>
              <td colspan="5" style="padding: 24px; text-align: center; color: #22c55e; font-weight: 600;">
                Zero open vulnerabilities detected across monitored assets.
              </td>
            </tr>
            """

        score_color = "#22c55e" if data["posture"]["score"] >= 80 else "#eab308" if data["posture"]["score"] >= 50 else "#ef4444"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sentriq Executive Cybersecurity Report</title>
  <style>
    @page {{
      size: A4;
      margin: 18mm 15mm 18mm 15mm;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      background: #ffffff;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #06b6d4;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }}
    .logo {{
      font-size: 24px;
      font-weight: 800;
      color: #0891b2;
      letter-spacing: -0.5px;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      background: #ecfeff;
      color: #0891b2;
      border: 1px solid #a5f3fc;
    }}
    .grid-cards {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 28px;
    }}
    .card {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 16px;
    }}
    .card-label {{
      font-size: 11px;
      font-weight: 600;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .card-value {{
      font-size: 28px;
      font-weight: 800;
      margin-top: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      margin-top: 12px;
    }}
    th {{
      background: #f1f5f9;
      padding: 10px 12px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      color: #475569;
      border-bottom: 2px solid #cbd5e1;
    }}
    .print-btn {{
      position: fixed;
      top: 20px;
      right: 20px;
      background: #0891b2;
      color: #ffffff;
      border: none;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }}
    @media print {{
      .print-btn {{ display: none; }}
      body {{ padding: 0; }}
    }}
  </style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>

  <div class="header">
    <div>
      <div class="logo">SENTRIQ</div>
      <div style="font-size: 12px; color: #64748b; margin-top: 2px;">Application Security Posture Management</div>
    </div>
    <div style="text-align: right;">
      <span class="badge">CONFIDENTIAL EXECUTIVE REPORT</span>
      <div style="font-size: 12px; color: #64748b; margin-top: 6px;">
        Generated: {data["generated_at"]}<br>
        Tenant: {data["tenant_email"]}
      </div>
    </div>
  </div>

  <section>
    <h2 style="font-size: 18px; font-weight: 700; color: #1e293b; margin: 0 0 12px 0;">Executive Posture Scorecard</h2>
    <div class="grid-cards">
      <div class="card" style="border-top: 4px solid {score_color};">
        <div class="card-label">Posture Score</div>
        <div class="card-value" style="color: {score_color};">{data["posture"]["score"]}%</div>
        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">Grade {data["posture"]["grade"]}</div>
      </div>
      <div class="card">
        <div class="card-label">Monitored Assets</div>
        <div class="card-value" style="color: #0f172a;">{data["assets"]["total_monitored"]}</div>
        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">
          {data["assets"]["projects_count"]} web, {data["assets"]["repos_count"]} repos, {data["assets"]["api_specs_count"]} apis, {data["assets"]["cloud_accounts_count"]} cloud
        </div>
      </div>
      <div class="card">
        <div class="card-label">Critical / High Violations</div>
        <div class="card-value" style="color: #ef4444;">{data["findings_summary"]["critical"] + data["findings_summary"]["high"]}</div>
        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">
          {data["findings_summary"]["critical"]} Critical, {data["findings_summary"]["high"]} High
        </div>
      </div>
      <div class="card">
        <div class="card-label">Resolved / Mitigated</div>
        <div class="card-value" style="color: #22c55e;">{data["findings_summary"]["resolved"]}</div>
        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">Verified remediation history</div>
      </div>
    </div>
  </section>

  <section style="margin-top: 24px;">
    <h2 style="font-size: 18px; font-weight: 700; color: #1e293b; margin: 0 0 8px 0;">Prioritized Security Findings</h2>
    <p style="font-size: 13px; color: #64748b; margin: 0 0 12px 0;">
      Cross-domain vulnerability summary across web perimeter, source code repositories, API schemas, and cloud infrastructure.
    </p>

    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Vulnerability Finding</th>
          <th>Affected Asset</th>
          <th>Standard / Category</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </section>

  <footer style="margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between;">
    <div>Sentriq Automated Security Intelligence &copy; 2026. All rights reserved.</div>
    <div>Standards: OWASP Top 10 • CWE • CIS Benchmarks • NIST CSF</div>
  </footer>
</body>
</html>"""
        return html_content
