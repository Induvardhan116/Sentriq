import io
import math
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class PurePDFDocument:
    """Standard-compliant pure-Python PDF 1.4 document builder.

    Zero third-party binary C dependencies. Generates valid PDF 1.4 files
    compatible with standard PDF viewers, mobile viewers, and automated parsers.
    """

    def __init__(self, title: str = "Sentriq Security Report"):
        self.title = title
        self.page_width = 612.0   # Letter width in points (8.5 inches)
        self.page_height = 792.0  # Letter height in points (11.0 inches)
        self.margin_x = 40.0
        self.margin_bottom = 50.0
        self.margin_top = 740.0
        self.y = self.margin_top

        self.pages_ops: List[List[str]] = [[]]
        self.current_page = 0

    def new_page(self):
        """Add a new page and reset the vertical drawing cursor."""
        self.pages_ops.append([])
        self.current_page += 1
        self.y = self.margin_top
        self._draw_page_decorations()

    def add_op(self, op: str):
        """Append a low-level PDF stream operator to the current page."""
        self.pages_ops[self.current_page].append(op)

    def set_fill_color(self, r: float, g: float, b: float):
        self.add_op(f"{r:.3f} {g:.3f} {b:.3f} rg")

    def set_stroke_color(self, r: float, g: float, b: float):
        self.add_op(f"{r:.3f} {g:.3f} {b:.3f} RG")

    def draw_rect(self, x: float, y: float, w: float, h: float, r=0.1, g=0.1, b=0.15, fill=True, stroke=False):
        self.set_fill_color(r, g, b)
        if stroke:
            self.set_stroke_color(r + 0.1, g + 0.1, b + 0.1)
            self.add_op(f"{x:.1f} {y:.1f} {w:.1f} {h:.1f} re B")
        else:
            self.add_op(f"{x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def draw_line(self, x1: float, y1: float, x2: float, y2: float, r=0.3, g=0.35, b=0.4, width=1.0):
        self.set_stroke_color(r, g, b)
        self.add_op(f"{width:.1f} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")

    def draw_text(
        self,
        text: str,
        x: float,
        y: float,
        font: str = "/F1",
        size: float = 10.0,
        r: float = 0.9,
        g: float = 0.9,
        b: float = 0.9,
    ):
        """Draw a single line of text with proper PDF string escaping."""
        if not text:
            return
        # Escape backslashes and parentheses
        safe_str = (
            text.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .encode("latin-1", "replace")
            .decode("latin-1")
        )
        self.set_fill_color(r, g, b)
        self.add_op(f"BT {font} {size:.1f} Tf {x:.1f} {y:.1f} Td ({safe_str}) Tj ET")

    def draw_badge(self, text: str, x: float, y: float, bg_r: float, bg_g: float, bg_b: float, fg_r=1.0, fg_g=1.0, fg_b=1.0, font_size=8.0):
        """Draw an enterprise severity chip/badge."""
        pad_x = 6.0
        text_w = len(text) * (font_size * 0.55)
        badge_w = text_w + (pad_x * 2)
        badge_h = font_size + 6.0
        self.draw_rect(x, y - 2, badge_w, badge_h, bg_r, bg_g, bg_b, fill=True)
        self.draw_text(text, x + pad_x, y + 2, font="/F2", size=font_size, r=fg_r, g=fg_g, b=fg_b)
        return badge_w

    def check_page_break(self, needed_height: float):
        """Automatically create a new page if the cursor is near the bottom."""
        if (self.y - needed_height) < self.margin_bottom:
            self.new_page()

    def _draw_page_decorations(self):
        """Draw common running header and footer on every page."""
        # Top banner line
        self.draw_rect(self.margin_x, 755, self.page_width - (self.margin_x * 2), 2, 0.02, 0.71, 0.83)
        self.draw_text("SENTRIQ APPLICATION SECURITY INTELLIGENCE", self.margin_x, 762, "/F2", 8, 0.02, 0.71, 0.83)
        self.draw_text(self.title.upper(), self.page_width - self.margin_x - (len(self.title) * 5), 762, "/F1", 8, 0.5, 0.55, 0.65)

        # Bottom footer line
        self.draw_rect(self.margin_x, 40, self.page_width - (self.margin_x * 2), 0.5, 0.2, 0.25, 0.3)
        self.draw_text("CONFIDENTIAL — AUTHORIZED CYBERSECURITY REPORT", self.margin_x, 28, "/F1", 7, 0.45, 0.5, 0.6)
        page_str = f"Page {self.current_page + 1}"
        self.draw_text(page_str, self.page_width - self.margin_x - 30, 28, "/F1", 7, 0.45, 0.5, 0.6)

    def build_pdf(self) -> bytes:
        """Compile internal drawing operations into standard-compliant PDF 1.4 binary stream."""
        # Decorate the first page headers/footers
        orig_page = self.current_page
        self.current_page = 0
        self._draw_page_decorations()
        self.current_page = orig_page

        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = {}

        num_pages = len(self.pages_ops)
        page_objs = []
        content_objs = []
        next_id = 6

        for _ in range(num_pages):
            page_objs.append(next_id)
            content_objs.append(next_id + 1)
            next_id += 2

        # 1. Catalog
        offsets[1] = out.tell()
        out.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # 2. Pages
        offsets[2] = out.tell()
        kids = " ".join(f"{pid} 0 R" for pid in page_objs)
        out.write(f"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {num_pages} >>\nendobj\n".encode("latin-1"))

        # 3. Font F1 (Helvetica Normal)
        offsets[3] = out.tell()
        out.write(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

        # 4. Font F2 (Helvetica-Bold)
        offsets[4] = out.tell()
        out.write(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

        # 5. Font F3 (Courier Monospace)
        offsets[5] = out.tell()
        out.write(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

        # Output Page & Content Objects
        for idx, (p_id, c_id) in enumerate(zip(page_objs, content_objs)):
            # Content Stream
            stream_body = "\n".join(self.pages_ops[idx]).encode("latin-1", "replace")
            offsets[c_id] = out.tell()
            out.write(f"{c_id} 0 obj\n<< /Length {len(stream_body)} >>\nstream\n".encode("latin-1"))
            out.write(stream_body)
            out.write(b"\nendstream\nendobj\n")

            # Page Object
            offsets[p_id] = out.tell()
            p_def = (
                f"{p_id} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.page_width:.0f} {self.page_height:.0f}] "
                f"/Contents {c_id} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>\nendobj\n"
            )
            out.write(p_def.encode("latin-1"))

        total_objs = next_id - 1
        xref_offset = out.tell()
        out.write(f"xref\n0 {total_objs + 1}\n".encode("latin-1"))
        out.write(b"0000000000 65535 f \n")
        for i in range(1, total_objs + 1):
            out.write(f"{offsets[i]:010d} 00000 n \n".encode("latin-1"))

        out.write(
            f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1")
        )
        return out.getvalue()


class SentriqPdfReportBuilder:
    """High-level builder transforming tenant security posture data into multi-page PDF reports."""

    @classmethod
    def generate_report(
        cls,
        data: Dict[str, Any],
        report_type: str = "executive",
    ) -> bytes:
        """Build and render an authentic downloadable PDF security report."""
        report_titles = {
            "executive": "Executive Cybersecurity Posture Report",
            "project": "Project & Web Application Security Report",
            "vulnerability": "Comprehensive Vulnerability Findings Catalog",
            "risk": "Risk Analytics & Posture Scoring Report",
            "repo": "Source Code & Repository Security (SAST/SCA) Report",
            "api": "API Security & OWASP Top 10 Assessment Report",
            "cloud": "Cloud Security Posture Management (CSPM) Report",
            "compliance": "Regulatory & Security Compliance Evidence Report",
        }

        title = report_titles.get(report_type.lower(), "Executive Cybersecurity Posture Report")
        doc = PurePDFDocument(title=title)

        posture = data.get("posture", {})
        assets = data.get("assets", {})
        summary = data.get("findings_summary", {})
        findings = data.get("findings", [])
        tenant_email = data.get("tenant_email", "admin@sentriq.io")
        generated_at = data.get("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

        # -------------------------------------------------------------
        # 1. Report Header Section
        # -------------------------------------------------------------
        doc.draw_rect(doc.margin_x, doc.y - 70, doc.page_width - (doc.margin_x * 2), 70, 0.06, 0.09, 0.16)
        doc.draw_text(title, doc.margin_x + 16, doc.y - 28, "/F2", 15, 1.0, 1.0, 1.0)
        doc.draw_text(
            f"Target Tenant: {tenant_email}  |  Generated: {generated_at}  |  Classification: STRICTLY CONFIDENTIAL",
            doc.margin_x + 16,
            doc.y - 50,
            "/F1",
            8,
            0.6,
            0.68,
            0.78,
        )
        doc.y -= 85

        # -------------------------------------------------------------
        # 2. Executive Posture & Score Cards
        # -------------------------------------------------------------
        score = posture.get("score", 100)
        risk = posture.get("risk_score", 0)
        grade = posture.get("grade", "A")

        card_w = (doc.page_width - (doc.margin_x * 2) - 30) / 4.0
        card_h = 58.0

        # Posture Score Card
        doc.draw_rect(doc.margin_x, doc.y - card_h, card_w, card_h, 0.08, 0.12, 0.2)
        doc.draw_text("POSTURE SCORE", doc.margin_x + 10, doc.y - 18, "/F2", 7, 0.02, 0.71, 0.83)
        doc.draw_text(f"{score}/100", doc.margin_x + 10, doc.y - 42, "/F2", 18, 1.0, 1.0, 1.0)

        # Risk Index Card
        x2 = doc.margin_x + card_w + 10
        doc.draw_rect(x2, doc.y - card_h, card_w, card_h, 0.08, 0.12, 0.2)
        doc.draw_text("RISK INDEX", x2 + 10, doc.y - 18, "/F2", 7, 0.9, 0.4, 0.4)
        doc.draw_text(f"{risk}/100", x2 + 10, doc.y - 42, "/F2", 18, 1.0, 1.0, 1.0)

        # Posture Grade Card
        x3 = x2 + card_w + 10
        doc.draw_rect(x3, doc.y - card_h, card_w, card_h, 0.08, 0.12, 0.2)
        doc.draw_text("POSTURE GRADE", x3 + 10, doc.y - 18, "/F2", 7, 0.2, 0.8, 0.5)
        doc.draw_text(f"Grade {grade}", x3 + 10, doc.y - 42, "/F2", 18, 0.2, 0.8, 0.5)

        # Monitored Assets Card
        x4 = x3 + card_w + 10
        doc.draw_rect(x4, doc.y - card_h, card_w, card_h, 0.08, 0.12, 0.2)
        doc.draw_text("MONITORED ASSETS", x4 + 10, doc.y - 18, "/F2", 7, 0.6, 0.7, 0.8)
        tot_assets = assets.get("total_monitored", 0)
        doc.draw_text(f"{tot_assets} Active", x4 + 10, doc.y - 42, "/F2", 16, 1.0, 1.0, 1.0)

        doc.y -= (card_h + 16)

        # -------------------------------------------------------------
        # 3. Severity Distribution Summary Bar
        # -------------------------------------------------------------
        doc.draw_rect(doc.margin_x, doc.y - 30, doc.page_width - (doc.margin_x * 2), 30, 0.05, 0.08, 0.13)
        doc.draw_text("FINDINGS DISTRIBUTION:", doc.margin_x + 12, doc.y - 19, "/F2", 8, 0.5, 0.58, 0.7)

        cur_x = doc.margin_x + 140
        crit_c = summary.get("critical", 0)
        high_c = summary.get("high", 0)
        med_c = summary.get("medium", 0)
        low_c = summary.get("low", 0)
        res_c = summary.get("resolved", 0)

        cur_x += doc.draw_badge(f"CRITICAL: {crit_c}", cur_x, doc.y - 23, 0.9, 0.15, 0.2, 1.0, 1.0, 1.0) + 8
        cur_x += doc.draw_badge(f"HIGH: {high_c}", cur_x, doc.y - 23, 0.95, 0.55, 0.1, 1.0, 1.0, 1.0) + 8
        cur_x += doc.draw_badge(f"MEDIUM: {med_c}", cur_x, doc.y - 23, 0.85, 0.7, 0.1, 0.1, 0.1, 0.1) + 8
        cur_x += doc.draw_badge(f"LOW: {low_c}", cur_x, doc.y - 23, 0.1, 0.6, 0.7, 1.0, 1.0, 1.0) + 8
        cur_x += doc.draw_badge(f"RESOLVED: {res_c}", cur_x, doc.y - 23, 0.15, 0.55, 0.35, 1.0, 1.0, 1.0)

        doc.y -= 44

        # -------------------------------------------------------------
        # 4. Scope & Methodology Statement
        # -------------------------------------------------------------
        doc.draw_rect(doc.margin_x, doc.y - 42, doc.page_width - (doc.margin_x * 2), 42, 0.04, 0.06, 0.1, fill=True)
        doc.draw_text("ASSESSMENT SCOPE & METHODOLOGY", doc.margin_x + 10, doc.y - 14, "/F2", 8, 0.02, 0.71, 0.83)
        doc.draw_text(
            "This report consolidates automated, defensive application security assessments, repository SAST/SCA inspection, OpenAPI audits,",
            doc.margin_x + 10,
            doc.y - 26,
            "/F1",
            7.5,
            0.7,
            0.75,
            0.85,
        )
        doc.draw_text(
            "and CIS Cloud benchmark reviews. All tests adhere strictly to safe, authorized, non-intrusive security standards.",
            doc.margin_x + 10,
            doc.y - 36,
            "/F1",
            7.5,
            0.7,
            0.75,
            0.85,
        )
        doc.y -= 54

        # -------------------------------------------------------------
        # 5. Filter Findings by Report Type if specific
        # -------------------------------------------------------------
        type_filtered = findings
        if report_type == "project":
            type_filtered = [f for f in findings if "Website" in f.get("source", "")]
        elif report_type == "repo":
            type_filtered = [f for f in findings if "Repo" in f.get("source", "")]
        elif report_type == "api":
            type_filtered = [f for f in findings if "API" in f.get("source", "")]
        elif report_type == "cloud":
            type_filtered = [f for f in findings if "Cloud" in f.get("source", "")]

        # -------------------------------------------------------------
        # 6. Detailed Findings Table
        # -------------------------------------------------------------
        doc.check_page_break(100)
        doc.draw_text(
            f"VULNERABILITY FINDINGS CATALOG ({len(type_filtered)} Items Recorded)",
            doc.margin_x,
            doc.y,
            "/F2",
            10,
            1.0,
            1.0,
            1.0,
        )
        doc.y -= 14

        # Table Header
        col_x = [doc.margin_x, doc.margin_x + 65, doc.margin_x + 145, doc.margin_x + 360, doc.margin_x + 440]
        header_h = 18.0
        doc.draw_rect(doc.margin_x, doc.y - header_h, doc.page_width - (doc.margin_x * 2), header_h, 0.1, 0.15, 0.22)
        doc.draw_text("SEVERITY", col_x[0] + 6, doc.y - 12, "/F2", 7.5, 0.8, 0.85, 0.9)
        doc.draw_text("SOURCE", col_x[1] + 6, doc.y - 12, "/F2", 7.5, 0.8, 0.85, 0.9)
        doc.draw_text("VULNERABILITY TITLE & ASSET", col_x[2] + 6, doc.y - 12, "/F2", 7.5, 0.8, 0.85, 0.9)
        doc.draw_text("CATEGORY", col_x[3] + 6, doc.y - 12, "/F2", 7.5, 0.8, 0.85, 0.9)
        doc.draw_text("STATUS / SCORE", col_x[4] + 6, doc.y - 12, "/F2", 7.5, 0.8, 0.85, 0.9)
        doc.y -= header_h

        if not type_filtered:
            doc.draw_rect(doc.margin_x, doc.y - 30, doc.page_width - (doc.margin_x * 2), 30, 0.05, 0.07, 0.1)
            doc.draw_text(
                "No open security findings discovered within this scope. All security controls conform to baseline.",
                doc.margin_x + 16,
                doc.y - 19,
                "/F1",
                8,
                0.3,
                0.8,
                0.5,
            )
            doc.y -= 36
        else:
            for idx, f in enumerate(type_filtered):
                doc.check_page_break(46)
                row_h = 38.0
                bg = (0.04, 0.06, 0.09) if idx % 2 == 0 else (0.06, 0.08, 0.13)
                doc.draw_rect(doc.margin_x, doc.y - row_h, doc.page_width - (doc.margin_x * 2), row_h, *bg)

                # Severity badge
                sev = f.get("severity", "medium").upper()
                sev_color = (
                    (0.9, 0.15, 0.2) if sev == "CRITICAL"
                    else (0.95, 0.55, 0.1) if sev == "HIGH"
                    else (0.85, 0.7, 0.1) if sev == "MEDIUM"
                    else (0.1, 0.6, 0.7)
                )
                doc.draw_badge(sev[:4], col_x[0] + 6, doc.y - 18, *sev_color, font_size=7)

                # Source
                doc.draw_text(f.get("source", "Web")[:12], col_x[1] + 6, doc.y - 16, "/F1", 7.5, 0.7, 0.75, 0.85)

                # Title and Asset
                title_txt = f.get("title", "Untitled finding")[:42]
                asset_txt = f.get("asset_name", "Perimeter")[:42]
                doc.draw_text(title_txt, col_x[2] + 6, doc.y - 14, "/F2", 8, 0.95, 0.95, 0.95)
                doc.draw_text(f"Asset: {asset_txt}", col_x[2] + 6, doc.y - 26, "/F1", 7, 0.55, 0.6, 0.7)

                # Category
                cat_txt = f.get("category", "General")[:15]
                doc.draw_text(cat_txt, col_x[3] + 6, doc.y - 16, "/F1", 7.5, 0.65, 0.7, 0.8)

                # Status / Risk Score
                st_txt = f.get("status", "open").upper()
                r_score = f.get("risk_score", 0)
                doc.draw_text(f"{st_txt} ({r_score} pts)", col_x[4] + 6, doc.y - 16, "/F2", 7.5, 0.8, 0.85, 0.9)

                doc.y -= row_h

        # -------------------------------------------------------------
        # 7. Compliance Framework Mapping Matrix
        # -------------------------------------------------------------
        doc.check_page_break(110)
        doc.y -= 14
        doc.draw_text("COMPLIANCE & REGULATORY FRAMEWORK MAPPING", doc.margin_x, doc.y, "/F2", 10, 1.0, 1.0, 1.0)
        doc.y -= 14

        comp_h = 60.0
        doc.draw_rect(doc.margin_x, doc.y - comp_h, doc.page_width - (doc.margin_x * 2), comp_h, 0.05, 0.08, 0.13)
        doc.draw_text("Framework Alignment", doc.margin_x + 12, doc.y - 16, "/F2", 8.5, 0.02, 0.71, 0.83)

        doc.draw_text("• OWASP Top 10 Web 2021: A01 Broken Access Control, A02 Crypto Failures, A05 Misconfigurations (Audited)", doc.margin_x + 12, doc.y - 30, "/F1", 7.5, 0.75, 0.8, 0.9)
        doc.draw_text("• OWASP API Security 2023: API1 Object Authorization, API3 Excessive Data, API8 Misconfigurations (Audited)", doc.margin_x + 12, doc.y - 42, "/F1", 7.5, 0.75, 0.8, 0.9)
        doc.draw_text("• CIS Cloud Benchmarks: CIS Storage Controls, Root IAM Enforcement, Ingress Port Restrictions (Audited)", doc.margin_x + 12, doc.y - 54, "/F1", 7.5, 0.75, 0.8, 0.9)
        doc.y -= (comp_h + 20)

        return doc.build_pdf()
