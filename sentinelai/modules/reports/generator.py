"""
PDF Report Generator for SentinelAI.
Replaces the placeholder in mitigation/engine.py with a working implementation.
Add this as sentinelai/modules/reports/generator.py
"""
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
import structlog

log = structlog.get_logger()


class ReportGenerator:
    """
    Generates professional PDF security reports using ReportLab.
    Called after any scan or correlation analysis completes.
    """

    def __init__(self):
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)

    async def generate_pdf(
        self,
        scan_data: dict,
        llm_analysis: str,
        findings: list = None,
        report_type: str = "log_analysis"
    ) -> str:
        """
        Generate a PDF report and return the file path.

        Args:
            scan_data: Scan metadata (target, dates, counts)
            llm_analysis: Full LLM analysis text
            findings: List of individual findings
            report_type: "log_analysis" or "correlation"

        Returns:
            Path to generated PDF file
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor, white, black
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer,
                HRFlowable, Table, TableStyle, PageBreak
            )
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            # File path
            timestamp  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            scan_id    = scan_data.get("id", str(uuid.uuid4()))[:8]
            filename   = f"sentinelai_report_{scan_id}_{timestamp}.pdf"
            filepath   = str(self.output_dir / filename)

            # Colours
            NAVY     = HexColor("#1F4E79")
            BLUE     = HexColor("#2E75B6")
            RED      = HexColor("#E24B4A")
            ORANGE   = HexColor("#F59E0B")
            GREEN    = HexColor("#10B981")
            GRAY     = HexColor("#444444")
            LIGHTGRAY = HexColor("#F5F5F5")
            DARKBG   = HexColor("#0A0A12")

            doc = SimpleDocTemplate(
                filepath,
                pagesize=letter,
                rightMargin=0.75*inch,
                leftMargin=0.75*inch,
                topMargin=0.75*inch,
                bottomMargin=0.75*inch
            )

            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle("ReportTitle",
                fontSize=22, textColor=NAVY, fontName="Helvetica-Bold",
                spaceAfter=6, alignment=TA_CENTER)
            subtitle_style = ParagraphStyle("Subtitle",
                fontSize=11, textColor=GRAY, fontName="Helvetica",
                spaceAfter=4, alignment=TA_CENTER)
            h1_style = ParagraphStyle("H1",
                fontSize=14, textColor=NAVY, fontName="Helvetica-Bold",
                spaceBefore=16, spaceAfter=6)
            h2_style = ParagraphStyle("H2",
                fontSize=12, textColor=BLUE, fontName="Helvetica-Bold",
                spaceBefore=10, spaceAfter=4)
            body_style = ParagraphStyle("Body",
                fontSize=9, textColor=GRAY, fontName="Helvetica",
                spaceAfter=4, leading=14)
            mono_style = ParagraphStyle("Mono",
                fontSize=8, textColor=HexColor("#1A1A2E"), fontName="Courier",
                spaceAfter=3, leading=12,
                backColor=HexColor("#F0F4F8"), leftIndent=8, rightIndent=8,
                borderPadding=6)
            label_style = ParagraphStyle("Label",
                fontSize=8, textColor=HexColor("#888888"), fontName="Helvetica",
                spaceAfter=2, spaceBefore=6)

            def hr(color=NAVY, thickness=1):
                return HRFlowable(width="100%", thickness=thickness,
                                  color=color, spaceAfter=6, spaceBefore=6)

            def sev_color(sev):
                return {
                    "critical": RED, "high": ORANGE,
                    "medium": BLUE, "low": GRAY
                }.get(str(sev).lower(), GRAY)

            story = []

            # ── Cover ─────────────────────────────────────────────────────
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph("🛡 SentinelAI", title_style))
            story.append(Paragraph("Security Assessment Report", subtitle_style))
            story.append(Spacer(1, 0.1*inch))
            story.append(hr(NAVY, 2))

            # Meta table
            target     = scan_data.get("target", "Unknown")
            created    = scan_data.get("created_at", datetime.utcnow().isoformat())
            findings_c = scan_data.get("finding_count", 0)
            critical_c = scan_data.get("critical_count", 0)
            high_c     = scan_data.get("high_count", 0)

            meta_data = [
                ["Target / Log source", str(target)[:80]],
                ["Report type", report_type.replace("_"," ").title()],
                ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
                ["Scan ID", scan_data.get("id","N/A")],
                ["Total findings", str(findings_c)],
                ["Critical", str(critical_c)],
            ]
            meta_table = Table(meta_data, colWidths=[2*inch, 4.5*inch])
            meta_table.setStyle(TableStyle([
                ("FONTNAME",  (0,0),(-1,-1), "Helvetica"),
                ("FONTSIZE",  (0,0),(-1,-1), 9),
                ("FONTNAME",  (0,0),(0,-1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0,0),(0,-1), NAVY),
                ("BACKGROUND",(0,0),(-1,-1), LIGHTGRAY),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[white, LIGHTGRAY]),
                ("GRID",      (0,0),(-1,-1), 0.5, HexColor("#DDDDDD")),
                ("PADDING",   (0,0),(-1,-1), 6),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 0.15*inch))

            # ── Risk summary ───────────────────────────────────────────────
            overall_risk = "CRITICAL" if critical_c > 0 else "HIGH" if high_c > 0 else "MEDIUM" if findings_c > 0 else "LOW"
            risk_color = {"CRITICAL":RED, "HIGH":ORANGE, "MEDIUM":BLUE, "LOW":GREEN}.get(overall_risk, GRAY)

            risk_data = [["Overall Risk Rating", overall_risk, f"{findings_c} findings ({critical_c} critical)"]]
            risk_table = Table(risk_data, colWidths=[2*inch, 1.5*inch, 3*inch])
            risk_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,-1), DARKBG),
                ("TEXTCOLOR",  (0,0),(0,0),  white),
                ("TEXTCOLOR",  (1,0),(1,0),  risk_color),
                ("TEXTCOLOR",  (2,0),(2,0),  HexColor("#AAAACC")),
                ("FONTNAME",   (0,0),(-1,-1),"Helvetica-Bold"),
                ("FONTSIZE",   (0,0),(-1,-1), 10),
                ("PADDING",    (0,0),(-1,-1), 10),
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 0.2*inch))

            story.append(Paragraph(
                "⚠ CONFIDENTIAL — This report contains sensitive security information. "
                "Distribution should be limited to authorized personnel only.",
                ParagraphStyle("Warning", fontSize=8, textColor=RED,
                               fontName="Helvetica-Bold", spaceAfter=8,
                               borderColor=RED, borderWidth=0.5, borderPadding=6,
                               backColor=HexColor("#FFF0F0"))
            ))

            # ── Findings ───────────────────────────────────────────────────
            if findings:
                story.append(PageBreak())
                story.append(Paragraph("Security Findings", h1_style))
                story.append(hr())

                for i, f in enumerate(findings[:30], 1):
                    sev   = str(f.get("severity","info")).upper()
                    color = sev_color(f.get("severity","info"))
                    story.append(Paragraph(
                        f"{i}. {f.get('title','Untitled Finding')}", h2_style))

                    sev_data = [["Severity", sev,
                                 f.get("cve_id","") or "",
                                 f"CVSS: {f.get('cvss_score','N/A')}"]]
                    sev_tbl  = Table(sev_data, colWidths=[0.8*inch,0.8*inch,1.5*inch,1.5*inch])
                    sev_tbl.setStyle(TableStyle([
                        ("BACKGROUND",(1,0),(1,0), color),
                        ("TEXTCOLOR", (1,0),(1,0), white),
                        ("TEXTCOLOR", (0,0),(0,0), NAVY),
                        ("FONTNAME",  (0,0),(-1,-1),"Helvetica-Bold"),
                        ("FONTSIZE",  (0,0),(-1,-1), 8),
                        ("PADDING",   (0,0),(-1,-1), 4),
                        ("GRID",      (0,0),(-1,-1),0.3, HexColor("#DDDDDD")),
                    ]))
                    story.append(sev_tbl)

                    if f.get("description"):
                        story.append(Paragraph(str(f["description"])[:300], body_style))
                    if f.get("mitre_attack"):
                        story.append(Paragraph(f"MITRE ATT&amp;CK: {f['mitre_attack']}", label_style))
                    if f.get("remediation"):
                        story.append(Paragraph(f"<b>Remediation:</b> {str(f['remediation'])[:200]}", body_style))
                    story.append(hr(HexColor("#EEEEEE"), 0.5))

            # ── LLM Analysis ───────────────────────────────────────────────
            if llm_analysis:
                story.append(PageBreak())
                story.append(Paragraph("AI Security Analysis", h1_style))
                story.append(hr())
                story.append(Paragraph(
                    "The following analysis was generated by Claude (Anthropic) based on "
                    "the security events detected in the submitted log data.",
                    ParagraphStyle("Note", fontSize=8, textColor=GRAY,
                                   fontName="Helvetica-Oblique", spaceAfter=10)
                ))

                # Split analysis into sections
                current_section = []
                for line in llm_analysis.split("\n"):
                    line = line.strip()
                    if not line:
                        if current_section:
                            story.append(Paragraph(" ".join(current_section), body_style))
                            current_section = []
                        story.append(Spacer(1, 0.05*inch))
                    elif line.startswith("###"):
                        if current_section:
                            story.append(Paragraph(" ".join(current_section), body_style))
                            current_section = []
                        story.append(Paragraph(line.lstrip("#").strip(), h2_style))
                    elif line.startswith("##"):
                        if current_section:
                            story.append(Paragraph(" ".join(current_section), body_style))
                            current_section = []
                        story.append(Paragraph(line.lstrip("#").strip(), h1_style))
                        story.append(hr(BLUE, 0.5))
                    elif line.startswith("|"):
                        # Table row — render as mono
                        if current_section:
                            story.append(Paragraph(" ".join(current_section), body_style))
                            current_section = []
                        clean = line.replace("|","  ").replace("---","").strip()
                        if clean:
                            story.append(Paragraph(clean, mono_style))
                    elif line.startswith("-") or line.startswith("•") or line.startswith("*"):
                        if current_section:
                            story.append(Paragraph(" ".join(current_section), body_style))
                            current_section = []
                        bullet_text = line.lstrip("-•* ").strip()
                        if bullet_text:
                            story.append(Paragraph(
                                f"• {bullet_text}",
                                ParagraphStyle("Bullet", fontSize=9, textColor=GRAY,
                                               fontName="Helvetica", leftIndent=16,
                                               spaceAfter=3, leading=13)
                            ))
                    else:
                        current_section.append(line)

                if current_section:
                    story.append(Paragraph(" ".join(current_section), body_style))

            # ── Footer ─────────────────────────────────────────────────────
            story.append(Spacer(1, 0.3*inch))
            story.append(hr(NAVY))
            story.append(Paragraph(
                f"Generated by SentinelAI v2.0.0 · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
                "For authorized security testing only.",
                ParagraphStyle("Footer", fontSize=7, textColor=HexColor("#AAAAAA"),
                               fontName="Helvetica", alignment=TA_CENTER)
            ))

            doc.build(story)
            log.info("PDF report generated", path=filepath)
            return filepath

        except ImportError:
            log.error("ReportLab not installed — run: pip install reportlab")
            raise
        except Exception as e:
            log.error("PDF generation failed", error=str(e))
            raise
