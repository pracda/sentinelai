"""
Executive PDF Report Generator for SentinelAI.
Produces a polished, multi-section security report using ReportLab.
"""
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
import structlog

log = structlog.get_logger()


class ReportGenerator:
    def __init__(self):
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)

    async def generate_pdf(
        self,
        scan_data: dict,
        llm_analysis: str,
        findings: list = None,
        report_type: str = "log_analysis",
        iocs: dict = None,
    ) -> str:
        findings = findings or []
        iocs = iocs or {}

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor, white, black, Color
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer,
                HRFlowable, Table, TableStyle, PageBreak, KeepTogether
            )
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            from reportlab.pdfgen import canvas as pdfcanvas

            W, H = letter

            # ── Colour palette ─────────────────────────────────────────────
            NAVY      = HexColor("#1A2744")
            BLUE      = HexColor("#2563EB")
            RED       = HexColor("#DC2626")
            ORANGE    = HexColor("#D97706")
            YELLOW    = HexColor("#CA8A04")
            GREEN     = HexColor("#059669")
            GRAY      = HexColor("#374151")
            GRAY2     = HexColor("#6B7280")
            LIGHTGRAY = HexColor("#F9FAFB")
            BORDER    = HexColor("#E5E7EB")
            ACCENT    = HexColor("#6C63FF")
            RED_BG    = HexColor("#FEF2F2")
            ORG_BG    = HexColor("#FFFBEB")

            def sev_color(sev: str):
                return {"critical": RED, "high": ORANGE, "medium": YELLOW,
                        "low": GREEN, "info": GRAY2}.get(str(sev).lower(), GRAY2)

            def sev_bg(sev: str):
                return {"critical": RED_BG, "high": ORG_BG,
                        "medium": HexColor("#FEFCE8"),
                        "low": HexColor("#F0FDF4"),
                        "info": LIGHTGRAY}.get(str(sev).lower(), LIGHTGRAY)

            # ── File path ──────────────────────────────────────────────────
            ts      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            scan_id = scan_data.get("id", str(uuid.uuid4()))[:8]
            fp      = str(self.output_dir / f"sentinelai_report_{scan_id}_{ts}.pdf")

            # ── Page header/footer callbacks ───────────────────────────────
            target_label = str(scan_data.get("target", "Unknown"))[:60]

            def _on_page(canvas, doc):
                canvas.saveState()
                # top rule + text
                canvas.setStrokeColor(NAVY)
                canvas.setLineWidth(0.5)
                canvas.line(0.65*inch, H - 0.52*inch, W - 0.65*inch, H - 0.52*inch)
                canvas.setFont("Helvetica", 7)
                canvas.setFillColor(NAVY)
                canvas.drawString(0.65*inch, H - 0.44*inch, "SentinelAI — Security Assessment Report  |  CONFIDENTIAL")
                canvas.setFillColor(GRAY2)
                canvas.drawRightString(W - 0.65*inch, H - 0.44*inch, target_label)
                # bottom rule + page number
                canvas.setStrokeColor(BORDER)
                canvas.line(0.65*inch, 0.55*inch, W - 0.65*inch, 0.55*inch)
                canvas.setFont("Helvetica", 7)
                canvas.setFillColor(GRAY2)
                canvas.drawCentredString(W / 2, 0.38*inch, f"Page {doc.page}")
                canvas.restoreState()

            def _on_cover(canvas, doc):
                canvas.saveState()
                # dark band — full top 3.1 inches
                canvas.setFillColor(NAVY)
                canvas.rect(0, H - 3.1*inch, W, 3.1*inch, fill=1, stroke=0)
                # accent rule inside band
                canvas.setStrokeColor(ACCENT)
                canvas.setLineWidth(1.5)
                canvas.line(1.5*inch, H - 2.55*inch, W - 1.5*inch, H - 2.55*inch)
                # title
                canvas.setFillColor(white)
                canvas.setFont("Helvetica-Bold", 30)
                canvas.drawCentredString(W / 2, H - 1.45*inch, "SENTINELAI")
                # subtitle
                canvas.setFillColor(HexColor("#A5B4FC"))
                canvas.setFont("Helvetica", 13)
                canvas.drawCentredString(W / 2, H - 2.05*inch, "Security Assessment Report")
                canvas.restoreState()

            # ── Document ───────────────────────────────────────────────────
            doc = SimpleDocTemplate(
                fp,
                pagesize=letter,
                rightMargin=0.75*inch, leftMargin=0.75*inch,
                topMargin=0.85*inch, bottomMargin=0.75*inch,
            )

            # ── Styles ─────────────────────────────────────────────────────
            S = getSampleStyleSheet()

            h1 = ParagraphStyle("H1",
                fontSize=13, textColor=NAVY, fontName="Helvetica-Bold",
                spaceBefore=18, spaceAfter=6)
            h2 = ParagraphStyle("H2",
                fontSize=11, textColor=BLUE, fontName="Helvetica-Bold",
                spaceBefore=10, spaceAfter=4)
            body = ParagraphStyle("Body",
                fontSize=9, textColor=GRAY, fontName="Helvetica",
                spaceAfter=4, leading=14)
            small = ParagraphStyle("Small",
                fontSize=8, textColor=GRAY2, fontName="Helvetica",
                spaceAfter=3, leading=12)
            mono = ParagraphStyle("Mono",
                fontSize=8, textColor=HexColor("#1E293B"), fontName="Courier",
                spaceAfter=3, leading=12, backColor=LIGHTGRAY,
                leftIndent=8, rightIndent=8, borderPadding=5)
            bullet_s = ParagraphStyle("Bullet",
                fontSize=9, textColor=GRAY, fontName="Helvetica",
                leftIndent=14, spaceAfter=3, leading=13)
            label_s = ParagraphStyle("Label",
                fontSize=7.5, textColor=GRAY2, fontName="Helvetica-Bold",
                spaceAfter=2, spaceBefore=6)
            warn_s = ParagraphStyle("Warn",
                fontSize=8, textColor=RED, fontName="Helvetica-Bold",
                borderColor=RED, borderWidth=0.4, borderPadding=6,
                backColor=RED_BG, spaceAfter=6)

            def hr(color=BORDER, t=0.5):
                return HRFlowable(width="100%", thickness=t, color=color,
                                  spaceAfter=6, spaceBefore=6)

            def tbl(data, widths, style_cmds):
                t = Table(data, colWidths=widths)
                t.setStyle(TableStyle(style_cmds))
                return t

            # ── Derived values ─────────────────────────────────────────────
            critical_c = scan_data.get("critical_count", 0)
            high_c     = scan_data.get("high_count", 0)
            medium_c   = sum(1 for f in findings if str(f.get("severity","")).lower() == "medium")
            low_c      = sum(1 for f in findings if str(f.get("severity","")).lower() == "low")
            total_c    = scan_data.get("finding_count", len(findings))

            overall = ("CRITICAL" if critical_c > 0 else
                       "HIGH"     if high_c > 0     else
                       "MEDIUM"   if medium_c > 0   else "LOW")
            risk_color = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN}[overall]

            # ── MITRE extraction from findings ─────────────────────────────
            mitre_counts: dict[str, dict] = {}
            for f in findings:
                raw = f.get("mitre_attack") or ""
                m = re.search(r'(T\d{4}(?:\.\d{3})?)', str(raw))
                if m:
                    tid = m.group(1)
                    name = raw.split("—")[-1].strip() if "—" in raw else tid
                    mitre_counts[tid] = {
                        "name": name,
                        "count": mitre_counts.get(tid, {}).get("count", 0) + 1
                    }

            story = []

            # ──────────────────────────────────────────────────────────────
            # COVER PAGE
            # ──────────────────────────────────────────────────────────────
            # Skip past the dark band (3.1" band - 0.85" topMargin = 2.25" to clear)
            story.append(Spacer(1, 2.35*inch))

            meta_rows = [
                ["Target / Log source", str(scan_data.get("target","Unknown"))[:80]],
                ["Report type",         report_type.replace("_"," ").title()],
                ["Generated",           datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
                ["Scan ID",             scan_data.get("id","N/A")],
                ["Authorized by",       scan_data.get("authorized_by","N/A")],
            ]
            story.append(tbl(meta_rows, [1.8*inch, 4.7*inch], [
                ("FONTNAME",     (0,0),(-1,-1), "Helvetica"),
                ("FONTNAME",     (0,0),(0,-1),  "Helvetica-Bold"),
                ("FONTSIZE",     (0,0),(-1,-1), 9),
                ("TEXTCOLOR",    (0,0),(0,-1),  NAVY),
                ("TEXTCOLOR",    (1,0),(1,-1),  GRAY),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[white, LIGHTGRAY]),
                ("GRID",         (0,0),(-1,-1), 0.4, BORDER),
                ("PADDING",      (0,0),(-1,-1), 7),
                ("TOPPADDING",   (0,0),(-1,-1), 5),
            ]))
            story.append(Spacer(1, 0.18*inch))

            # Risk rating badge
            story.append(tbl(
                [[f"Overall Risk Rating", overall,
                  f"{total_c} finding{'s' if total_c != 1 else ''}  ·  {critical_c} critical  ·  {high_c} high"]],
                [1.8*inch, 1.2*inch, 3.5*inch], [
                    ("BACKGROUND",  (0,0), (-1,-1), NAVY),
                    ("TEXTCOLOR",   (0,0), (0,0),   white),
                    ("TEXTCOLOR",   (1,0), (1,0),   risk_color),
                    ("TEXTCOLOR",   (2,0), (2,0),   HexColor("#93C5FD")),
                    ("FONTNAME",    (0,0), (-1,-1),  "Helvetica-Bold"),
                    ("FONTSIZE",    (0,0), (-1,-1),  10),
                    ("FONTSIZE",    (1,0), (1,0),    13),
                    ("PADDING",     (0,0), (-1,-1),  11),
                    ("ALIGN",       (1,0), (1,0),    "CENTER"),
                ]
            ))
            story.append(Spacer(1, 0.14*inch))
            story.append(Paragraph(
                "CONFIDENTIAL — This report contains sensitive security information. "
                "Distribute only to authorized personnel.",
                warn_s
            ))

            # Severity distribution bar
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("Findings by Severity", label_s))
            sev_data = [
                ["Critical", "High", "Medium", "Low"],
                [str(critical_c), str(high_c), str(medium_c), str(low_c)],
            ]
            story.append(tbl(sev_data, [1.5*inch]*4, [
                ("BACKGROUND",  (0,0),(0,0), RED),
                ("BACKGROUND",  (1,0),(1,0), ORANGE),
                ("BACKGROUND",  (2,0),(2,0), YELLOW),
                ("BACKGROUND",  (3,0),(3,0), GREEN),
                ("BACKGROUND",  (0,1),(0,1), RED_BG),
                ("BACKGROUND",  (1,1),(1,1), ORG_BG),
                ("BACKGROUND",  (2,1),(2,1), HexColor("#FEFCE8")),
                ("BACKGROUND",  (3,1),(3,1), HexColor("#F0FDF4")),
                ("TEXTCOLOR",   (0,0),(-1,0), white),
                ("TEXTCOLOR",   (0,1),(0,1), RED),
                ("TEXTCOLOR",   (1,1),(1,1), ORANGE),
                ("TEXTCOLOR",   (2,1),(2,1), YELLOW),
                ("TEXTCOLOR",   (3,1),(3,1), GREEN),
                ("FONTNAME",    (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0),(-1,0),  9),
                ("FONTSIZE",    (0,1),(-1,1),  18),
                ("ALIGN",       (0,0),(-1,-1), "CENTER"),
                ("PADDING",     (0,0),(-1,0),  6),
                ("PADDING",     (0,1),(-1,1),  10),
                ("GRID",        (0,0),(-1,-1), 0.4, BORDER),
            ]))

            story.append(PageBreak())

            # ──────────────────────────────────────────────────────────────
            # EXECUTIVE SUMMARY
            # ──────────────────────────────────────────────────────────────
            story.append(Paragraph("Executive Summary", h1))
            story.append(hr(NAVY, 1))

            # Pull the first coherent block from llm_analysis as exec summary
            exec_lines = []
            if llm_analysis:
                for line in llm_analysis.split("\n"):
                    line = line.strip()
                    if line.startswith("#"):
                        if exec_lines:
                            break
                        continue
                    if line:
                        exec_lines.append(line)
                    if len(exec_lines) >= 6:
                        break

            exec_text = " ".join(exec_lines) if exec_lines else (
                scan_data.get("summary") or
                f"Security assessment of {scan_data.get('target','the target')} completed on "
                f"{datetime.utcnow().strftime('%B %d, %Y')} with {total_c} findings identified. "
                f"{'Immediate action required for critical issues.' if critical_c else 'No critical issues detected.'}"
            )
            story.append(Paragraph(exec_text, body))
            story.append(Spacer(1, 0.12*inch))

            # IOC section if available
            ips     = (iocs.get("ips")     or [])[:20]
            domains = (iocs.get("domains") or [])[:15]
            hashes  = (iocs.get("hashes")  or [])[:10]

            if ips or domains:
                story.append(Paragraph("Indicators of Compromise (IOCs)", h1))
                story.append(hr(NAVY, 1))

                if ips:
                    story.append(Paragraph("Suspicious IP Addresses", h2))
                    ip_rows = [["IP Address", "Risk"]]
                    for ip in ips:
                        ip_rows.append([ip, "Suspicious"])
                    story.append(tbl(ip_rows, [3.5*inch, 3*inch], [
                        ("BACKGROUND",  (0,0),(-1,0),  NAVY),
                        ("TEXTCOLOR",   (0,0),(-1,0),  white),
                        ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
                        ("FONTSIZE",    (0,0),(-1,-1), 8.5),
                        ("FONTNAME",    (0,1),(-1,-1), "Courier"),
                        ("ROWBACKGROUNDS",(0,1),(-1,-1),[white, RED_BG]),
                        ("TEXTCOLOR",   (0,1),(-1,-1), RED),
                        ("GRID",        (0,0),(-1,-1), 0.4, BORDER),
                        ("PADDING",     (0,0),(-1,-1), 6),
                    ]))
                    story.append(Spacer(1, 0.1*inch))

                if domains:
                    story.append(Paragraph("Suspicious Domains", h2))
                    dom_rows = [["Domain", "Risk"]]
                    for d in domains:
                        dom_rows.append([d, "Suspicious"])
                    story.append(tbl(dom_rows, [4*inch, 2.5*inch], [
                        ("BACKGROUND",  (0,0),(-1,0),  NAVY),
                        ("TEXTCOLOR",   (0,0),(-1,0),  white),
                        ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
                        ("FONTSIZE",    (0,0),(-1,-1), 8.5),
                        ("FONTNAME",    (0,1),(-1,-1), "Courier"),
                        ("ROWBACKGROUNDS",(0,1),(-1,-1),[white, ORG_BG]),
                        ("TEXTCOLOR",   (0,1),(-1,-1), ORANGE),
                        ("GRID",        (0,0),(-1,-1), 0.4, BORDER),
                        ("PADDING",     (0,0),(-1,-1), 6),
                    ]))
                    story.append(Spacer(1, 0.1*inch))

            # MITRE table
            if mitre_counts:
                story.append(Paragraph("MITRE ATT&CK Techniques Observed", h1))
                story.append(hr(NAVY, 1))
                mit_rows = [["Technique ID", "Name", "Detections"]]
                for tid, meta in sorted(mitre_counts.items(), key=lambda x: -x[1]["count"]):
                    mit_rows.append([tid, meta["name"], str(meta["count"])])
                story.append(tbl(mit_rows, [1.1*inch, 4.5*inch, 1*inch], [
                    ("BACKGROUND",  (0,0),(-1,0),  NAVY),
                    ("TEXTCOLOR",   (0,0),(-1,0),  white),
                    ("FONTNAME",    (0,0),(-1,0),  "Helvetica-Bold"),
                    ("FONTSIZE",    (0,0),(-1,-1), 8.5),
                    ("FONTNAME",    (0,1),(0,-1),  "Courier"),
                    ("TEXTCOLOR",   (0,1),(0,-1),  ACCENT),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[white, LIGHTGRAY]),
                    ("GRID",        (0,0),(-1,-1), 0.4, BORDER),
                    ("PADDING",     (0,0),(-1,-1), 6),
                    ("ALIGN",       (2,0),(2,-1),  "CENTER"),
                ]))
                story.append(Spacer(1, 0.12*inch))

            # ──────────────────────────────────────────────────────────────
            # FINDINGS
            # ──────────────────────────────────────────────────────────────
            if findings:
                story.append(PageBreak())
                story.append(Paragraph("Security Findings", h1))
                story.append(hr(NAVY, 1))

                for i, f in enumerate(findings[:40], 1):
                    sev  = str(f.get("severity", "info")).lower()
                    fc   = sev_color(sev)
                    fbg  = sev_bg(sev)

                    block = []
                    block.append(Paragraph(f"{i}. {f.get('title','Untitled Finding')}", h2))

                    chip_data = [[
                        sev.upper(),
                        f.get("cve_id") or "—",
                        f"CVSS: {f.get('cvss_score','N/A')}",
                        f.get("mitre_attack") or "—",
                    ]]
                    chip = tbl(chip_data, [0.9*inch, 1.3*inch, 1.1*inch, 3.2*inch], [
                        ("BACKGROUND", (0,0),(0,0),  fc),
                        ("BACKGROUND", (1,0),(-1,0), fbg),
                        ("TEXTCOLOR",  (0,0),(0,0),  white),
                        ("TEXTCOLOR",  (1,0),(-1,0), GRAY),
                        ("FONTNAME",   (0,0),(-1,-1),"Helvetica-Bold"),
                        ("FONTSIZE",   (0,0),(-1,-1), 7.5),
                        ("PADDING",    (0,0),(-1,-1), 5),
                        ("GRID",       (0,0),(-1,-1), 0.3, BORDER),
                        ("ALIGN",      (0,0),(0,0),   "CENTER"),
                    ])
                    block.append(chip)

                    if f.get("description"):
                        block.append(Paragraph(str(f["description"])[:400], body))
                    if f.get("evidence"):
                        block.append(Paragraph("<b>Evidence:</b> " + str(f["evidence"])[:250], small))
                    if f.get("remediation"):
                        block.append(Paragraph("<b>Remediation:</b> " + str(f["remediation"])[:300], body))
                    block.append(hr(BORDER, 0.4))

                    story.append(KeepTogether(block))

            # ──────────────────────────────────────────────────────────────
            # AI ANALYSIS
            # ──────────────────────────────────────────────────────────────
            if llm_analysis:
                story.append(PageBreak())
                story.append(Paragraph("AI Security Analysis", h1))
                story.append(hr(NAVY, 1))
                story.append(Paragraph(
                    "Generated by Claude (Anthropic) based on detected security events.",
                    ParagraphStyle("Note", fontSize=8, textColor=GRAY2,
                                   fontName="Helvetica-Oblique", spaceAfter=10)
                ))

                pending = []

                def flush():
                    if pending:
                        story.append(Paragraph(" ".join(pending), body))
                        pending.clear()

                for line in llm_analysis.split("\n"):
                    stripped = line.strip()
                    if not stripped:
                        flush()
                        story.append(Spacer(1, 0.04*inch))
                    elif stripped.startswith("### "):
                        flush()
                        story.append(Paragraph(stripped[4:], h2))
                    elif stripped.startswith("## "):
                        flush()
                        story.append(Paragraph(stripped[3:], h1))
                        story.append(hr(BLUE, 0.5))
                    elif stripped.startswith("# "):
                        flush()
                        story.append(Paragraph(stripped[2:], h1))
                    elif stripped.startswith("|"):
                        flush()
                        clean = stripped.replace("|", "  ").strip()
                        if clean.replace("-","").replace(" ",""):
                            story.append(Paragraph(clean, mono))
                    elif stripped.startswith(("- ", "• ", "* ")):
                        flush()
                        story.append(Paragraph("• " + stripped.lstrip("-•* "), bullet_s))
                    else:
                        pending.append(stripped)
                flush()

            # ──────────────────────────────────────────────────────────────
            # FOOTER PAGE
            # ──────────────────────────────────────────────────────────────
            story.append(Spacer(1, 0.3*inch))
            story.append(hr(NAVY, 1))
            story.append(Paragraph(
                f"Generated by SentinelAI  ·  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ·  "
                "For authorized security assessment use only.",
                ParagraphStyle("Footer", fontSize=7.5, textColor=GRAY2,
                               fontName="Helvetica", alignment=TA_CENTER)
            ))

            doc.build(story, onFirstPage=_on_cover, onLaterPages=_on_page)
            log.info("PDF report generated", path=fp)
            return fp

        except ImportError:
            log.error("ReportLab not installed — run: pip install reportlab")
            raise
        except Exception as e:
            log.error("PDF generation failed", error=str(e))
            raise
