"""
Module 6: Mitigation Engine (Blue Team)

Takes scan and analysis results and uses LLMs to generate:
  1. Executive summary (non-technical, business-focused)
  2. Priority-ranked remediation plan
  3. Technical implementation guide for each fix
  4. Risk scoring and timeline recommendations
  5. PDF and Markdown report export
"""
import json
from typing import Optional
from datetime import datetime
from pathlib import Path
import structlog

from sentinelai.core.llm_client import get_llm_client
from sentinelai.core.config import get_settings

log = structlog.get_logger()


class MitigationEngine:
    """
    Generates AI-powered remediation plans and professional security reports.
    """

    def __init__(self):
        self.llm  = get_llm_client()
        self.settings = get_settings()

    # ── LLM Mitigation Plan ────────────────────────────────────────────────

    async def generate_mitigation_plan(
        self,
        target: str,
        findings: list[dict],
        scan_type: str = "full",
        organization: str = "Target Organization"
    ) -> str:
        """
        Generate a comprehensive, prioritised remediation plan using Claude.

        Args:
            target: The scanned target
            findings: List of vulnerability/threat findings
            scan_type: "recon", "vuln", "log_analyse", or "full"
            organization: Name for the report
        """
        log.info("Generating LLM mitigation plan", target=target, findings=len(findings))

        prompt = f"""Generate a comprehensive security remediation plan for: {organization}
Target: {target}
Assessment type: {scan_type}
Assessment date: {datetime.utcnow().strftime('%Y-%m-%d')}

## Security Findings
{json.dumps(findings[:30], indent=2, default=str)}

## Required Output

### 1. Executive Summary (for C-suite audience)
- 3-4 paragraphs, no technical jargon
- Business risk articulation
- Financial impact estimate if vulnerabilities are exploited
- Headline risk rating: Critical / High / Medium / Low

### 2. Findings Summary Table
| # | Finding | Severity | CVSS | Affected Asset | Risk |
|---|---------|----------|------|----------------|------|

### 3. Immediate Actions (0-24 hours)
For each critical/high finding:
- Specific action to take
- Commands or configuration changes (where applicable)
- Who is responsible (Security team / Sysadmin / Developer)
- Estimated time to implement

### 4. Short-term Remediation (1-7 days)
Medium severity findings with implementation guide:
- Step-by-step fix instructions
- Testing verification steps
- Rollback plan if fix causes issues

### 5. Long-term Security Improvements (30-90 days)
Strategic recommendations:
- Architecture changes
- Process improvements
- Security tooling gaps
- Training recommendations

### 6. Remediation Priority Matrix
| Priority | Finding | Effort (Low/Med/High) | Impact (Low/Med/High) | Deadline |
|----------|---------|----------------------|----------------------|----------|

### 7. Verification Checklist
After remediation, how to verify each fix was successful:
- [ ] Specific test for each vulnerability
- [ ] Expected result when fixed

### 8. Risk Acceptance Statement
For findings the organization chooses not to remediate immediately:
Document the accepted risk, business justification, and review date.

Be specific with commands, configuration examples, and actionable steps.
Reference NIST, CIS Benchmarks, and OWASP where relevant."""

        system = self.llm.security_analyst_system() + """

You are generating a formal security assessment report. Be:
- Specific and actionable — generic advice is useless
- Realistic about timelines — don't suggest impossible fixes
- Business-aware — acknowledge that not everything can be fixed immediately
- Clear about risk — help the client understand actual business impact"""

        return await self.llm.complete(prompt=prompt, system=system, max_tokens=4000)

    # ── Structured findings from LLM analysis ─────────────────────────────

    async def extract_structured_findings(
        self,
        llm_analysis: str,
        scan_type: str
    ) -> list[dict]:
        """
        Parse the LLM analysis text into structured finding objects.
        Used to populate the database and generate sortable reports.
        """
        prompt = f"""Extract structured security findings from this analysis:

{llm_analysis[:3000]}

Return a JSON array of findings. Each finding must have:
{{
  "title": "Short finding title",
  "severity": "critical|high|medium|low|info",
  "cvss_score": 7.5,
  "cve_id": "CVE-2024-XXXX or null",
  "description": "What the vulnerability is",
  "evidence": "What evidence was found",
  "remediation": "How to fix it",
  "mitre_attack": "T1190 or null",
  "effort_to_fix": "low|medium|high",
  "priority": 1
}}

Return ONLY the JSON array, no other text."""

        result = await self.llm.complete_json(prompt)
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "error" in result:
            return []
        return []

    # ── Report generation ──────────────────────────────────────────────────

    async def generate_report(
        self,
        scan_results: dict,
        output_format: str = "markdown",
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate a full security assessment report in Markdown or PDF.

        Args:
            scan_results: Combined results from recon, vuln, log modules
            output_format: "markdown" or "pdf"
            output_path: Where to save the file (optional)

        Returns:
            Path to generated report file
        """
        target    = scan_results.get("target", "Unknown Target")
        scan_type = scan_results.get("scan_type", "full")

        log.info("Generating security report", target=target, format=output_format)

        # Build findings list from scan results
        findings = self._extract_all_findings(scan_results)

        # Generate mitigation plan
        mitigation = await self.generate_mitigation_plan(
            target=target,
            findings=findings,
            scan_type=scan_type
        )

        # Build the full report
        report_content = self._build_markdown_report(
            scan_results=scan_results,
            findings=findings,
            mitigation_plan=mitigation
        )

        # Save file
        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            safe_target = target.replace(".", "_").replace("/", "_")
            filename = f"sentinelai_report_{safe_target}_{timestamp}.md"
            output_path = str(Path("reports") / filename)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        if output_format == "pdf":
            output_path = output_path.replace(".md", ".pdf")
            self._export_pdf(report_content, output_path, target)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_content)

        log.info("Report generated", path=output_path)
        return output_path

    # ── Markdown report builder ────────────────────────────────────────────

    def _build_markdown_report(
        self,
        scan_results: dict,
        findings: list,
        mitigation_plan: str
    ) -> str:
        target     = scan_results.get("target", "Unknown")
        started_at = scan_results.get("started_at", "")
        scan_type  = scan_results.get("scan_type", "full")

        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]
        medium   = [f for f in findings if f.get("severity") == "medium"]
        low      = [f for f in findings if f.get("severity") == "low"]

        overall_risk = "CRITICAL" if critical else "HIGH" if high else "MEDIUM" if medium else "LOW"

        report = f"""# SentinelAI Security Assessment Report

**Target:** {target}
**Assessment Type:** {scan_type.upper()}
**Date:** {datetime.utcnow().strftime('%B %d, %Y')}
**Overall Risk Rating:** {overall_risk}
**Generated by:** SentinelAI v{self.settings.app_version}

---

> ⚠️ **CONFIDENTIAL** — This report contains sensitive security information.
> Distribution should be limited to authorized personnel only.
> This assessment was conducted under authorized penetration testing agreement.

---

## Risk Dashboard

| Severity | Count |
|----------|-------|
| 🔴 Critical | {len(critical)} |
| 🟠 High | {len(high)} |
| 🟡 Medium | {len(medium)} |
| 🟢 Low | {len(low)} |
| **Total** | **{len(findings)}** |

---

## Scan Summary

"""
        # Add module-specific summaries
        if "dns" in scan_results:
            dns = scan_results["dns"]
            report += f"""### Reconnaissance Results
- **Subdomains discovered:** {len(dns.get('subdomains', []))}
- **DNS record types:** {', '.join(dns.get('records', {}).keys())}
- **Open ports:** {len(scan_results.get('ports', {}).get('open_ports', []))}

"""

        if "all_cves" in scan_results:
            cves = scan_results["all_cves"]
            report += f"""### Vulnerability Analysis Results
- **Total CVEs found:** {len(cves)}
- **Critical/High CVEs:** {len([c for c in cves if (c.get('cvss_score') or 0) >= 7.0])}
- **Highest CVSS score:** {max((c.get('cvss_score') or 0 for c in cves), default=0)}

"""

        if "anomalies" in scan_results:
            anomalies = scan_results["anomalies"]
            report += f"""### Log Analysis Results
- **Log lines analysed:** {scan_results.get('log_data', {}).get('total_lines', 0)}
- **Anomalies detected:** {anomalies.get('anomaly_count', 0)}
- **Suspicious IPs:** {len(anomalies.get('suspicious_ips', []))}

"""

        report += f"""---

## Security Findings

"""
        # Add findings
        for i, finding in enumerate(findings[:30], 1):
            severity_emoji = {
                "critical": "🔴", "high": "🟠",
                "medium": "🟡", "low": "🟢", "info": "⚪"
            }.get(finding.get("severity", "info"), "⚪")

            report += f"""### {i}. {finding.get('title', 'Untitled Finding')}

**Severity:** {severity_emoji} {finding.get('severity', 'unknown').upper()}
{f"**CVE:** {finding['cve_id']}" if finding.get('cve_id') else ""}
{f"**CVSS Score:** {finding['cvss_score']}" if finding.get('cvss_score') else ""}
{f"**MITRE ATT&CK:** {finding['mitre_attack']}" if finding.get('mitre_attack') else ""}

**Description:**
{finding.get('description', 'No description available')}

**Evidence:**
{finding.get('evidence', 'See scan results')}

**Remediation:**
{finding.get('remediation', 'See mitigation plan below')}

---

"""

        # Add LLM analyses
        if scan_results.get("llm_analysis"):
            report += f"""## LLM Security Analysis

{scan_results['llm_analysis']}

---

"""

        # Add mitigation plan
        report += f"""## Remediation Plan

{mitigation_plan}

---

## Disclaimer

This security assessment was conducted for authorized penetration testing purposes only.
All findings should be validated before remediation. SentinelAI and its operators
are not responsible for any damage caused by implementing these recommendations
without proper change management processes.

*Report generated: {datetime.utcnow().isoformat()} UTC*
"""
        return report

    # ── PDF export ─────────────────────────────────────────────────────────

    def _export_pdf(self, markdown_content: str, output_path: str, title: str):
        """Export the report as a PDF using ReportLab."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
            from reportlab.lib.units import inch

            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=inch,
                leftMargin=inch,
                topMargin=inch,
                bottomMargin=inch
            )

            styles = getSampleStyleSheet()
            navy  = HexColor("#1F4E79")
            red   = HexColor("#A32D2D")

            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Title"],
                textColor=navy,
                fontSize=20,
                spaceAfter=12
            )
            h1_style = ParagraphStyle(
                "CustomH1",
                parent=styles["Heading1"],
                textColor=navy,
                fontSize=14,
                spaceBefore=16,
                spaceAfter=8
            )

            story = []
            story.append(Paragraph(f"SentinelAI Security Report: {title}", title_style))
            story.append(Paragraph(
                f"Generated: {datetime.utcnow().strftime('%B %d, %Y')}",
                styles["Normal"]
            ))
            story.append(Spacer(1, 0.3 * inch))
            story.append(HRFlowable(width="100%", thickness=1, color=navy))
            story.append(Spacer(1, 0.2 * inch))

            # Parse markdown sections
            for line in markdown_content.split("\n"):
                if line.startswith("## "):
                    story.append(Paragraph(line[3:], h1_style))
                elif line.startswith("### "):
                    story.append(Paragraph(line[4:], styles["Heading2"]))
                elif line.startswith("**") and line.endswith("**"):
                    story.append(Paragraph(f"<b>{line[2:-2]}</b>", styles["Normal"]))
                elif line.strip() == "---":
                    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC")))
                    story.append(Spacer(1, 0.1 * inch))
                elif line.strip():
                    story.append(Paragraph(line, styles["Normal"]))
                    story.append(Spacer(1, 0.05 * inch))

            doc.build(story)
            log.info("PDF report generated", path=output_path)

        except ImportError:
            log.warning("ReportLab not installed — saving as Markdown instead")
            md_path = output_path.replace(".pdf", ".md")
            with open(md_path, "w") as f:
                f.write(markdown_content)

    # ── Private helpers ────────────────────────────────────────────────────

    def _extract_all_findings(self, scan_results: dict) -> list[dict]:
        """Extract and normalise findings from all module results."""
        findings = []

        # From CVE analysis
        for cve in scan_results.get("all_cves", [])[:20]:
            findings.append({
                "title":       f"{cve.get('cve_id', 'CVE')} — Vulnerability",
                "severity":    cve.get("severity", "medium"),
                "cvss_score":  cve.get("cvss_score"),
                "cve_id":      cve.get("cve_id"),
                "description": cve.get("description", ""),
                "evidence":    f"Detected on service scan",
                "remediation": "Apply vendor patch and update service",
                "mitre_attack": None
            })

        # From log anomalies
        for anomaly in scan_results.get("anomalies", {}).get("top_threats", []):
            findings.append({
                "title":      f"Log anomaly: {anomaly.get('type', 'Unknown')}",
                "severity":   anomaly.get("severity", "medium"),
                "cvss_score": None,
                "cve_id":     None,
                "description": f"Pattern detected: {anomaly.get('type')}",
                "evidence":   anomaly.get("raw_entry", ""),
                "remediation": "Investigate source IP and block if malicious",
                "mitre_attack": anomaly.get("mitre_ttp")
            })

        return findings


# Optional type hint
from typing import Optional
