"""
Module 2: Vulnerability Analyser (Red Team)

For each discovered service/version:
  1. Queries NVD (National Vulnerability Database) for known CVEs
  2. Fetches CVSS scores and attack vectors
  3. LLM assesses real-world exploitability in context
  4. Generates ranked attack path with proof-of-concept guidance
  5. Maps findings to MITRE ATT&CK techniques
"""
import asyncio
from datetime import datetime
from typing import Optional
import httpx
import structlog

from sentinelai.core.llm_client import get_llm_client
from sentinelai.core.config import get_settings

log = structlog.get_logger()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class VulnAnalyser:
    """
    Vulnerability analysis engine.
    Combines NVD CVE data with LLM-powered exploitability assessment.
    """

    def __init__(self):
        self.llm = get_llm_client()
        self.settings = get_settings()

    # ── CVE Lookup ─────────────────────────────────────────────────────────

    async def lookup_cves(
        self,
        keyword: str,
        max_results: int = 10
    ) -> list[dict]:
        """
        Search NVD for CVEs matching a keyword (service name, product, version).

        Args:
            keyword: e.g. "Apache 2.4.51", "OpenSSH 8.2", "nginx 1.18"
            max_results: Maximum CVEs to return

        Returns:
            List of CVE dicts with id, description, cvss_score, published date
        """
        log.info("Querying NVD for CVEs", keyword=keyword)

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 20),
            "cvssV3Severity": "HIGH"  # start with high severity
        }

        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    NVD_BASE_URL,
                    params=params,
                    headers=headers
                )
                response.raise_for_status()
                data = response.json()

        except httpx.TimeoutException:
            log.warning("NVD API timeout", keyword=keyword)
            return []
        except httpx.HTTPError as e:
            log.error("NVD API error", error=str(e))
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Extract description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # Extract CVSS v3 score
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_vector = None
            attack_vector = None

            cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss_data:
                cvss_info = cvss_data[0].get("cvssData", {})
                cvss_score  = cvss_info.get("baseScore")
                cvss_vector = cvss_info.get("vectorString")
                attack_vector = cvss_info.get("attackVector")

            # Extract references
            references = [
                ref.get("url", "") for ref in cve.get("references", [])[:3]
            ]

            cves.append({
                "cve_id":       cve_id,
                "description":  description[:500],
                "cvss_score":   cvss_score,
                "cvss_vector":  cvss_vector,
                "attack_vector": attack_vector,
                "published":    cve.get("published", ""),
                "modified":     cve.get("lastModified", ""),
                "references":   references,
                "severity":     self._score_to_severity(cvss_score)
            })

        log.info("CVE lookup complete", keyword=keyword, count=len(cves))
        return sorted(cves, key=lambda x: x.get("cvss_score") or 0, reverse=True)

    # ── IP Reputation Check ────────────────────────────────────────────────

    async def check_ip_reputation(self, ip: str) -> dict:
        """
        Check IP reputation via AbuseIPDB.
        Returns abuse confidence score and known attack categories.
        """
        if not self.settings.abuseipdb_api_key:
            return {"error": "No AbuseIPDB API key configured", "ip": ip}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={
                        "Key": self.settings.abuseipdb_api_key,
                        "Accept": "application/json"
                    }
                )
                response.raise_for_status()
                data = response.json().get("data", {})

                return {
                    "ip":               ip,
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "country":          data.get("countryCode", ""),
                    "isp":              data.get("isp", ""),
                    "total_reports":    data.get("totalReports", 0),
                    "last_reported":    data.get("lastReportedAt", ""),
                    "categories":       data.get("reports", [])[:5],
                    "is_malicious":     data.get("abuseConfidenceScore", 0) > 25
                }
        except Exception as e:
            return {"error": str(e), "ip": ip}

    # ── LLM Exploitability Assessment ─────────────────────────────────────

    async def assess_exploitability(
        self,
        target: str,
        open_ports: list[dict],
        cves: list[dict],
        environment_context: Optional[str] = None
    ) -> str:
        """
        Feed CVE data and service info to Claude for expert exploitability assessment.

        This is the core LLM value-add: not just listing CVEs but assessing
        which ones are actually exploitable in this specific environment.
        """
        log.info("Starting LLM exploitability assessment", target=target, cve_count=len(cves))

        prompt = f"""Perform a detailed exploitability assessment for: {target}

## Discovered Services
{self._format_ports(open_ports)}

## Known CVEs Found
{self._format_cves(cves)}

{f"## Environment Context{chr(10)}{environment_context}" if environment_context else ""}

## Required Assessment

### 1. Executive Risk Summary
- Overall risk level: Critical/High/Medium/Low
- 2-3 sentence business impact statement

### 2. Top 5 Exploitable Vulnerabilities
For each, provide:
- CVE ID and service affected
- Why this is exploitable in THIS environment (not just generic CVSS score)
- Step-by-step attack path (high level)
- MITRE ATT&CK technique mapping
- Estimated time to exploit for a skilled attacker
- Proof-of-concept approach (describe, don't provide working exploit code)

### 3. Attack Chain Analysis
Describe the most likely complete attack chain from initial access to impact:
Initial Access → Execution → Persistence → Privilege Escalation → Impact

### 4. Quick Wins for Defenders
What 3 things could the target do TODAY to eliminate the most critical risk?

### 5. Exploitation Difficulty Matrix
Rate each CVE:
| CVE | Exploitability | Impact | Priority |
|-----|---------------|--------|----------|

Be specific and technical. This is for an authorized penetration test."""

        return await self.llm.complete(
            prompt=prompt,
            system=self.llm.vuln_analyst_system(),
            max_tokens=4000
        )

    # ── Full Vuln Analysis Workflow ────────────────────────────────────────

    async def run_full_analysis(
        self,
        target: str,
        open_ports: list[dict],
        authorized_by: str
    ) -> dict:
        """
        Complete vulnerability analysis workflow:
        Service list → CVE lookup → LLM assessment → Ranked findings
        """
        log.info("Starting full vulnerability analysis", target=target)

        results = {
            "target":         target,
            "authorized_by":  authorized_by,
            "started_at":     datetime.utcnow().isoformat(),
            "cves_by_service": {},
            "all_cves":       [],
            "llm_assessment": "",
            "finding_count":  0,
            "completed_at":   None
        }

        # Look up CVEs for each discovered service
        cve_tasks = []
        for port_info in open_ports:
            service  = port_info.get("service", "")
            product  = port_info.get("product", "")
            version  = port_info.get("version", "")

            if service and service != "unknown":
                keyword = f"{product} {version}".strip() if product else service
                cve_tasks.append((port_info["port"], keyword))

        # Run CVE lookups concurrently (max 5 at once)
        semaphore = asyncio.Semaphore(5)
        async def bounded_lookup(port, keyword):
            async with semaphore:
                cves = await self.lookup_cves(keyword)
                return port, keyword, cves

        lookups = await asyncio.gather(*[
            bounded_lookup(port, keyword) for port, keyword in cve_tasks
        ])

        for port, keyword, cves in lookups:
            results["cves_by_service"][f"port_{port}_{keyword}"] = cves
            results["all_cves"].extend(cves)

        # Deduplicate CVEs
        seen = set()
        unique_cves = []
        for cve in results["all_cves"]:
            if cve["cve_id"] not in seen:
                seen.add(cve["cve_id"])
                unique_cves.append(cve)
        results["all_cves"] = sorted(
            unique_cves,
            key=lambda x: x.get("cvss_score") or 0,
            reverse=True
        )
        results["finding_count"] = len(results["all_cves"])

        # LLM exploitability assessment
        results["llm_assessment"] = await self.assess_exploitability(
            target, open_ports, results["all_cves"][:20]  # top 20 CVEs
        )

        results["completed_at"] = datetime.utcnow().isoformat()
        log.info("Vulnerability analysis complete",
                 target=target, cves_found=results["finding_count"])

        return results

    # ── Private helpers ────────────────────────────────────────────────────

    def _score_to_severity(self, score: Optional[float]) -> str:
        if score is None:    return "info"
        if score >= 9.0:     return "critical"
        if score >= 7.0:     return "high"
        if score >= 4.0:     return "medium"
        return "low"

    def _format_ports(self, ports: list[dict]) -> str:
        if not ports:
            return "No open ports provided"
        lines = []
        for p in ports:
            lines.append(
                f"- Port {p.get('port')}/{p.get('protocol','tcp')}: "
                f"{p.get('service','unknown')} "
                f"{p.get('product','')} {p.get('version','')}".strip()
            )
        return "\n".join(lines)

    def _format_cves(self, cves: list[dict]) -> str:
        if not cves:
            return "No CVEs found"
        lines = []
        for c in cves[:15]:
            lines.append(
                f"- {c['cve_id']} (CVSS: {c.get('cvss_score', 'N/A')}, "
                f"Attack Vector: {c.get('attack_vector', 'N/A')}): "
                f"{c['description'][:150]}"
            )
        return "\n".join(lines)
