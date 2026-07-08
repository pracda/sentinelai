"""
Module: Log Correlator (Blue Team)

Accepts 2-10 log sources and cross-correlates events to reconstruct
the full attack chain across systems:
  1. Ingests and analyses each log source independently
  2. Extracts IOCs and anomalies from each
  3. Feeds all results to Claude for unified correlation analysis
  4. Returns a structured attack chain timeline
"""
import asyncio
from datetime import datetime
from typing import Optional
import structlog

from sentinelai.core.llm_client import get_llm_client
from sentinelai.modules.logs.analyser import LogAnalyser

log = structlog.get_logger()


class LogCorrelator:
    """
    Cross-source log correlation engine.
    Identifies attack chains that span multiple systems/log sources.
    """

    def __init__(self):
        self.llm = get_llm_client()
        self.analyser = LogAnalyser()

    async def correlate(
        self,
        logs: list[dict],
        context: Optional[str] = None,
        api_key_name: str = "default"
    ) -> dict:
        """
        Correlate events across 2-10 log sources.

        Args:
            logs: List of {"log_source": str, "log_content": str} dicts
            context: Optional analyst context/hint
            api_key_name: API key identifier for audit

        Returns:
            Correlation report with unified timeline and attack chain
        """
        if not logs or len(logs) < 2:
            return {"error": "Provide at least 2 log sources for correlation"}
        if len(logs) > 10:
            logs = logs[:10]

        log.info("Starting log correlation", sources=len(logs))

        started_at = datetime.utcnow().isoformat()

        # Step 1: analyse each source in parallel
        tasks = [
            self._analyse_single(entry.get("log_source", f"source_{i}"),
                                 entry.get("log_content", ""))
            for i, entry in enumerate(logs)
        ]
        per_source_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Step 2: collect IOCs and anomalies from each source
        source_summaries = []
        all_suspicious_ips = set()
        total_anomalies = 0

        for i, result in enumerate(per_source_results):
            source_name = logs[i].get("log_source", f"source_{i}")
            if isinstance(result, Exception):
                source_summaries.append({
                    "source": source_name,
                    "error": str(result)
                })
                continue

            anomalies = result.get("anomalies", {})
            iocs = result.get("iocs", {})
            suspicious_ips = anomalies.get("suspicious_ips", [])
            all_suspicious_ips.update(suspicious_ips)
            total_anomalies += anomalies.get("anomaly_count", 0)

            source_summaries.append({
                "source":          source_name,
                "log_type":        result.get("log_data", {}).get("log_type", "unknown"),
                "lines_analysed":  result.get("log_data", {}).get("total_lines", 0),
                "anomaly_count":   anomalies.get("anomaly_count", 0),
                "suspicious_ips":  suspicious_ips,
                "top_threats":     anomalies.get("top_threats", [])[:3],
                "iocs_ips":        iocs.get("ips", [])[:10],
                "iocs_domains":    iocs.get("domains", [])[:5],
                "llm_analysis":    result.get("llm_analysis", "")
            })

        # Step 3: LLM cross-source correlation
        correlation_analysis = await self._correlate_with_llm(
            source_summaries=source_summaries,
            shared_ips=list(all_suspicious_ips),
            context=context
        )

        return {
            "correlation_id":       f"corr_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "started_at":           started_at,
            "completed_at":         datetime.utcnow().isoformat(),
            "sources_analysed":     len(source_summaries),
            "total_anomalies":      total_anomalies,
            "shared_suspicious_ips": list(all_suspicious_ips),
            "per_source":           source_summaries,
            "correlation_analysis": correlation_analysis
        }

    async def _analyse_single(self, log_source: str, log_content: str) -> dict:
        """Run full analysis on a single log source."""
        if not log_content.strip():
            return {
                "log_data": {"log_type": "unknown", "total_lines": 0},
                "anomalies": {"anomaly_count": 0, "suspicious_ips": [], "top_threats": []},
                "iocs": {},
                "llm_analysis": ""
            }
        return await self.analyser.run_full_analysis(
            log_source=log_source,
            log_content=log_content
        )

    async def _correlate_with_llm(
        self,
        source_summaries: list[dict],
        shared_ips: list[str],
        context: Optional[str] = None
    ) -> str:
        """Ask Claude to reconstruct the attack chain across all sources."""

        sources_text = ""
        for s in source_summaries:
            if "error" in s:
                sources_text += f"\n### {s['source']}\nError: {s['error']}\n"
                continue
            sources_text += f"""
### {s['source']} ({s['log_type']}, {s['lines_analysed']} lines)
- Anomalies: {s['anomaly_count']}
- Suspicious IPs: {s['suspicious_ips'][:5]}
- Top threats: {[t.get('type') for t in s['top_threats']]}
- IOC IPs: {s['iocs_ips'][:5]}

Per-source analysis summary:
{s['llm_analysis'][:800]}
"""

        prompt = f"""You are performing cross-source log correlation for incident response.
Multiple security log sources have been collected from the same environment during a potential attack.
Your task is to correlate events across all sources and reconstruct the complete attack chain.

## Sources Analysed
{sources_text}

## Shared Suspicious IPs (appear in multiple sources)
{shared_ips[:20]}

{f"## Analyst Context{chr(10)}{context}" if context else ""}

## Required Correlation Analysis

### 1. Attack Chain Reconstruction
Reconstruct the complete attack sequence in chronological order across ALL log sources:
[Timestamp/Phase] → [Source] → [Event] → [Significance]

### 2. Pivot Points
Where did the attacker move from one system to another?
- Source: [Log source] → Target: [Log source]
- Evidence: [Specific events that link the two]
- Technique: [MITRE ATT&CK TTP]

### 3. Shared IOC Analysis
For each shared IP or domain appearing across multiple sources:
- Confirmed malicious vs. coincidental
- Role in the attack (C2, scanner, exfiltration server)

### 4. Unified MITRE ATT&CK Timeline
Map the complete attack to the ATT&CK Kill Chain:
| Phase | Technique | Source | Evidence |
|-------|-----------|--------|----------|

### 5. Attack Attribution Assessment
Based on TTPs, tooling, and patterns:
- Sophistication level
- Likely threat actor category
- Confidence level

### 6. Blast Radius Assessment
What systems/data were likely accessed or compromised?

### 7. Immediate Containment Actions (priority ordered)
What should the SOC do RIGHT NOW based on the full picture?"""

        return await self.llm.complete(
            prompt=prompt,
            system=self.llm.log_analyst_system(),
            max_tokens=8000
        )
