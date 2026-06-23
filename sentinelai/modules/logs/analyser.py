"""
Module 4: Log Analyser (Blue Team)

Ingests raw security logs and uses LLMs to:
  1. Parse and normalise log entries (Apache, Nginx, auth, Windows Event, syslog)
  2. Detect anomalies and suspicious patterns
  3. Extract IOCs (IPs, hashes, domains, user agents, usernames)
  4. Reconstruct attack timeline from log sequence
  5. Map to MITRE ATT&CK TTPs
  6. Severity-score each anomaly
"""
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from collections import Counter
import structlog

from sentinelai.core.llm_client import get_llm_client
from sentinelai.core.config import get_settings

log = structlog.get_logger()


# ── Log parsers ───────────────────────────────────────────────────────────

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

AUTH_PATTERN = re.compile(
    r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<host>\S+) '
    r'(?P<service>\S+): (?P<message>.+)'
)

SYSLOG_PATTERN = re.compile(
    r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<host>\S+) '
    r'(?P<process>[^\[]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.+)'
)

# Suspicious indicators to flag immediately
SUSPICIOUS_PATTERNS = {
    "sql_injection":     re.compile(r"(union\s+select|drop\s+table|1=1|'or'|xp_cmdshell)", re.I),
    "xss_attempt":       re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I),
    "path_traversal":    re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I),
    "command_injection": re.compile(r"(;ls|;cat|;id|;pwd|\|cmd|&&cmd)", re.I),
    "scanner_ua":        re.compile(r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|hydra|nessus)", re.I),
    "brute_force":       re.compile(r"(failed password|authentication failure|invalid user)", re.I),
    "privilege_escalation": re.compile(r"(sudo|su -|passwd|shadow|wheel)", re.I),
    "lateral_movement":  re.compile(r"(psexec|wmic|winrm|mstsc|rdp)", re.I),
}


class LogAnalyser:
    """
    Blue team log analysis engine.
    Parses raw logs, detects threats, extracts IOCs, and generates
    LLM-powered threat analysis with MITRE ATT&CK mapping.
    """

    def __init__(self):
        self.llm = get_llm_client()
        self.settings = get_settings()

    # ── Log ingestion ──────────────────────────────────────────────────────

    def ingest_log_file(self, filepath: str) -> dict:
        """
        Read and parse a log file.
        Auto-detects log type from filename and content.
        """
        path = Path(filepath)
        if not path.exists():
            return {"error": f"File not found: {filepath}"}

        log.info("Ingesting log file", filepath=filepath)

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Limit to configured max
        max_lines = self.settings.max_log_lines_per_analysis
        truncated = len(lines) > max_lines
        lines = lines[:max_lines]

        # Auto-detect log type
        log_type = self._detect_log_type(filepath, lines[:10])

        # Parse entries
        parsed = []
        for i, line in enumerate(lines):
            entry = self._parse_line(line.strip(), log_type, i + 1)
            if entry:
                parsed.append(entry)

        log.info("Log ingestion complete",
                 lines_read=len(lines),
                 parsed=len(parsed),
                 log_type=log_type,
                 truncated=truncated)

        return {
            "filepath":    filepath,
            "log_type":    log_type,
            "total_lines": len(lines),
            "parsed_count": len(parsed),
            "truncated":   truncated,
            "entries":     parsed
        }

    def ingest_log_text(self, text: str, log_type: str = "generic") -> dict:
        """Ingest log content directly as a string (for API use)."""
        lines = text.strip().split("\n")
        max_lines = self.settings.max_log_lines_per_analysis
        truncated = len(lines) > max_lines
        lines = lines[:max_lines]

        parsed = []
        for i, line in enumerate(lines):
            entry = self._parse_line(line.strip(), log_type, i + 1)
            if entry:
                parsed.append(entry)

        return {
            "log_type":    log_type,
            "total_lines": len(lines),
            "parsed_count": len(parsed),
            "truncated":   truncated,
            "entries":     parsed
        }

    # ── Anomaly detection ──────────────────────────────────────────────────

    def detect_anomalies(self, log_data: dict) -> dict:
        """
        Rule-based anomaly detection on parsed log entries.
        Runs before LLM analysis to pre-filter and highlight suspicious items.
        """
        entries  = log_data.get("entries", [])
        log_type = log_data.get("log_type", "generic")

        anomalies  = []
        ip_counts  = Counter()
        status_counts = Counter()
        suspicious_ips = set()

        for entry in entries:
            raw = entry.get("raw", "")
            ip  = entry.get("ip", "")
            if ip:
                ip_counts[ip] += 1

            status = entry.get("status")
            if status:
                status_counts[str(status)] += 1

            # Check against suspicious patterns
            for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(raw):
                    anomaly = {
                        "line_number":  entry.get("line_number"),
                        "type":         pattern_name,
                        "severity":     self._pattern_severity(pattern_name),
                        "raw_entry":    raw[:300],
                        "ip":           ip,
                        "timestamp":    entry.get("timestamp"),
                        "mitre_ttp":    self._pattern_to_mitre(pattern_name)
                    }
                    anomalies.append(anomaly)
                    if ip:
                        suspicious_ips.add(ip)

        # Detect brute force (>20 failed attempts from same IP)
        if log_type in ("auth", "apache", "nginx"):
            for ip, count in ip_counts.items():
                if count > 20:
                    anomalies.append({
                        "type":     "potential_brute_force",
                        "severity": "high",
                        "ip":       ip,
                        "count":    count,
                        "mitre_ttp": "T1110 — Brute Force"
                    })
                    suspicious_ips.add(ip)

        # Detect scanning (many 404s from same IP)
        if log_type in ("apache", "nginx"):
            for entry in entries:
                if str(entry.get("status")) in ("404", "403"):
                    ip = entry.get("ip", "")
                    if ip:
                        suspicious_ips.add(ip)

        log.info("Anomaly detection complete",
                 anomalies=len(anomalies),
                 suspicious_ips=len(suspicious_ips))

        return {
            "anomaly_count":  len(anomalies),
            "anomalies":      anomalies,
            "ip_frequency":   dict(ip_counts.most_common(20)),
            "status_counts":  dict(status_counts),
            "suspicious_ips": list(suspicious_ips),
            "top_threats":    self._rank_threats(anomalies)
        }

    # ── IOC extraction ─────────────────────────────────────────────────────

    def extract_iocs(self, log_text: str) -> dict:
        """
        Extract Indicators of Compromise from log text.
        Uses regex for speed, then LLM for context-aware enrichment.
        """
        iocs = {
            "ips":        list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_text))),
            "domains":    list(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', log_text))),
            "file_hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', log_text))),
            "urls":       list(set(re.findall(r'https?://[^\s"\'<>]+', log_text))),
            "emails":     list(set(re.findall(r'\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b', log_text))),
            "user_agents": list(set(re.findall(r'"[^"]{20,300}"(?:\s|$)', log_text)))[:10]
        }

        # Filter out common false positives
        iocs["ips"] = [
            ip for ip in iocs["ips"]
            if not ip.startswith(("127.", "0.", "255."))
        ][:50]

        return iocs

    # ── LLM threat analysis ────────────────────────────────────────────────

    async def analyse_with_llm(
        self,
        log_data: dict,
        anomaly_data: dict,
        iocs: dict,
        context: Optional[str] = None
    ) -> str:
        """
        Core LLM analysis — Claude acts as a threat hunter reviewing the logs.
        Correlates anomalies, builds attack timeline, maps to MITRE ATT&CK.
        """
        log.info("Starting LLM log analysis")

        # Build a representative sample of anomalous log lines
        sample_anomalies = anomaly_data.get("anomalies", [])[:30]
        top_ips = list(anomaly_data.get("ip_frequency", {}).items())[:10]

        prompt = f"""You are a threat hunter performing incident response.
Analyse the following security log data and provide a comprehensive threat assessment.

## Log Source Information
- Log type: {log_data.get('log_type', 'unknown')}
- Total lines analysed: {log_data.get('total_lines', 0)}
- Anomalies detected: {anomaly_data.get('anomaly_count', 0)}

## Pre-detected Anomalies (rule-based)
{json.dumps(sample_anomalies[:15], indent=2, default=str)}

## IP Frequency Analysis (top 10)
{json.dumps(top_ips, indent=2)}

## Extracted IOCs
- Suspicious IPs: {iocs.get('ips', [])[:20]}
- Suspicious domains: {iocs.get('domains', [])[:10]}
- File hashes: {iocs.get('file_hashes', [])[:5]}

## Sample Log Entries (most suspicious)
{self._format_sample_entries(log_data.get('entries', []), anomaly_data)}

{f"## Additional Context{chr(10)}{context}" if context else ""}

## Required Analysis

### 1. Threat Summary
- Is this an active attack, historical attack, or routine noise?
- Attack stage (Reconnaissance / Initial Access / Execution / Persistence / etc.)
- Overall severity: Critical / High / Medium / Low

### 2. Attack Timeline Reconstruction
Reconstruct the sequence of events in chronological order:
[Timestamp] — [Event] — [Significance]

### 3. MITRE ATT&CK TTP Mapping
For each identified technique:
| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|

### 4. Threat Actor Assessment
- Sophistication level (Nation State / Organized Crime / Script Kiddie / Insider)
- Likely motivation (Financial / Espionage / Disruption / Unknown)
- Indicators suggesting this assessment

### 5. IOC Confidence Assessment
Rate each IOC type (High/Medium/Low confidence):
- Which IPs are confirmed malicious vs noisy
- Which patterns indicate actual compromise vs scanning

### 6. Immediate Response Actions (priority ordered)
What should the SOC do in the next 60 minutes?

### 7. Containment Recommendations
Specific firewall rules, account locks, or system isolations recommended."""

        return await self.llm.complete(
            prompt=prompt,
            system=self.llm.log_analyst_system(),
            max_tokens=4000
        )

    # ── Full log analysis workflow ─────────────────────────────────────────

    async def run_full_analysis(
        self,
        log_source: str,
        log_content: Optional[str] = None,
        log_filepath: Optional[str] = None,
        context: Optional[str] = None
    ) -> dict:
        """
        Complete log analysis pipeline:
        Ingest → Parse → Anomaly detection → IOC extraction → LLM analysis
        """
        log.info("Starting full log analysis", source=log_source)

        results = {
            "log_source":    log_source,
            "started_at":    datetime.utcnow().isoformat(),
            "log_data":      {},
            "anomalies":     {},
            "iocs":          {},
            "llm_analysis":  "",
            "completed_at":  None
        }

        # Step 1: Ingest
        if log_filepath:
            results["log_data"] = self.ingest_log_file(log_filepath)
        elif log_content:
            log_type = self._detect_log_type(log_source, log_content.split("\n")[:5])
            results["log_data"] = self.ingest_log_text(log_content, log_type)
        else:
            results["error"] = "No log content provided"
            return results

        # Step 2: Rule-based anomaly detection
        results["anomalies"] = self.detect_anomalies(results["log_data"])

        # Step 3: IOC extraction
        raw_text = log_content or ""
        if log_filepath:
            with open(log_filepath, "r", errors="replace") as f:
                raw_text = f.read()[:100000]  # 100KB max for IOC extraction
        results["iocs"] = self.extract_iocs(raw_text)

        # Step 4: LLM threat analysis
        results["llm_analysis"] = await self.analyse_with_llm(
            results["log_data"],
            results["anomalies"],
            results["iocs"],
            context
        )

        results["completed_at"] = datetime.utcnow().isoformat()
        log.info("Log analysis complete",
                 anomalies=results["anomalies"].get("anomaly_count", 0))

        return results

    # ── Private helpers ────────────────────────────────────────────────────

    def _detect_log_type(self, source: str, sample_lines: list) -> str:
        source_lower = source.lower()
        if any(x in source_lower for x in ("apache", "access.log", "httpd")):
            return "apache"
        if "nginx" in source_lower:
            return "nginx"
        if any(x in source_lower for x in ("auth", "secure", "sshd")):
            return "auth"
        if "syslog" in source_lower or "messages" in source_lower:
            return "syslog"
        if "windows" in source_lower or "event" in source_lower:
            return "windows_event"

        # Detect from content
        sample = " ".join(sample_lines[:5])
        if APACHE_PATTERN.search(sample):
            return "apache"
        if AUTH_PATTERN.search(sample):
            return "auth"
        return "generic"

    def _parse_line(self, line: str, log_type: str, line_number: int) -> Optional[dict]:
        if not line or line.startswith("#"):
            return None

        entry = {"line_number": line_number, "raw": line, "log_type": log_type}

        if log_type in ("apache", "nginx"):
            m = APACHE_PATTERN.match(line)
            if m:
                entry.update({
                    "ip":        m.group("ip"),
                    "timestamp": m.group("time"),
                    "method":    m.group("method"),
                    "path":      m.group("path"),
                    "status":    int(m.group("status")),
                    "size":      m.group("size"),
                    "ua":        m.group("ua") if m.lastindex and m.lastindex >= 8 else ""
                })

        elif log_type == "auth":
            m = AUTH_PATTERN.match(line)
            if m:
                entry.update({
                    "timestamp": m.group("timestamp"),
                    "host":      m.group("host"),
                    "service":   m.group("service"),
                    "message":   m.group("message")
                })
                # Extract IP from auth message
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    entry["ip"] = ip_match.group(1)

        return entry

    def _pattern_severity(self, pattern_name: str) -> str:
        high = {"sql_injection", "command_injection", "privilege_escalation", "lateral_movement"}
        medium = {"xss_attempt", "path_traversal", "brute_force"}
        return "high" if pattern_name in high else "medium" if pattern_name in medium else "low"

    def _pattern_to_mitre(self, pattern_name: str) -> str:
        mapping = {
            "sql_injection":        "T1190 — Exploit Public-Facing Application",
            "xss_attempt":          "T1059.007 — JavaScript",
            "path_traversal":       "T1083 — File and Directory Discovery",
            "command_injection":    "T1059 — Command and Scripting Interpreter",
            "scanner_ua":           "T1595 — Active Scanning",
            "brute_force":          "T1110 — Brute Force",
            "privilege_escalation": "T1078 — Valid Accounts",
            "lateral_movement":     "T1021 — Remote Services"
        }
        return mapping.get(pattern_name, "Unknown")

    def _rank_threats(self, anomalies: list) -> list:
        severity_rank = {"high": 3, "medium": 2, "low": 1}
        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: severity_rank.get(x.get("severity", "low"), 0),
            reverse=True
        )
        return sorted_anomalies[:5]

    def _format_sample_entries(self, entries: list, anomaly_data: dict) -> str:
        suspicious_lines = {
            a.get("line_number") for a in anomaly_data.get("anomalies", [])
        }
        samples = [
            e["raw"] for e in entries
            if e.get("line_number") in suspicious_lines
        ][:20]
        return "\n".join(samples) if samples else "No suspicious entries found"
