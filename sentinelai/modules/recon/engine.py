"""
Module 1: Reconnaissance Engine (Red Team)

Performs automated target profiling:
  1. DNS enumeration — subdomains, MX, NS, TXT records
  2. Port scanning — open ports and service versions (via nmap)
  3. Service fingerprinting — OS detection, banner grabbing
  4. LLM attack surface analysis — Claude interprets the findings

⚠️  Only scan targets you own or have explicit written authorization to scan.
"""
import socket
import asyncio
from datetime import datetime
from typing import Optional
import structlog

from sentinelai.core.llm_client import get_llm_client
from sentinelai.core.config import get_settings

log = structlog.get_logger()


class ReconEngine:
    """
    Reconnaissance engine for authorized target profiling.
    Combines traditional recon tools with LLM-powered analysis.
    """

    def __init__(self):
        self.llm = get_llm_client()
        self.settings = get_settings()

    # ── DNS Enumeration ────────────────────────────────────────────────────

    async def enumerate_dns(self, target: str) -> dict:
        """
        Enumerate DNS records for a target domain.
        Returns A, AAAA, MX, NS, TXT, CNAME records.
        """
        log.info("Starting DNS enumeration", target=target)
        results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "records": {},
            "subdomains": [],
            "errors": []
        }

        try:
            import dns.resolver
            import dns.exception

            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            # Query common record types
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
            for rtype in record_types:
                try:
                    answers = resolver.resolve(target, rtype)
                    results["records"][rtype] = [str(r) for r in answers]
                    log.debug(f"DNS {rtype} records found", count=len(answers))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                except dns.exception.DNSException as e:
                    results["errors"].append(f"{rtype}: {str(e)}")

            # Common subdomain enumeration
            common_subdomains = [
                "www", "mail", "ftp", "admin", "api", "dev", "staging",
                "vpn", "remote", "portal", "app", "secure", "login",
                "dashboard", "backend", "internal", "corp", "support"
            ]

            for sub in common_subdomains:
                fqdn = f"{sub}.{target}"
                try:
                    answers = resolver.resolve(fqdn, "A")
                    results["subdomains"].append({
                        "subdomain": fqdn,
                        "ips": [str(r) for r in answers]
                    })
                except Exception:
                    pass

        except ImportError:
            results["errors"].append("dnspython not installed — run: pip install dnspython")

        log.info("DNS enumeration complete",
                 record_types=len(results["records"]),
                 subdomains=len(results["subdomains"]))
        return results

    # ── Port Scanning ──────────────────────────────────────────────────────

    async def port_scan(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "basic"
    ) -> dict:
        """
        Scan target for open ports and service versions.

        Args:
            target: IP address or hostname
            ports: Port range (e.g. "1-1024", "80,443,8080", "1-65535")
            scan_type: "basic" (TCP connect) or "version" (service detection)
        """
        log.info("Starting port scan", target=target, ports=ports)

        results = {
            "target": target,
            "ports": ports,
            "timestamp": datetime.utcnow().isoformat(),
            "open_ports": [],
            "os_detection": None,
            "scan_summary": {},
            "error": None
        }

        try:
            import nmap

            nm = nmap.PortScanner()

            # Resolve hostname to IP first
            try:
                ip = socket.gethostbyname(target)
                results["resolved_ip"] = ip
            except socket.gaierror:
                results["error"] = f"Could not resolve hostname: {target}"
                return results

            # Run nmap scan
            # -sV: service version detection
            # -T4: aggressive timing (faster)
            # --open: only show open ports
            scan_args = "-sV -T4 --open" if scan_type == "version" else "-T4 --open"

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: nm.scan(ip, ports, arguments=scan_args)
            )

            # Parse results
            if ip in nm.all_hosts():
                host = nm[ip]
                results["scan_summary"] = {
                    "state": host.state(),
                    "hostname": host.hostname()
                }

                for protocol in host.all_protocols():
                    port_list = sorted(host[protocol].keys())
                    for port in port_list:
                        port_info = host[protocol][port]
                        if port_info["state"] == "open":
                            results["open_ports"].append({
                                "port": port,
                                "protocol": protocol,
                                "state": port_info["state"],
                                "service": port_info.get("name", "unknown"),
                                "version": port_info.get("version", ""),
                                "product": port_info.get("product", ""),
                                "extra_info": port_info.get("extrainfo", "")
                            })

        except ImportError:
            results["error"] = "python-nmap not installed — run: pip install python-nmap"
        except Exception as e:
            results["error"] = str(e)
            log.error("Port scan error", error=str(e))

        log.info("Port scan complete", open_ports=len(results["open_ports"]))
        return results

    # ── LLM Attack Surface Analysis ────────────────────────────────────────

    async def analyse_attack_surface(
        self,
        dns_results: dict,
        port_results: dict,
        target: str
    ) -> str:
        """
        Feed reconnaissance data to Claude for expert attack surface analysis.

        This is where the LLM adds real value — interpreting raw scan data
        to identify the most likely attack vectors and prioritise them.
        """
        log.info("Starting LLM attack surface analysis", target=target)

        prompt = f"""Perform a comprehensive attack surface analysis for target: {target}

## DNS Reconnaissance Results
Records found: {dns_results.get('records', {})}
Subdomains discovered: {dns_results.get('subdomains', [])}

## Port Scan Results
Open ports: {port_results.get('open_ports', [])}
Total open ports: {len(port_results.get('open_ports', []))}

## Analysis Required

Please provide:

### 1. Attack Surface Summary
- Estimated exposure level (Critical/High/Medium/Low)
- Most significant findings

### 2. High-Value Attack Vectors
For each significant finding, provide:
- Attack vector description
- MITRE ATT&CK technique (e.g. T1190 — Exploit Public-Facing Application)
- Likelihood of successful exploitation (High/Medium/Low)
- Potential impact if exploited

### 3. Service Risk Assessment
Assess each open port/service for:
- Known vulnerabilities for this service
- Misconfigurations to investigate
- Recommended follow-up checks

### 4. Recommended Penetration Testing Priorities
List the top 5 specific areas to investigate next, in priority order.

### 5. Defensive Recommendations
What should the target organisation do to reduce this attack surface?

Be specific and technical. Reference CVEs where relevant."""

        analysis = await self.llm.complete(
            prompt=prompt,
            system=self.llm.vuln_analyst_system(),
            max_tokens=3000
        )

        return analysis

    # ── Full Recon Workflow ────────────────────────────────────────────────

    async def run_full_recon(
        self,
        target: str,
        authorized_by: str,
        ports: str = "1-1024"
    ) -> dict:
        """
        Run the complete reconnaissance workflow:
        DNS enum → Port scan → LLM analysis → Structured report

        Args:
            target: Domain or IP to scan
            authorized_by: Name/email of person who authorized the scan
            ports: Port range to scan
        """
        log.info("Starting full recon", target=target, authorized_by=authorized_by)

        results = {
            "target": target,
            "authorized_by": authorized_by,
            "started_at": datetime.utcnow().isoformat(),
            "dns": {},
            "ports": {},
            "llm_analysis": "",
            "completed_at": None
        }

        # Step 1: DNS enumeration
        results["dns"] = await self.enumerate_dns(target)

        # Step 2: Port scan
        results["ports"] = await self.port_scan(target, ports, scan_type="version")

        # Step 3: LLM attack surface analysis
        results["llm_analysis"] = await self.analyse_attack_surface(
            results["dns"],
            results["ports"],
            target
        )

        results["completed_at"] = datetime.utcnow().isoformat()
        log.info("Full recon complete", target=target)

        return results
