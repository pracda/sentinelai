"""
ScanService — orchestrates all modules and persists results to DB.
"""
import uuid
from datetime import datetime
from typing import Optional
import structlog

from sentinelai.core.database import (
    Scan, Finding, LogAnalysis,
    ScanType, ScanStatus, Severity,
    get_session_factory
)
from sentinelai.core.notifier import send_alert
from sentinelai.modules.recon.engine import ReconEngine
from sentinelai.modules.vuln.analyser import VulnAnalyser
from sentinelai.modules.logs.analyser import LogAnalyser
from sentinelai.modules.mitigation.engine import MitigationEngine

log = structlog.get_logger()


class ScanService:

    async def run_recon(self, target, ports, authorized_by, api_key_name) -> str:
        scan_id = str(uuid.uuid4())
        await self._create_scan(scan_id, target, ScanType.RECON, authorized_by, api_key_name)
        try:
            engine = ReconEngine()
            results = await engine.run_full_recon(target=target, authorized_by=authorized_by, ports=ports)
            await self._complete_scan(scan_id, results, results.get("llm_analysis", ""))
        except Exception as e:
            await self._fail_scan(scan_id, str(e))
        return scan_id

    async def run_vuln(self, target, open_ports, authorized_by, api_key_name) -> str:
        scan_id = str(uuid.uuid4())
        await self._create_scan(scan_id, target, ScanType.VULN, authorized_by, api_key_name)
        try:
            analyser = VulnAnalyser()
            results = await analyser.run_full_analysis(target=target, open_ports=open_ports, authorized_by=authorized_by)
            findings = self._extract_vuln_findings(results)
            await self._save_findings(scan_id, findings)
            critical = sum(1 for f in findings if f.get("severity") == "critical")
            high = sum(1 for f in findings if f.get("severity") == "high")
            await self._complete_scan(scan_id, results, results.get("llm_assessment", ""),
                                      finding_count=len(findings), critical_count=critical, high_count=high)
        except Exception as e:
            await self._fail_scan(scan_id, str(e))
        return scan_id

    async def run_log_analysis(self, log_source, log_content, api_key_name, context=None) -> str:
        scan_id = str(uuid.uuid4())
        await self._create_scan(scan_id, log_source, ScanType.LOG_ANALYSE, "api", api_key_name)
        try:
            analyser = LogAnalyser()
            results = await analyser.run_full_analysis(
                log_source=log_source, log_content=log_content, context=context)
            anomalies = results.get("anomalies", {})
            anomaly_count = anomalies.get("anomaly_count", 0)
            await self._save_log_analysis(scan_id, log_source, results)
            findings = self._extract_log_findings(anomalies)
            await self._save_findings(scan_id, findings)
            critical = sum(1 for f in findings if f.get("severity") == "critical")
            high = sum(1 for f in findings if f.get("severity") == "high")
            await self._complete_scan(scan_id, results, results.get("llm_analysis", ""),
                                      finding_count=anomaly_count, critical_count=critical, high_count=high)
        except Exception as e:
            await self._fail_scan(scan_id, str(e))
        return scan_id

    async def run_full_scan(self, target, ports, authorized_by, api_key_name) -> str:
        scan_id = str(uuid.uuid4())
        await self._create_scan(scan_id, target, ScanType.FULL, authorized_by, api_key_name)
        try:
            combined_results = {"target": target, "scan_type": "full"}
            recon_engine = ReconEngine()
            recon_results = await recon_engine.run_full_recon(target=target, authorized_by=authorized_by, ports=ports)
            combined_results["recon"] = recon_results
            open_ports = recon_results.get("ports", {}).get("open_ports", [])
            if open_ports:
                vuln_analyser = VulnAnalyser()
                vuln_results = await vuln_analyser.run_full_analysis(
                    target=target, open_ports=open_ports, authorized_by=authorized_by)
                combined_results["vuln"] = vuln_results
                findings = self._extract_vuln_findings(vuln_results)
                await self._save_findings(scan_id, findings)
            mitigation = MitigationEngine()
            all_findings = self._extract_all_findings(combined_results)
            report_content = await mitigation.generate_mitigation_plan(
                target=target, findings=all_findings, scan_type="full")
            combined_results["mitigation_report"] = report_content
            full_analysis = "\n\n---\n\n".join(filter(None, [
                recon_results.get("llm_analysis", ""),
                combined_results.get("vuln", {}).get("llm_assessment", ""),
                report_content
            ]))
            findings_list = self._extract_all_findings(combined_results)
            critical = sum(1 for f in findings_list if f.get("severity") == "critical")
            high = sum(1 for f in findings_list if f.get("severity") == "high")
            await self._complete_scan(scan_id, combined_results, full_analysis,
                                      finding_count=len(findings_list), critical_count=critical, high_count=high)
        except Exception as e:
            await self._fail_scan(scan_id, str(e))
        return scan_id

    async def _create_scan(self, scan_id, target, scan_type, authorized_by, api_key_name):
        async with get_session_factory()() as session:
            scan = Scan(id=scan_id, target=target, scan_type=scan_type,
                        status=ScanStatus.RUNNING, authorized_by=authorized_by)
            session.add(scan)
            await session.commit()

    async def _complete_scan(self, scan_id, results, llm_analysis,
                              finding_count=0, critical_count=0, high_count=0):
        async with get_session_factory()() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.raw_results = self._sanitise_results(results)
                scan.llm_analysis = llm_analysis
                scan.summary = self._build_summary(results, finding_count)
                scan.finding_count = finding_count
                scan.critical_count = critical_count
                scan.high_count = high_count
                await session.commit()
                scan_dict = {
                    "id": scan.id,
                    "target": scan.target,
                    "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
                    "finding_count": finding_count,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "summary": scan.summary,
                }
        await send_alert(scan_dict, critical_count, high_count)

    async def _fail_scan(self, scan_id, error):
        async with get_session_factory()() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                scan.error = error[:500]
                await session.commit()

    async def _save_findings(self, scan_id, findings):
        if not findings:
            return
        async with get_session_factory()() as session:
            for f in findings[:50]:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    title=f.get("title", "Untitled")[:500],
                    description=f.get("description", "")[:2000],
                    severity=self._parse_severity(f.get("severity", "info")),
                    cvss_score=f.get("cvss_score"),
                    cve_id=f.get("cve_id"),
                    mitre_attack=f.get("mitre_attack"),
                    evidence=f.get("evidence", "")[:1000],
                    remediation=f.get("remediation", "")[:2000],
                )
                session.add(finding)
            await session.commit()

    async def _save_log_analysis(self, scan_id, log_source, results):
        async with get_session_factory()() as session:
            log_data = results.get("log_data", {})
            anomalies = results.get("anomalies", {})
            iocs = results.get("iocs", {})
            record = LogAnalysis(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                log_source=log_source,
                log_type=log_data.get("log_type", "unknown"),
                lines_analysed=log_data.get("total_lines", 0),
                anomalies_found=anomalies.get("anomaly_count", 0),
                iocs_extracted=iocs,
                llm_analysis=results.get("llm_analysis", "")
            )
            session.add(record)
            await session.commit()

    def _sanitise_results(self, results):
        import json
        try:
            json.dumps(results)
            return results
        except (TypeError, ValueError):
            return {"error": "Results not serialisable", "target": results.get("target")}

    def _parse_severity(self, sev):
        mapping = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW}
        return mapping.get(sev.lower(), Severity.INFO)

    def _build_summary(self, results, finding_count):
        target = results.get("target", "unknown")
        return f"Scan of {target} completed. {finding_count} findings identified."

    def _extract_vuln_findings(self, results):
        findings = []
        for cve in results.get("all_cves", [])[:20]:
            findings.append({
                "title": f"{cve.get('cve_id','CVE')} — {cve.get('description','')[:80]}",
                "description": cve.get("description", ""),
                "severity": cve.get("severity", "medium"),
                "cvss_score": cve.get("cvss_score"),
                "cve_id": cve.get("cve_id"),
                "evidence": "Detected via NVD CVE lookup",
                "remediation": "Apply vendor patch and update service version",
            })
        return findings

    def _extract_log_findings(self, anomalies):
        findings = []
        for anomaly in anomalies.get("anomalies", []):
            findings.append({
                "title": f"Log anomaly: {anomaly.get('type','unknown')}",
                "description": f"Detected pattern: {anomaly.get('type')}",
                "severity": anomaly.get("severity", "medium"),
                "evidence": anomaly.get("raw_entry", "")[:500],
                "mitre_attack": anomaly.get("mitre_ttp"),
                "remediation": "Investigate source IP and block if confirmed malicious",
            })
        return findings

    def _extract_all_findings(self, results):
        findings = []
        if "vuln" in results:
            findings.extend(self._extract_vuln_findings(results["vuln"]))
        return findings
