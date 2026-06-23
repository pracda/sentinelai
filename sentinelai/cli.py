"""
SentinelAI Command Line Interface

Usage:
    python -m sentinelai scan --target example.com --mode recon
    python -m sentinelai analyse --logs ./sample_logs/apache.log
    python -m sentinelai report --scan-id <id> --format pdf
    python -m sentinelai demo
"""
import asyncio
import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich import print as rprint

app    = typer.Typer(help="SentinelAI — LLM-Powered Security Operations Platform")
console = Console()


def banner():
    console.print(Panel.fit(
        "[bold blue]SentinelAI[/] — LLM-Powered Security Operations\n"
        "[dim]Red team + Blue team automation with Claude AI[/]",
        border_style="blue"
    ))


@app.command()
def scan(
    target: str = typer.Option(..., help="Target domain or IP (e.g. example.com)"),
    mode: str = typer.Option("recon", help="Scan mode: recon, vuln, full"),
    ports: str = typer.Option("1-1024", help="Port range to scan"),
    authorized_by: str = typer.Option(..., help="Your email (authorization confirmation)"),
    output: str = typer.Option("markdown", help="Output format: markdown, json")
):
    """
    Run a security scan against an authorized target.

    ⚠️  Only scan targets you own or have explicit written permission to test.
    """
    banner()

    console.print(f"\n[yellow]⚠️  Authorization check[/]")
    console.print(f"You are about to scan: [bold]{target}[/]")
    console.print(f"Authorized by: [bold]{authorized_by}[/]\n")

    confirm = typer.confirm("Do you confirm you have authorization to scan this target?")
    if not confirm:
        console.print("[red]Scan cancelled — authorization not confirmed[/]")
        raise typer.Abort()

    async def _run():
        from sentinelai.modules.recon.engine import ReconEngine
        from sentinelai.modules.vuln.analyser import VulnAnalyser

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            results = {}

            if mode in ("recon", "full"):
                task = progress.add_task("[cyan]Running reconnaissance...", total=None)
                engine = ReconEngine()
                recon_results = await engine.run_full_recon(
                    target=target,
                    authorized_by=authorized_by,
                    ports=ports
                )
                results["recon"] = recon_results
                progress.update(task, description="[green]✓ Reconnaissance complete")

                # Print DNS results
                dns = recon_results.get("dns", {})
                table = Table(title="DNS Records")
                table.add_column("Type", style="cyan")
                table.add_column("Records")
                for rtype, records in dns.get("records", {}).items():
                    table.add_row(rtype, ", ".join(records[:3]))
                console.print(table)

                # Print open ports
                ports_found = recon_results.get("ports", {}).get("open_ports", [])
                if ports_found:
                    port_table = Table(title=f"Open Ports ({len(ports_found)} found)")
                    port_table.add_column("Port", style="red")
                    port_table.add_column("Service")
                    port_table.add_column("Version")
                    for p in ports_found[:20]:
                        port_table.add_row(
                            str(p.get("port")),
                            p.get("service", ""),
                            f"{p.get('product','')} {p.get('version','')}".strip()
                        )
                    console.print(port_table)

                progress.remove_task(task)

            if mode in ("vuln", "full") and results.get("recon"):
                task = progress.add_task("[cyan]Analysing vulnerabilities...", total=None)
                vuln_engine = VulnAnalyser()
                open_ports  = results["recon"].get("ports", {}).get("open_ports", [])
                vuln_results = await vuln_engine.run_full_analysis(
                    target=target,
                    open_ports=open_ports,
                    authorized_by=authorized_by
                )
                results["vuln"] = vuln_results
                progress.update(task, description="[green]✓ Vulnerability analysis complete")
                progress.remove_task(task)

                console.print(f"\n[red]CVEs found:[/] {vuln_results.get('finding_count', 0)}")

        # Print LLM analysis
        if mode == "recon" and "recon" in results:
            analysis = results["recon"].get("llm_analysis", "")
        else:
            analysis = results.get("vuln", {}).get("llm_assessment", "")

        if analysis:
            console.print("\n[bold blue]LLM Security Analysis[/]")
            console.print(Markdown(analysis))

        if output == "json":
            print(json.dumps(results, indent=2, default=str))

    asyncio.run(_run())


@app.command()
def analyse(
    logs: str = typer.Option(..., help="Path to log file"),
    context: Optional[str] = typer.Option(None, help="Additional environment context")
):
    """
    Analyse a security log file for threats and IOCs.
    Supports: Apache, Nginx, auth logs, syslog.
    """
    banner()

    if not Path(logs).exists():
        console.print(f"[red]File not found: {logs}[/]")
        raise typer.Exit(1)

    async def _run():
        from sentinelai.modules.logs.analyser import LogAnalyser

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
            task = p.add_task("[cyan]Analysing logs...", total=None)
            analyser = LogAnalyser()
            results  = await analyser.run_full_analysis(
                log_source=logs,
                log_filepath=logs,
                context=context
            )
            p.update(task, description="[green]✓ Analysis complete")

        anomalies = results.get("anomalies", {})
        console.print(f"\n[bold]Anomalies detected:[/] {anomalies.get('anomaly_count', 0)}")
        console.print(f"[bold]Suspicious IPs:[/] {len(anomalies.get('suspicious_ips', []))}")

        iocs = results.get("iocs", {})
        console.print(f"[bold]IOCs extracted:[/] {sum(len(v) for v in iocs.values())}")

        console.print("\n[bold blue]Threat Analysis[/]")
        console.print(Markdown(results.get("llm_analysis", "No analysis available")))

    asyncio.run(_run())


@app.command()
def demo():
    """
    Run a demonstration with sample log data (no real scanning).
    Uses pre-loaded sample logs to show LLM analysis capabilities.
    """
    banner()
    console.print("\n[cyan]Running demo with sample Apache logs...[/]\n")

    sample_log = """192.168.1.100 - - [22/Jun/2026:14:32:01 +0000] "GET /admin/login HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.5 - - [22/Jun/2026:14:32:15 +0000] "GET /index.php?id=1 UNION SELECT * FROM users-- HTTP/1.1" 500 892 "-" "sqlmap/1.7"
10.0.0.5 - - [22/Jun/2026:14:32:16 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 892 "-" "sqlmap/1.7"
10.0.0.5 - - [22/Jun/2026:14:32:17 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 512 "-" "Nikto/2.1.6"
203.0.113.42 - - [22/Jun/2026:14:33:00 +0000] "POST /wp-login.php HTTP/1.1" 401 892 "-" "python-requests/2.28"
203.0.113.42 - - [22/Jun/2026:14:33:01 +0000] "POST /wp-login.php HTTP/1.1" 401 892 "-" "python-requests/2.28"
203.0.113.42 - - [22/Jun/2026:14:33:02 +0000] "POST /wp-login.php HTTP/1.1" 401 892 "-" "python-requests/2.28"
203.0.113.42 - - [22/Jun/2026:14:33:03 +0000] "POST /wp-login.php HTTP/1.1" 200 1456 "-" "python-requests/2.28"
192.168.1.1 - - [22/Jun/2026:14:35:00 +0000] "GET /shell.php HTTP/1.1" 200 234 "-" "curl/7.81.0"
192.168.1.1 - - [22/Jun/2026:14:35:05 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 89 "-" "curl/7.81.0"
192.168.1.1 - - [22/Jun/2026:14:35:10 +0000] "GET /shell.php?cmd=cat+/etc/shadow HTTP/1.1" 200 1234 "-" "curl/7.81.0"
"""

    async def _run():
        from sentinelai.modules.logs.analyser import LogAnalyser
        analyser = LogAnalyser()
        results  = await analyser.run_full_analysis(
            log_source="demo_apache.log",
            log_content=sample_log
        )

        anomalies = results.get("anomalies", {})
        console.print(Panel(
            f"[red]Anomalies: {anomalies.get('anomaly_count', 0)}[/]\n"
            f"[yellow]Suspicious IPs: {', '.join(anomalies.get('suspicious_ips', []))}[/]\n"
            f"[cyan]Top threats: {[t.get('type') for t in anomalies.get('top_threats', [])]}[/]",
            title="Pre-analysis results",
            border_style="red"
        ))

        console.print("\n[bold blue]LLM Threat Analysis[/]")
        console.print(Markdown(results.get("llm_analysis", "No analysis — check API key")))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
