"""
Alert notifications for SentinelAI.
Supports Slack webhooks and SMTP email. Both are opt-in via env vars.
"""
import asyncio
import smtplib
import json
from email.message import EmailMessage
from typing import Optional
import httpx
import structlog

from sentinelai.core.config import get_settings

log = structlog.get_logger()


def _should_alert(critical_count: int, high_count: int) -> bool:
    settings = get_settings()
    level = settings.alert_min_severity.lower()
    if level == "critical":
        return critical_count > 0
    if level == "high":
        return critical_count > 0 or high_count > 0
    if level == "any":
        return True
    return critical_count > 0


def _build_message(scan: dict) -> tuple[str, str]:
    """Returns (subject, body) for the alert."""
    target = scan.get("target", "unknown")
    scan_type = scan.get("scan_type", "scan")
    total = scan.get("finding_count", 0)
    critical = scan.get("critical_count", 0)
    high = scan.get("high_count", 0)
    scan_id = scan.get("id", "")
    summary = scan.get("summary", "")

    subject = f"[SentinelAI] {critical} critical finding(s) on {target}"
    body = (
        f"SentinelAI alert — {scan_type} scan completed\n\n"
        f"Target:   {target}\n"
        f"Findings: {total} total  |  {critical} critical  |  {high} high\n"
        f"Scan ID:  {scan_id}\n"
        f"Summary:  {summary}\n"
    )
    return subject, body


async def _send_slack(scan: dict) -> None:
    settings = get_settings()
    if not settings.slack_webhook_url:
        return

    target = scan.get("target", "unknown")
    critical = scan.get("critical_count", 0)
    high = scan.get("high_count", 0)
    total = scan.get("finding_count", 0)
    scan_type = scan.get("scan_type", "scan")
    scan_id = scan.get("id", "")

    color = "#E24B4A" if critical > 0 else "#F59E0B"
    payload = {
        "attachments": [{
            "color": color,
            "title": f":rotating_light: SentinelAI — {critical} critical finding(s) on `{target}`",
            "fields": [
                {"title": "Scan type", "value": scan_type, "short": True},
                {"title": "Total findings", "value": str(total), "short": True},
                {"title": "Critical", "value": str(critical), "short": True},
                {"title": "High", "value": str(high), "short": True},
                {"title": "Scan ID", "value": scan_id[:8], "short": True},
            ],
            "footer": "SentinelAI",
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                settings.slack_webhook_url,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
        log.info("Slack alert sent", target=target)
    except Exception as e:
        log.warning("Slack alert failed", error=str(e))


def _send_email_sync(subject: str, body: str) -> None:
    settings = get_settings()
    if not all([settings.smtp_host, settings.alert_email_to, settings.smtp_user, settings.smtp_password]):
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = settings.alert_email_to
    msg.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
            smtp.starttls()
            smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        log.info("Email alert sent", to=settings.alert_email_to)
    except Exception as e:
        log.warning("Email alert failed", error=str(e))


async def send_alert(scan: dict, critical_count: int, high_count: int) -> None:
    """Fire-and-forget alert. Call after a scan completes."""
    if not _should_alert(critical_count, high_count):
        return

    subject, body = _build_message(scan)

    await _send_slack(scan)

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_email_sync, subject, body)


async def send_watchlist_alert(entry: dict, scan_id: str, matched_findings: list) -> None:
    """Notify when a watched service appears in scan findings."""
    settings = get_settings()
    service = entry.get("service_name", "unknown")
    min_sev = entry.get("min_severity", "high")
    count = len(matched_findings)
    titles = "\n".join(f"  - [{f.get('severity','?').upper()}] {f.get('title','?')}"
                       for f in matched_findings)

    subject = f"[SentinelAI] Watchlist hit: '{service}' found in scan"
    body = (
        f"SentinelAI watchlist alert\n\n"
        f"Watched service: {service}  (min severity: {min_sev})\n"
        f"Scan ID:         {scan_id}\n"
        f"Matched findings ({count}):\n{titles}\n"
    )

    # Slack
    if settings.slack_webhook_url:
        payload = {
            "attachments": [{
                "color": "#F59E0B",
                "title": f":bell: Watchlist hit — `{service}` detected",
                "fields": [
                    {"title": "Matches", "value": str(count), "short": True},
                    {"title": "Min severity", "value": min_sev, "short": True},
                    {"title": "Scan ID", "value": scan_id[:8], "short": True},
                ],
                "text": titles,
                "footer": "SentinelAI watchlist",
            }]
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    settings.slack_webhook_url,
                    content=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                r.raise_for_status()
            log.info("Watchlist Slack alert sent", service=service)
        except Exception as e:
            log.warning("Watchlist Slack alert failed", error=str(e))

    # Email
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_email_sync, subject, body)
