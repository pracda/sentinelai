"""
Alert notifier — fires email or webhook when scan events match user-defined rules.
Triggers: scan_complete, critical_finding, brute_force, high_finding
"""
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import httpx
import structlog

from sentinelai.core.config import get_settings

log = structlog.get_logger()


async def _send_email(to: str, subject: str, body: str):
    s = get_settings()
    if not all([s.smtp_host, s.smtp_user, s.smtp_password, s.smtp_from]):
        log.warning("SMTP not configured — skipping email alert")
        return
    try:
        import aiosmtplib
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = s.smtp_from
        msg["To"]      = to
        msg.attach(MIMEText(body, "html"))
        await aiosmtplib.send(
            msg,
            hostname=s.smtp_host,
            port=s.smtp_port,
            username=s.smtp_user,
            password=s.smtp_password,
            start_tls=True,
        )
        log.info("Alert email sent", to=to, subject=subject)
    except Exception as e:
        log.error("Failed to send alert email", error=str(e))


async def _send_webhook(url: str, payload: dict):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, json=payload)
        log.info("Alert webhook sent", url=url)
    except Exception as e:
        log.error("Failed to send alert webhook", error=str(e))


def _build_email_body(trigger: str, context: dict) -> tuple[str, str]:
    scan_id  = context.get("scan_id", "N/A")
    target   = context.get("target", "N/A")
    severity = context.get("severity", "")
    count    = context.get("finding_count", 0)

    subject = f"[SentinelAI] {trigger.replace('_', ' ').title()} — {target}"
    body = f"""
<html><body style="font-family:sans-serif;color:#1a2744;padding:20px">
<h2 style="color:#dc2626">⚠ SentinelAI Alert: {trigger.replace('_',' ').title()}</h2>
<table style="border-collapse:collapse;width:100%;max-width:560px">
  <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:bold">Trigger</td>
      <td style="padding:6px 12px">{trigger}</td></tr>
  <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:bold">Target</td>
      <td style="padding:6px 12px">{target}</td></tr>
  <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:bold">Scan ID</td>
      <td style="padding:6px 12px;font-family:monospace">{scan_id}</td></tr>
  {"<tr><td style='padding:6px 12px;background:#f9fafb;font-weight:bold'>Severity</td><td style='padding:6px 12px;color:#dc2626'>" + severity + "</td></tr>" if severity else ""}
  {"<tr><td style='padding:6px 12px;background:#f9fafb;font-weight:bold'>Findings</td><td style='padding:6px 12px'>" + str(count) + "</td></tr>" if count else ""}
</table>
<p style="margin-top:20px;color:#6b7280;font-size:12px">
  This alert was triggered by a SentinelAI alert rule. Log in to review the full report.
</p>
</body></html>"""
    return subject, body


async def fire_alerts(trigger: str, context: dict, rules: list[dict]):
    """
    Fire all matching active alert rules for a given trigger event.

    Args:
        trigger: One of scan_complete, critical_finding, high_finding, brute_force
        context: Dict with scan_id, target, severity, finding_count, etc.
        rules:   List of AlertRule dicts (loaded from DB by caller)
    """
    subject, body = _build_email_body(trigger, context)
    webhook_payload = {"trigger": trigger, "sentinelai": True, **context}
    tasks = []
    for rule in rules:
        if not rule.get("is_active"):
            continue
        if rule.get("trigger") not in (trigger, "all"):
            continue
        if rule.get("notify_email"):
            tasks.append(_send_email(rule["notify_email"], subject, body))
        if rule.get("notify_webhook"):
            tasks.append(_send_webhook(rule["notify_webhook"], webhook_payload))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
