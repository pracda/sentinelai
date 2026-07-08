# SentinelAI — LLM-Powered Security Operations Platform

An AI-driven security platform that uses large language models to automate both red team and blue team security workflows — from reconnaissance and vulnerability analysis to log threat detection and AI-generated mitigation reports.

## What it does

SentinelAI uses Claude (Anthropic) as the primary analyst brain. Traditional security tools give you raw data. SentinelAI feeds that data to an LLM which **reasons about it** — explaining what a vulnerability means, correlating log anomalies to known attack patterns, and writing actionable remediation plans.

```
Target → Recon scan → CVE analysis → LLM assessment → Attack vectors
                                                              ↓
Report ← Mitigation plan ← LLM correlation ← IOC enrichment ← Log analysis
```

## Feature overview

| Feature | Description |
|---|---|
| Reconnaissance | DNS enum, port scan, service fingerprint, LLM attack-surface analysis |
| Vulnerability analysis | CVE lookup, CVSS scoring, LLM exploitability assessment |
| Log analysis | Ingest raw logs, LLM anomaly detection, IOC extraction, timeline reconstruction |
| Log correlation | Cross-reference log findings against scan data and known IOCs |
| Report generation | LLM-written PDF/Markdown reports with prioritised mitigations |
| Scheduled scans | Cron-based recurring scans that run server-side |
| Alert rules | Email and/or webhook notifications on scan findings above a severity threshold |
| MITRE ATT&CK heatmap | Visual map of techniques identified across all scans |
| User accounts | JWT-based auth, bcrypt passwords, per-user activity tracking |
| API key management | Create/rotate/revoke named API keys for programmatic access |
| Admin panel | User management, per-user service usage, usage analytics, security event log |
| REST API | Full API surface with interactive docs at `/docs` |

## Tech stack

- Python 3.11 · FastAPI · SQLAlchemy (async) · aiosqlite
- Anthropic Claude (primary LLM) · OpenAI (fallback)
- PyJWT · bcrypt · python-nmap · dnspython
- NVD CVE API · AbuseIPDB
- ReportLab (PDF reports)
- Litestream (SQLite replication to S3)
- Docker · AWS Elastic Beanstalk · ECR

## Quick start (local Docker)

```powershell
# Build and run
.\sentinel.ps1 up local

# Stop
.\sentinel.ps1 down local

# Check status
.\sentinel.ps1 status
```

The app is available at `http://localhost:8000`.

See [USER_GUIDE.md](USER_GUIDE.md) for a step-by-step walkthrough of all features.

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and fill in values before running.

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Claude API key (primary LLM) |
| `OPENAI_API_KEY` | No | OpenAI API key (fallback LLM) |
| `JWT_SECRET_KEY` | Yes | Long random string for JWT signing — change in production |
| `SENTINELAI_API_KEYS` | Yes | Comma-separated static API keys for service-level access |
| `ADMIN_EMAILS` | Recommended | Comma-separated emails always granted admin on startup |
| `DATABASE_URL` | No | SQLite path (default: `sqlite+aiosqlite:////data/sentinelai.db`) |
| `NVD_API_KEY` | No | NVD API key for higher CVE query rate limits |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB key for IOC enrichment |
| `SLACK_WEBHOOK_URL` | No | Default Slack webhook for alert notifications |
| `ALERT_MIN_SEVERITY` | No | Minimum severity for alerts: `critical` / `high` / `any` (default: `critical`) |
| `SMTP_HOST` | No | SMTP host for email alert delivery |
| `SMTP_PORT` | No | SMTP port (default: 587) |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASSWORD` | No | SMTP password |
| `SMTP_FROM` | No | Sender address for alert emails |
| `ALERT_EMAIL_TO` | No | Default recipient for alert emails |

## AWS deployment

```powershell
# Deploy to Elastic Beanstalk (builds image, pushes to ECR, creates EB env)
.\sentinel.ps1 up aws

# Take down the EB environment (stops billing)
.\sentinel.ps1 down aws

# Check status and get the live URL
.\sentinel.ps1 status
```

The production URL follows the pattern:
```
http://sentinelai-prod.us-east-1.elasticbeanstalk.com
```

The deploy script injects `SENTINELAI_API_KEYS`, `JWT_SECRET_KEY`, and `ADMIN_EMAILS` as EB environment variables. All other secrets (`ANTHROPIC_API_KEY`, etc.) should be baked into the Docker image or added to the EB environment configuration manually.

Litestream replicates the SQLite database to S3 on a 1-second sync interval. On startup the container restores the latest snapshot automatically, so data persists across EB environment recreates.

## API reference

Interactive docs at `<base-url>/docs`. Key endpoints:

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | None | Register a new user |
| POST | `/api/v1/auth/login` | None | Login, returns JWT |
| GET | `/api/v1/stats` | JWT or API key | Dashboard statistics |
| POST | `/api/v1/scan/recon` | API key | Start recon scan |
| POST | `/api/v1/scan/vuln` | API key | Start vulnerability scan |
| POST | `/api/v1/scan/full` | API key | Start full scan pipeline |
| GET | `/api/v1/scans` | JWT or API key | List scans |
| GET | `/api/v1/scans/{id}` | JWT or API key | Get scan results |
| DELETE | `/api/v1/scans/{id}` | JWT or API key | Delete a scan |
| GET | `/api/v1/scans/{id}/report` | JWT or API key | Download report (PDF/MD) |
| POST | `/api/v1/logs/analyse` | API key | Analyse log content |
| POST | `/api/v1/logs/correlate` | API key | Correlate logs with scan data |
| POST | `/api/v1/report/generate` | API key | Generate report for a scan |
| GET | `/api/v1/schedules` | JWT or API key | List scheduled scans |
| POST | `/api/v1/schedules` | JWT | Create a schedule |
| PATCH | `/api/v1/schedules/{id}/toggle` | JWT | Enable/disable a schedule |
| DELETE | `/api/v1/schedules/{id}` | JWT | Delete a schedule |
| GET | `/api/v1/alerts/rules` | JWT | List alert rules |
| POST | `/api/v1/alerts/rules` | JWT | Create an alert rule |
| PATCH | `/api/v1/alerts/rules/{id}/toggle` | JWT | Enable/disable a rule |
| DELETE | `/api/v1/alerts/rules/{id}` | JWT | Delete a rule |
| GET | `/api/v1/mitre/heatmap` | JWT or API key | MITRE ATT&CK heatmap data |
| GET | `/api/v1/user/keys` | JWT | List your API keys |
| POST | `/api/v1/user/keys` | JWT | Create an API key |
| POST | `/api/v1/user/keys/{id}/rotate` | JWT | Rotate an API key |
| DELETE | `/api/v1/user/keys/{id}` | JWT | Revoke an API key |
| GET | `/api/v1/admin/users` | JWT (admin) | All users with usage stats |
| GET | `/api/v1/admin/users/{id}/activity` | JWT (admin) | Per-user activity feed |
| PATCH | `/api/v1/admin/users/{id}/toggle` | JWT (admin) | Enable/disable a user |
| GET | `/api/v1/admin/analytics` | JWT (admin) | Platform analytics |
| GET | `/api/v1/admin/usage` | JWT (admin) | Raw API usage log |
| GET | `/api/v1/admin/security-events` | JWT (admin) | Security event log |

## Authentication

The API accepts two authentication methods:

- **JWT Bearer token** — obtained via `/api/v1/auth/login`. Pass as `Authorization: Bearer <token>`. Valid for 24 hours.
- **API key** — created in the dashboard under API Keys. Pass as `X-API-Key: <key>`. No expiry.

Read endpoints (stats, scans, schedules, MITRE) accept either. Write endpoints for scans require an API key. Admin endpoints require a JWT with admin privileges.

## Project structure

```
sentinelai/
├── sentinelai/
│   ├── api/
│   │   └── main.py          # All FastAPI routes and startup logic
│   ├── core/
│   │   ├── auth.py          # JWT creation/verification, bcrypt hashing
│   │   ├── config.py        # Pydantic settings (env vars)
│   │   ├── database.py      # SQLAlchemy async engine and session factory
│   │   └── models.py        # ORM models (User, Scan, Finding, Schedule, ...)
│   └── services/
│       ├── scan_service.py  # Recon, vuln, full-scan orchestration
│       ├── log_service.py   # Log analysis and correlation
│       └── report_service.py# PDF/Markdown report generation
├── ui/
│   └── sentinelai-dashboard.html  # Single-file dashboard UI
├── .platform/               # EB platform hooks (nginx config, etc.)
├── Dockerfile
├── requirements.txt
├── litestream.yml           # Litestream S3 replication config
├── start.sh                 # Container entrypoint (starts litestream + uvicorn)
├── sentinel.ps1             # Local/AWS deploy helper (PowerShell)
├── .env                     # Local secrets — never commit
├── README.md                # This file
└── USER_GUIDE.md            # Step-by-step user documentation
```

## ⚠️ Ethical use

This tool is for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. All scan endpoints require `authorization.confirm: true` and an `authorized_by` field. All scan activity is logged and auditable by administrators. Unauthorized scanning is illegal.

## License

MIT
