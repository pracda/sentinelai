# SentinelAI — LLM-Powered Security Operations Platform

An AI-driven security platform that uses large language models to automate both red team and blue team security workflows — from reconnaissance and vulnerability analysis to log threat detection and AI-generated mitigation reports.

## What it does

SentinelAI uses Claude (Anthropic) as the primary analyst brain. Traditional security tools give you raw data. SentinelAI feeds that data to an LLM which **reasons about it** — explaining what a vulnerability means, correlating log anomalies to known attack patterns, and writing actionable remediation plans.

```
Target → Recon scan → CVE analysis → LLM assessment → Attack vectors
                                                              ↓
Report ← Mitigation plan ← LLM correlation ← IOC enrichment ← Log analysis
```

## Modules

| Module | Type | What it does |
|---|---|---|
| Reconnaissance engine | Red team | DNS enum, port scan, service fingerprint, LLM attack surface analysis |
| Vulnerability analyser | Red team | CVE lookup, CVSS scoring, LLM exploitability assessment |
| Log analyser | Blue team | Ingest raw logs, LLM anomaly detection, IOC extraction, timeline reconstruction |
| Mitigation engine | Blue team | LLM-generated remediation plans, priority ranking, PDF/Markdown reports |

## Tech stack

- Python 3.11 · FastAPI · LangChain
- Anthropic Claude (primary LLM) · OpenAI (fallback)
- python-nmap · dnspython · NVD CVE API · AbuseIPDB
- SQLAlchemy · SQLite / PostgreSQL
- ReportLab (PDF reports) · Rich (CLI)

## Quick start

```bash
# 1. Clone and setup
git clone https://github.com/prasiddhapaudel/sentinelai.git
cd sentinelai
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env — add your Anthropic API key at minimum

# 4. Run the API server
uvicorn sentinelai.api.main:app --reload

# 5. Or use the CLI
python -m sentinelai scan --target example.com --mode recon
python -m sentinelai analyse --logs ./sample_logs/apache.log
python -m sentinelai report --scan-id <id> --format pdf
```

## API reference

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/scan/recon` | Start reconnaissance scan |
| POST | `/api/v1/scan/vuln` | Vulnerability analysis |
| POST | `/api/v1/logs/analyse` | Analyse log file for threats |
| POST | `/api/v1/report/generate` | Generate mitigation report |
| GET | `/api/v1/scans` | List all scans |
| GET | `/api/v1/scans/{id}` | Get scan results |
| GET | `/docs` | Interactive API docs |

## ⚠️ Ethical use

This tool is for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. All scans require authorization confirmation. Unauthorized scanning is illegal.

## License

MIT
