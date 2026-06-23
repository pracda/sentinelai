"""
SentinelAI FastAPI Application

REST API + WebSocket for real-time streaming analysis.
Interactive docs at /docs (Swagger UI).
"""
import uuid
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import structlog

from sentinelai.core.config import get_settings
from sentinelai.core.database import init_db
from sentinelai.modules.recon.engine import ReconEngine
from sentinelai.modules.vuln.analyser import VulnAnalyser
from sentinelai.modules.logs.analyser import LogAnalyser
from sentinelai.modules.mitigation.engine import MitigationEngine

log = structlog.get_logger()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    await init_db()
    log.info("SentinelAI started", version=settings.app_version)
    yield
    log.info("SentinelAI shutdown")


app = FastAPI(
    title="SentinelAI",
    description="""
## LLM-Powered Security Operations Platform

An AI-driven security platform combining red team and blue team workflows:

- **Reconnaissance** — DNS enumeration, port scanning, LLM attack surface analysis
- **Vulnerability Analysis** — CVE lookup, exploitability assessment, attack chain mapping
- **Log Analysis** — Anomaly detection, IOC extraction, MITRE ATT&CK mapping
- **Mitigation** — AI-generated remediation plans and professional PDF reports

> ⚠️ **Authorized use only.** Only scan targets you own or have explicit permission to test.
    """,
    version=settings.app_version,
    lifespan=lifespan
)


# ── Request/Response models ────────────────────────────────────────────────

class AuthorizationConfirm(BaseModel):
    """Required for all scan endpoints — explicit authorization."""
    authorized_by: str = Field(
        ...,
        description="Full name or email of person authorizing this scan",
        example="security@example.com"
    )
    confirm: bool = Field(
        ...,
        description="Must be true — confirms you have authorization to scan this target"
    )


class ReconRequest(BaseModel):
    target: str = Field(..., example="example.com")
    ports: str = Field(default="1-1024", example="1-1024")
    authorization: AuthorizationConfirm


class VulnRequest(BaseModel):
    target: str = Field(..., example="example.com")
    open_ports: list[dict] = Field(default_factory=list)
    authorization: AuthorizationConfirm


class LogAnalysisRequest(BaseModel):
    log_source: str = Field(..., example="apache_access.log")
    log_content: Optional[str] = Field(
        None,
        description="Raw log content as string"
    )
    context: Optional[str] = Field(
        None,
        description="Additional context about the environment"
    )


class ReportRequest(BaseModel):
    scan_results: dict
    output_format: str = Field(default="markdown", pattern="^(markdown|pdf)$")
    organization: str = Field(default="Target Organization")


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def root():
    return {
        "name":    settings.app_name,
        "version": settings.app_version,
        "status":  "operational",
        "docs":    "/docs"
    }


@app.get("/api/v1/health", tags=["Health"])
async def health():
    return {
        "status":           "healthy",
        "llm_configured":  get_settings().has_anthropic_key(),
        "version":         settings.app_version
    }


# ── Reconnaissance ─────────────────────────────────────────────────────────

@app.post("/api/v1/scan/recon", tags=["Red Team — Reconnaissance"])
async def run_recon(request: ReconRequest):
    """
    Run full reconnaissance against a target.

    **Performs:**
    - DNS enumeration (A, MX, NS, TXT, subdomains)
    - Port scanning with service version detection
    - LLM-powered attack surface analysis

    **⚠️ Authorization required** — you must confirm you own or have permission to scan this target.
    """
    if not request.authorization.confirm:
        raise HTTPException(
            status_code=403,
            detail="Authorization not confirmed. Set authorization.confirm=true to proceed."
        )

    engine = ReconEngine()
    results = await engine.run_full_recon(
        target=request.target,
        authorized_by=request.authorization.authorized_by,
        ports=request.ports
    )
    return {"scan_id": str(uuid.uuid4()), "results": results}


# ── Vulnerability Analysis ─────────────────────────────────────────────────

@app.post("/api/v1/scan/vuln", tags=["Red Team — Vulnerability Analysis"])
async def run_vuln_analysis(request: VulnRequest):
    """
    Analyse discovered services for known vulnerabilities.

    **Performs:**
    - NVD CVE database lookup for each service
    - CVSS score retrieval and analysis
    - LLM exploitability assessment
    - MITRE ATT&CK technique mapping
    - Attack chain generation
    """
    if not request.authorization.confirm:
        raise HTTPException(status_code=403, detail="Authorization not confirmed.")

    analyser = VulnAnalyser()
    results = await analyser.run_full_analysis(
        target=request.target,
        open_ports=request.open_ports,
        authorized_by=request.authorization.authorized_by
    )
    return {"scan_id": str(uuid.uuid4()), "results": results}


# ── Log Analysis ───────────────────────────────────────────────────────────

@app.post("/api/v1/logs/analyse", tags=["Blue Team — Log Analysis"])
async def analyse_logs(request: LogAnalysisRequest):
    """
    Analyse security logs for threats, anomalies, and IOCs.

    **Performs:**
    - Log parsing (Apache, Nginx, auth, syslog, Windows Event)
    - Rule-based anomaly detection (SQL injection, XSS, brute force, etc.)
    - IOC extraction (IPs, domains, hashes, URLs)
    - LLM threat analysis with MITRE ATT&CK mapping
    - Attack timeline reconstruction
    - Immediate response recommendations
    """
    if not request.log_content:
        raise HTTPException(status_code=400, detail="log_content is required")

    analyser = LogAnalyser()
    results = await analyser.run_full_analysis(
        log_source=request.log_source,
        log_content=request.log_content,
        context=request.context
    )
    return {"scan_id": str(uuid.uuid4()), "results": results}


# ── Report Generation ──────────────────────────────────────────────────────

@app.post("/api/v1/report/generate", tags=["Blue Team — Reports"])
async def generate_report(request: ReportRequest):
    """
    Generate a professional security assessment report.

    **Output:**
    - Executive summary (C-suite readable)
    - Priority-ranked findings table
    - Technical remediation plan with specific commands
    - Verification checklist
    - Available as Markdown or PDF
    """
    engine = MitigationEngine()

    report_path = await engine.generate_report(
        scan_results=request.scan_results,
        output_format=request.output_format,
        output_path=None
    )

    if request.output_format == "pdf":
        return FileResponse(
            report_path,
            media_type="application/pdf",
            filename=report_path.split("/")[-1]
        )

    with open(report_path, "r") as f:
        content = f.read()

    return {
        "report_path": report_path,
        "format":      request.output_format,
        "content":     content
    }


# ── WebSocket streaming ────────────────────────────────────────────────────

@app.websocket("/ws/analyse")
async def websocket_analyse(websocket: WebSocket):
    """
    WebSocket endpoint for real-time streaming log analysis.

    Connect and send a JSON message:
    {
        "log_content": "...",
        "log_source": "apache.log"
    }

    Receives streaming LLM analysis token by token.
    """
    await websocket.accept()
    log.info("WebSocket client connected")

    try:
        data = await websocket.receive_json()
        log_content = data.get("log_content", "")
        log_source  = data.get("log_source", "unknown")

        if not log_content:
            await websocket.send_json({"error": "No log_content provided"})
            return

        analyser = LogAnalyser()

        # Parse and detect anomalies (fast, synchronous)
        log_data  = analyser.ingest_log_text(log_content, log_type="generic")
        anomalies = analyser.detect_anomalies(log_data)
        iocs      = analyser.extract_iocs(log_content)

        # Send pre-analysis results immediately
        await websocket.send_json({
            "type":      "pre_analysis",
            "anomalies": anomalies.get("anomaly_count", 0),
            "iocs":      {k: len(v) for k, v in iocs.items()}
        })

        # Stream LLM analysis token by token
        await websocket.send_json({"type": "stream_start"})

        from sentinelai.core.llm_client import get_llm_client
        llm = get_llm_client()

        prompt = f"""Analyse these security logs for threats:

Log source: {log_source}
Anomalies detected: {anomalies.get('anomaly_count', 0)}
Suspicious IPs: {anomalies.get('suspicious_ips', [])}

Log content:
{log_content[:3000]}

Provide: threat assessment, attack timeline, MITRE TTPs, and immediate response actions."""

        async for chunk in llm.stream(prompt, system=llm.log_analyst_system()):
            await websocket.send_json({"type": "chunk", "content": chunk})

        await websocket.send_json({"type": "stream_end"})

    except WebSocketDisconnect:
        log.info("WebSocket client disconnected")
    except Exception as e:
        log.error("WebSocket error", error=str(e))
        await websocket.send_json({"type": "error", "message": str(e)})
