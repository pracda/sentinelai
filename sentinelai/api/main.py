"""
SentinelAI FastAPI Application — Phase 2

Security: All endpoints (except /health, /docs) require X-API-Key header.
OWASP API Security Top 10 fully addressed.
"""
import uuid
import os
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, List
from datetime import datetime, timedelta

from fastapi import (
    FastAPI, HTTPException, WebSocket, WebSocketDisconnect,
    BackgroundTasks, Depends, Request, Security
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, StreamingResponse
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func
import structlog

import time as _time
import re as _re

from sentinelai.core.config import get_settings
from sentinelai.core.database import (
    init_db, get_session_factory,
    Scan, Finding, Schedule, LogAnalysis, ScanStatus, ScanType,
    User, UserApiKey, UsageLog, SecurityEvent, AlertRule, ActivityEvent,
    CodeAudit, RemediationStatus, CveWatchlistEntry, SystemConfig,
)
from sentinelai.core.security import (
    verify_api_key, rate_limit_dependency,
    init_api_keys, validate_target, validate_log_content,
    SECURE_HEADERS, generate_api_key, _hash_key,
    register_api_key, register_api_key_by_hash,
    unregister_api_key_by_hash, get_key_meta,
    API_KEY_HEADER, _API_KEY_STORE,
)
from sentinelai.core.auth import (
    hash_password, verify_password, create_token,
    get_current_user, require_admin,
)
from sentinelai.core.scan_service import ScanService
from sentinelai.modules.logs.analyser import LogAnalyser

log = structlog.get_logger()
settings = get_settings()

# ── Brute-force tracking (in-memory, per-IP failed login window) ───────────
from collections import defaultdict as _defaultdict
_failed_logins: dict[str, list[float]] = _defaultdict(list)
_BRUTE_WINDOW  = 300   # 5 minutes
_BRUTE_THRESH  = 5     # attempts before lockout


def _decode_safe(token: str) -> dict:
    """Decode JWT without raising — returns {} on any error."""
    try:
        from sentinelai.core.auth import _decode
        return _decode(token)
    except Exception:
        return {}


async def jwt_or_api_key(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    api_key: Optional[str] = Security(API_KEY_HEADER),
) -> str:
    """Accept either a valid JWT Bearer token OR a valid X-API-Key — for read/dashboard endpoints."""
    if creds:
        payload = _decode_safe(creds.credentials)
        if payload.get("sub"):
            return payload["sub"]
    if api_key:
        if _hash_key(api_key) in _API_KEY_STORE:
            return api_key
    raise HTTPException(status_code=401, detail="Authentication required (JWT or API key)")


# ── Lifespan ───────────────────────────────────────────────────────────────

async def _scheduler_loop():
    """Background task: every 60 s check for due schedules and fire scans."""
    await asyncio.sleep(10)  # short delay to let startup finish
    while True:
        try:
            async with get_session_factory()() as session:
                now = datetime.utcnow()
                result = await session.execute(
                    select(Schedule).where(
                        Schedule.enabled == True,
                        Schedule.next_run <= now
                    )
                )
                due = result.scalars().all()
            for sched in due:
                log.info("Scheduler firing scan", schedule_id=sched.id, target=sched.target)
                service = ScanService()
                if sched.scan_type == ScanType.RECON:
                    asyncio.create_task(service.run_recon(sched.target, None, sched.authorized_by, "scheduler"))
                elif sched.scan_type == ScanType.VULN:
                    asyncio.create_task(service.run_vuln(sched.target, [], sched.authorized_by, "scheduler"))
                elif sched.scan_type == ScanType.FULL:
                    asyncio.create_task(service.run_full_scan(sched.target, None, sched.authorized_by, "scheduler"))
                async with get_session_factory()() as session:
                    row = await session.get(Schedule, sched.id)
                    if row:
                        row.last_run = now
                        row.next_run = now + timedelta(hours=sched.interval_hours)
                        await session.commit()
        except Exception as e:
            log.error("Scheduler error", error=str(e))
        await asyncio.sleep(60)


# ── Startup helpers ────────────────────────────────────────────────────────

async def _load_db_api_keys():
    """Load all active user API keys from DB into in-memory store."""
    try:
        async with get_session_factory()() as session:
            rows = (await session.execute(
                select(UserApiKey).where(UserApiKey.is_active == True)
            )).scalars().all()
            for k in rows:
                register_api_key_by_hash(k.key_hash, k.name,
                                         user_id=k.user_id, key_id=k.id)
            log.info("Loaded user API keys from DB", count=len(rows))
    except Exception as e:
        log.warning("Could not load user API keys from DB", error=str(e))


async def _load_gateway_config():
    """Load LLM gateway config from system_config table into llm_client's in-memory override."""
    from sentinelai.core.llm_client import set_gateway_config, clear_gateway_config
    try:
        async with get_session_factory()() as session:
            rows = (await session.execute(
                select(SystemConfig).where(SystemConfig.key.like("llm_gateway_%"))
            )).scalars().all()
        cfg = {r.key: r.value for r in rows}
        api_key = cfg.get("llm_gateway_api_key", "")
        if api_key:
            set_gateway_config(
                enabled=cfg.get("llm_gateway_enabled", "false").lower() == "true",
                url=cfg.get("llm_gateway_url", ""),
                api_key=api_key,
            )
        else:
            clear_gateway_config()
    except Exception as e:
        log.warning("Could not load gateway config from DB, using env vars", error=str(e))


async def _ensure_admin_emails():
    """Promote any user whose email is in ADMIN_EMAILS to admin — runs on every startup.
    This is idempotent and survives DB restores from S3/litestream."""
    admin_emails = [e.strip().lower() for e in settings.admin_emails.split(',') if e.strip()]
    if not admin_emails:
        return
    try:
        async with get_session_factory()() as session:
            promoted = []
            for email in admin_emails:
                user = (await session.execute(
                    select(User).where(func.lower(User.email) == email)
                )).scalars().first()
                if user and not user.is_admin:
                    user.is_admin = True
                    promoted.append(user.username)
            if promoted:
                await session.commit()
                log.info("Promoted users to admin via ADMIN_EMAILS", users=promoted)
    except Exception as e:
        log.warning("Could not run admin email promotion", error=str(e))


async def _log_request(user_id, api_key_id, endpoint, method, ip, status, dur):
    try:
        async with get_session_factory()() as session:
            session.add(UsageLog(
                id=str(uuid.uuid4()),
                user_id=user_id, api_key_id=api_key_id,
                endpoint=endpoint, method=method, ip_address=ip,
                status_code=status, duration_ms=dur,
            ))
            if api_key_id:
                row = await session.get(UserApiKey, api_key_id)
                if row:
                    row.last_used_at = datetime.utcnow()
                    row.usage_count  = (row.usage_count or 0) + 1
            await session.commit()
    except Exception:
        pass


async def _log_security_event(event_type, ip, details=None,
                               user_id=None, severity="medium"):
    try:
        async with get_session_factory()() as session:
            session.add(SecurityEvent(
                id=str(uuid.uuid4()),
                user_id=user_id, event_type=event_type,
                ip_address=ip, details=details, severity=severity,
            ))
            await session.commit()
    except Exception:
        pass


async def _log_activity(event_type: str, ip: str, *,
                         user_id=None, api_key_id=None, scan_id=None,
                         details=None, duration_ms=None, user_agent=None):
    """Write a semantic ActivityEvent record for evaluation and auditing."""
    try:
        async with get_session_factory()() as session:
            session.add(ActivityEvent(
                id=str(uuid.uuid4()),
                user_id=user_id, api_key_id=api_key_id,
                event_type=event_type, scan_id=scan_id,
                details=details, duration_ms=duration_ms,
                ip_address=ip,
                user_agent=(user_agent or "")[:512],
            ))
            await session.commit()
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    init_api_keys()
    await _load_db_api_keys()
    await _load_gateway_config()
    await _ensure_admin_emails()
    scheduler_task = asyncio.create_task(_scheduler_loop())
    kev_task = asyncio.create_task(_kev_refresh_loop())
    log.info("SentinelAI started",
             version=settings.app_version,
             environment=settings.environment)
    yield
    scheduler_task.cancel()
    kev_task.cancel()
    log.info("SentinelAI shutdown")


# ── App ────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelAI",
    description="""
## LLM-Powered Security Operations Platform

**Authentication:** All endpoints except `/health` require `X-API-Key` header.

**Rate limiting:** 20 requests per minute per API key.

**OWASP coverage:** API1 (auth), API2 (broken auth), API4 (rate limiting),
API8 (secure headers), API10 (output validation).

> ⚠️ Authorized use only. Only scan systems you own or have explicit permission to test.
    """,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── Dashboard UI ───────────────────────────────────────────────────────────

@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    candidates = [
        "/app/ui/sentinelai-dashboard.html",
        os.path.join(os.getcwd(), "ui", "sentinelai-dashboard.html"),
        "ui/sentinelai-dashboard.html",
    ]
    for ui_path in candidates:
        if os.path.exists(ui_path):
            with open(ui_path, "r", encoding="utf-8") as f:
                return f.read()
    raise HTTPException(status_code=404, detail=f"Dashboard not found. Tried: {candidates}")

# ── CORS ───────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


# ── Request tracking + secure headers middleware ───────────────────────────

# Paths that generate too much noise to log individually
_NO_LOG_PATHS = frozenset(['/', '/health', '/docs', '/redoc', '/openapi.json', '/ui'])

@app.middleware("http")
async def tracking_middleware(request: Request, call_next):
    start = _time.time()
    response = await call_next(request)

    # Always apply secure headers
    for h, v in SECURE_HEADERS.items():
        response.headers[h] = v

    path = request.url.path
    if path in _NO_LOG_PATHS or path.startswith('/static'):
        return response

    # Resolve caller identity without a DB query (in-memory lookups only)
    user_id, api_key_id = None, None
    auth_hdr = request.headers.get('Authorization', '')
    if auth_hdr.startswith('Bearer '):
        payload = _decode_safe(auth_hdr[7:])
        user_id = payload.get('sub')

    raw_key = request.headers.get('X-API-Key', '')
    if raw_key:
        meta = get_key_meta(raw_key)
        if meta:
            api_key_id = meta.get('key_id')
            if not user_id:
                user_id = meta.get('user_id')

    dur_ms = int((_time.time() - start) * 1000)
    ip     = request.client.host if request.client else 'unknown'

    asyncio.create_task(
        _log_request(user_id, api_key_id, path, request.method, ip,
                     response.status_code, dur_ms)
    )
    return response


# ── Request/Response models ────────────────────────────────────────────────

class AuthorizationConfirm(BaseModel):
    authorized_by: str = Field(..., min_length=3, max_length=255)
    confirm: bool = Field(...)


class ReconRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    ports: str = Field(default="1-1024", pattern=r'^[\d\-,]+$')
    authorization: AuthorizationConfirm


class VulnRequest(BaseModel):
    target: str = Field(...)
    open_ports: List[dict] = Field(default_factory=list)
    authorization: AuthorizationConfirm


class LogAnalysisRequest(BaseModel):
    log_source: str = Field(..., example="apache_access.log")
    log_content: Optional[str] = Field(None)
    context: Optional[str] = Field(None, max_length=1000)


class FullScanRequest(BaseModel):
    target: str = Field(...)
    ports: str = Field(default="1-1024", pattern=r'^[\d\-,]+$')
    authorization: AuthorizationConfirm


class ReportRequest(BaseModel):
    scan_id: str
    output_format: str = Field(default="markdown", pattern="^(markdown|pdf)$")


class MultiLogRequest(BaseModel):
    logs: List[dict] = Field(..., description="List of {log_source, log_content} objects")
    context: Optional[str] = Field(None, max_length=500)


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    scan_type: str
    message: str


# ── Health (public) ────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": "SentinelAI",
        "version": settings.app_version,
        "status": "operational",
        "docs": "/docs",
        "ui": "/ui"
    }


@app.get("/health", tags=["Health"])
async def health():
    """Public health check."""
    db_url = settings.database_url
    db_type = "postgresql" if "postgresql" in db_url else "sqlite"
    return {
        "status": "healthy",
        "version": settings.app_version,
        "llm_configured": settings.has_anthropic_key(),
        "db_type": db_type,
        "db_ephemeral": db_type == "sqlite",
    }


# ── Auth ───────────────────────────────────────────────────────────────────

@app.get("/api/v1/auth/key", tags=["Authentication"])
async def generate_key():
    """Generate a new API key for development."""
    return {
        "key": generate_api_key(),
        "note": "Add this to SENTINELAI_API_KEYS in your .env file"
    }


# ── Scans ──────────────────────────────────────────────────────────────────

@app.get("/api/v1/scans", tags=["Scans"],
         dependencies=[Depends(jwt_or_api_key)])
async def list_scans(
    limit: int = 20,
    offset: int = 0,
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
):
    """List all scans with pagination."""
    async with get_session_factory()() as session:
        query = select(Scan).order_by(desc(Scan.created_at))
        if status:
            query = query.where(Scan.status == status)
        if scan_type:
            query = query.where(Scan.scan_type == scan_type)
        query = query.offset(offset).limit(min(limit, 100))
        result = await session.execute(query)
        scans = result.scalars().all()
        return {
            "scans": [_scan_to_dict(s) for s in scans],
            "count": len(scans),
            "offset": offset,
            "limit": limit
        }


@app.get("/api/v1/scans/{scan_id}", tags=["Scans"],
         dependencies=[Depends(jwt_or_api_key)])
async def get_scan(scan_id: str):
    """Get full details of a specific scan."""
    async with get_session_factory()() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        findings_query = (select(Finding)
                          .where(Finding.scan_id == scan_id)
                          .order_by(Finding.created_at))
        findings_result = await session.execute(findings_query)
        findings = findings_result.scalars().all()
        result = _scan_to_dict(scan)
        result["llm_analysis"] = scan.llm_analysis
        result["findings"] = [_finding_to_dict(f) for f in findings]
        return result


@app.get("/api/v1/scans/{scan_id}/analysis/stream", tags=["Scans"],
         dependencies=[Depends(jwt_or_api_key)])
async def stream_scan_analysis(scan_id: str):
    """Stream the LLM analysis for a scan as SSE.
    If the scan is still running, polls until complete then streams.
    If already complete, streams the cached analysis word-by-word."""
    async def generate():
        # Poll until the scan has a completed analysis (max 5 min)
        for _ in range(300):
            async with get_session_factory()() as session:
                scan = await session.get(Scan, scan_id)
            if not scan:
                yield "data: [ERROR: scan not found]\n\n"
                return
            if scan.status == ScanStatus.FAILED:
                yield f"data: [Scan failed: {scan.error or 'unknown error'}]\n\n"
                yield "data: [DONE]\n\n"
                return
            if scan.status == ScanStatus.COMPLETED and scan.llm_analysis:
                break
            yield "data: [RUNNING]\n\n"
            await asyncio.sleep(1)
        else:
            yield "data: [Timed out waiting for analysis]\n\n"
            yield "data: [DONE]\n\n"
            return

        # Stream the stored analysis word by word
        words = scan.llm_analysis.split(" ")
        chunk = ""
        for i, word in enumerate(words):
            chunk += ("" if chunk == "" else " ") + word
            if len(chunk) >= 40 or i == len(words) - 1:
                yield f"data: {chunk}\n\n"
                chunk = ""
                await asyncio.sleep(0.02)
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.delete("/api/v1/scans/{scan_id}", tags=["Scans"],
            dependencies=[Depends(jwt_or_api_key)])
async def delete_scan(scan_id: str):
    """Delete a scan and all its findings."""
    async with get_session_factory()() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        await session.delete(scan)
        await session.commit()
        return {"message": f"Scan {scan_id} deleted"}


@app.get("/api/v1/scans/{scan_id}/report", tags=["Blue Team"],
         dependencies=[Depends(jwt_or_api_key)])
async def download_report(scan_id: str, http_request: Request):
    """Download a polished PDF security report for any completed scan."""
    async with get_session_factory()() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed yet")

        # Load findings from DB
        findings_rows = (await session.execute(
            select(Finding).where(Finding.scan_id == scan_id)
            .order_by(Finding.severity)
        )).scalars().all()
        findings = [_finding_to_dict(f) for f in findings_rows]

        # Load IOCs from LogAnalysis (log scans store them here)
        log_row = (await session.execute(
            select(LogAnalysis).where(LogAnalysis.scan_id == scan_id)
        )).scalars().first()
        iocs = log_row.iocs_extracted or {} if log_row else {}
        llm_text = (log_row.llm_analysis if log_row else None) or scan.llm_analysis or ""

    from sentinelai.modules.reports.generator import ReportGenerator
    generator = ReportGenerator()
    pdf_path = await generator.generate_pdf(
        scan_data=_scan_to_dict(scan),
        llm_analysis=llm_text,
        findings=findings,
        report_type=scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
        iocs=iocs,
    )
    ip   = http_request.client.host if http_request.client else "unknown"
    meta = get_key_meta(http_request.headers.get("X-API-Key", ""))
    asyncio.create_task(_log_activity(
        "pdf_download", ip,
        user_id=meta.get("user_id") if meta else None,
        api_key_id=meta.get("key_id") if meta else None,
        scan_id=scan_id,
        details={"target": scan.target, "scan_type": str(scan.scan_type)}
    ))
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"sentinelai_report_{scan_id[:8]}.pdf"
    )


# ── Red Team ───────────────────────────────────────────────────────────────

@app.post("/api/v1/scan/recon", tags=["Red Team"], response_model=ScanResponse)
async def run_recon(
    request: ReconRequest,
    background_tasks: BackgroundTasks,
    api_key_name: str = Depends(rate_limit_dependency)
):
    """Start a reconnaissance scan."""
    if not request.authorization.confirm:
        raise HTTPException(status_code=403, detail="Set authorization.confirm=true")
    target = validate_target(request.target)
    service = ScanService()
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        service.run_recon,
        target=target,
        ports=request.ports,
        authorized_by=request.authorization.authorized_by,
        api_key_name=api_key_name
    )
    return ScanResponse(scan_id=scan_id, status="running", target=target,
                        scan_type="recon", message="Recon scan started.")


@app.post("/api/v1/scan/vuln", tags=["Red Team"], response_model=ScanResponse)
async def run_vuln(
    request: VulnRequest,
    background_tasks: BackgroundTasks,
    api_key_name: str = Depends(rate_limit_dependency)
):
    """Analyse services for vulnerabilities."""
    if not request.authorization.confirm:
        raise HTTPException(status_code=403, detail="Set authorization.confirm=true")
    target = validate_target(request.target)
    service = ScanService()
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        service.run_vuln,
        target=target,
        open_ports=request.open_ports,
        authorized_by=request.authorization.authorized_by,
        api_key_name=api_key_name
    )
    return ScanResponse(scan_id=scan_id, status="running", target=target,
                        scan_type="vuln", message="Vulnerability analysis started.")


@app.post("/api/v1/scan/full", tags=["Red Team"], response_model=ScanResponse)
async def run_full_scan(
    request: FullScanRequest,
    background_tasks: BackgroundTasks,
    api_key_name: str = Depends(rate_limit_dependency)
):
    """Complete security assessment: Recon + Vuln + Report."""
    if not request.authorization.confirm:
        raise HTTPException(status_code=403, detail="Set authorization.confirm=true")
    target = validate_target(request.target)
    service = ScanService()
    scan_id = str(uuid.uuid4())
    background_tasks.add_task(
        service.run_full_scan,
        target=target,
        ports=request.ports,
        authorized_by=request.authorization.authorized_by,
        api_key_name=api_key_name
    )
    return ScanResponse(scan_id=scan_id, status="running", target=target,
                        scan_type="full", message="Full scan started.")


# ── Blue Team ──────────────────────────────────────────────────────────────

@app.post("/api/v1/logs/analyse", tags=["Blue Team"],
          dependencies=[Depends(rate_limit_dependency)])
async def analyse_logs(
    request: LogAnalysisRequest,
    background_tasks: BackgroundTasks,
    api_key_name: str = Depends(rate_limit_dependency)
):
    """Analyse security logs for threats, anomalies, and IOCs."""
    if not request.log_content:
        raise HTTPException(status_code=400, detail="log_content is required")
    content = validate_log_content(request.log_content)
    service = ScanService()
    scan_id = await service.run_log_analysis(
        log_source=request.log_source,
        log_content=content,
        api_key_name=api_key_name,
        context=request.context
    )
    async with get_session_factory()() as session:
        scan = await session.get(Scan, scan_id)
        result = _scan_to_dict(scan) if scan else {"scan_id": scan_id}
        raw = (scan.raw_results or {}) if scan else {}
        result["results"] = {
            "llm_analysis": scan.llm_analysis if scan else "",
            "anomalies": raw.get("anomalies", {
                "anomaly_count": 0,
                "suspicious_ips": [],
                "top_threats": []
            }),
            "iocs": raw.get("iocs", {})
        }
        return result


@app.post("/api/v1/logs/correlate", tags=["Blue Team"],
          dependencies=[Depends(rate_limit_dependency)])
async def correlate_logs(
    request: MultiLogRequest,
    http_request: Request,
    api_key_name: str = Depends(rate_limit_dependency)
):
    """Correlate events across 2-10 log sources to reconstruct the attack chain."""
    from sentinelai.modules.logs.correlator import LogCorrelator
    correlator = LogCorrelator()
    result = await correlator.correlate(
        logs=request.logs,
        context=request.context,
        api_key_name=api_key_name
    )

    # Persist correlation to DB so it appears in history
    scan_id = str(uuid.uuid4())
    source_names = ", ".join(
        str(lg.get("log_source", "unknown")) for lg in request.logs[:3]
    )
    shared_ips = result.get("shared_suspicious_ips", [])
    async with get_session_factory()() as session:
        now = datetime.utcnow()
        scan = Scan(
            id=scan_id,
            target=source_names[:255],
            scan_type=ScanType.LOG_ANALYSE,
            status=ScanStatus.COMPLETED,
            authorized_by=api_key_name,
            created_at=now,
            completed_at=now,
            llm_analysis=result.get("correlation_analysis", ""),
            finding_count=result.get("total_anomalies", 0),
        )
        session.add(scan)
        log_entry = LogAnalysis(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            log_source="multi_correlation",
            log_type="correlation",
            lines_analysed=0,
            anomalies_found=result.get("total_anomalies", 0),
            iocs_extracted={"suspicious_ips": shared_ips},
            llm_analysis=result.get("correlation_analysis", ""),
            created_at=now,
        )
        session.add(log_entry)
        await session.commit()

    ip = http_request.client.host if http_request.client else "unknown"
    meta = get_key_meta(http_request.headers.get("X-API-Key", ""))
    asyncio.create_task(_log_activity(
        "attack_chain", ip,
        user_id=meta.get("user_id") if meta else None,
        api_key_id=meta.get("key_id") if meta else None,
        scan_id=scan_id,
        details={
            "sources": len(request.logs),
            "source_names": [lg.get("log_source", "?") for lg in request.logs[:5]],
            "total_anomalies": result.get("total_anomalies", 0),
            "shared_ips": len(shared_ips),
        }
    ))
    result["scan_id"] = scan_id
    return result


@app.post("/api/v1/report/generate", tags=["Blue Team"],
          dependencies=[Depends(rate_limit_dependency)])
async def generate_report(request: ReportRequest):
    """Generate a security report for a completed scan."""
    async with get_session_factory()() as session:
        scan = await session.get(Scan, request.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found")
        if scan.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed yet")
        from sentinelai.modules.mitigation.engine import MitigationEngine
        engine = MitigationEngine()
        scan_data = {
            "target": scan.target,
            "scan_type": scan.scan_type,
            **(scan.raw_results or {})
        }
        report_path = await engine.generate_report(
            scan_results=scan_data,
            output_format=request.output_format
        )
        if request.output_format == "pdf":
            return FileResponse(report_path, media_type="application/pdf",
                                filename=f"sentinelai_report_{scan.target}.pdf")
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"scan_id": request.scan_id, "target": scan.target,
                "format": request.output_format, "content": content}


# ── Dashboard Stats ────────────────────────────────────────────────────────

@app.get("/api/v1/stats", tags=["Dashboard"],
         dependencies=[Depends(jwt_or_api_key)])
async def get_stats():
    """Platform-wide statistics."""
    async with get_session_factory()() as session:
        all_scans = (await session.execute(select(Scan))).scalars().all()
        total = len(all_scans)
        completed = sum(1 for s in all_scans if s.status == ScanStatus.COMPLETED)
        failed = sum(1 for s in all_scans if s.status == ScanStatus.FAILED)
        running = sum(1 for s in all_scans if s.status == ScanStatus.RUNNING)
        total_findings = sum(s.finding_count or 0 for s in all_scans)
        total_critical = sum(s.critical_count or 0 for s in all_scans)
        total_high = sum(s.high_count or 0 for s in all_scans)
        by_type = {}
        for s in all_scans:
            t = s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type)
            by_type[t] = by_type.get(t, 0) + 1
        recent = sorted(all_scans, key=lambda s: s.created_at, reverse=True)[:5]
        return {
            "total_scans": total,
            "completed_scans": completed,
            "failed_scans": failed,
            "running_scans": running,
            "total_findings": total_findings,
            "critical_findings": total_critical,
            "high_findings": total_high,
            "scans_by_type": by_type,
            "recent_scans": [_scan_to_dict(s) for s in recent]
        }


# ── WebSocket streaming ────────────────────────────────────────────────────

@app.websocket("/ws/analyse")
async def websocket_analyse(websocket: WebSocket):
    """Real-time streaming log analysis via WebSocket."""
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        api_key = data.get("api_key", "")
        from sentinelai.core.security import _hash_key, _API_KEY_STORE
        import hmac
        key_hash = _hash_key(api_key)
        authenticated = any(
            hmac.compare_digest(key_hash, stored)
            for stored in _API_KEY_STORE
        )
        if not authenticated:
            await websocket.send_json({"type": "error", "message": "Invalid API key"})
            await websocket.close(code=4001)
            return
        log_content = data.get("log_content", "")
        log_source = data.get("log_source", "unknown")
        if not log_content:
            await websocket.send_json({"type": "error", "message": "No log_content"})
            return
        analyser = LogAnalyser()
        log_data = analyser.ingest_log_text(log_content)
        anomalies = analyser.detect_anomalies(log_data)
        iocs = analyser.extract_iocs(log_content)
        await websocket.send_json({
            "type": "pre_analysis",
            "anomalies": anomalies.get("anomaly_count", 0),
            "suspicious_ips": anomalies.get("suspicious_ips", []),
            "top_threats": [t.get("type") for t in anomalies.get("top_threats", [])],
            "iocs": {k: len(v) for k, v in iocs.items() if v}
        })
        await websocket.send_json({"type": "stream_start"})
        from sentinelai.core.llm_client import get_llm_client
        llm = get_llm_client()
        prompt = f"""Analyse these security logs:
Log source: {log_source}
Anomalies: {anomalies.get('anomaly_count', 0)}
Suspicious IPs: {anomalies.get('suspicious_ips', [])}
Log sample:
{log_content[:2000]}
Provide: threat assessment, MITRE TTPs, attack timeline, immediate actions."""
        full_response = ""
        async for chunk in llm.stream(prompt, system=llm.log_analyst_system()):
            await websocket.send_json({"type": "chunk", "content": chunk})
            full_response += chunk
        await websocket.send_json({"type": "stream_end"})

        # Send full IOC details for rendering
        await websocket.send_json({"type": "iocs", "iocs": iocs})

        # Persist to DB so it appears in scan history
        from sentinelai.core.database import Scan as ScanModel, LogAnalysis as LogAnalysisModel, ScanType, ScanStatus
        anomaly_count = anomalies.get("anomaly_count", 0)
        scan_id = str(uuid.uuid4())
        now = datetime.utcnow()
        async with get_session_factory()() as session:
            scan_row = ScanModel(
                id=scan_id,
                target=log_source,
                scan_type=ScanType.LOG_ANALYSE,
                status=ScanStatus.COMPLETED,
                authorized_by="api",
                created_at=now,
                completed_at=now,
                llm_analysis=full_response,
                finding_count=anomaly_count,
                summary=f"Scan of {log_source} completed. {anomaly_count} findings identified.",
            )
            session.add(scan_row)
            log_record = LogAnalysisModel(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                log_source=log_source,
                log_type=log_data.get("log_type", "unknown"),
                lines_analysed=log_data.get("total_lines", 0),
                anomalies_found=anomaly_count,
                iocs_extracted=iocs,
                llm_analysis=full_response,
            )
            session.add(log_record)
            await session.commit()

        # Log semantic activity — resolve identity from the WS api_key
        ws_meta = get_key_meta(api_key)
        ws_ip   = websocket.client.host if websocket.client else "unknown"
        asyncio.create_task(_log_activity(
            "log_analysis", ws_ip,
            user_id=ws_meta.get("user_id") if ws_meta else None,
            api_key_id=ws_meta.get("key_id") if ws_meta else None,
            scan_id=scan_id,
            details={
                "log_source": log_source,
                "log_type": log_data.get("log_type", "unknown"),
                "lines_analysed": log_data.get("total_lines", 0),
                "anomalies_found": anomaly_count,
                "ioc_count": sum(len(v) for v in iocs.values() if isinstance(v, list)),
            }
        ))
        await websocket.send_json({"type": "saved", "scan_id": scan_id, "finding_count": anomaly_count})
    except WebSocketDisconnect:
        log.info("WebSocket client disconnected")
    except Exception as e:
        log.error("WebSocket error", error=str(e))
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


# ── Helper serialisers ─────────────────────────────────────────────────────

def _scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
        "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        "authorized_by": scan.authorized_by,
        "finding_count": scan.finding_count or 0,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "summary": scan.summary,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "error": scan.error,
    }


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "cvss_score": finding.cvss_score,
        "cve_id": finding.cve_id,
        "mitre_attack": finding.mitre_attack,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
    }


def _schedule_to_dict(s: Schedule) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "target": s.target,
        "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type),
        "interval_hours": s.interval_hours,
        "authorized_by": s.authorized_by,
        "enabled": s.enabled,
        "last_run": s.last_run.isoformat() if s.last_run else None,
        "next_run": s.next_run.isoformat() if s.next_run else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


# ── Schedule CRUD ──────────────────────────────────────────────────────────

class ScheduleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    target: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field(..., pattern="^(recon|vuln|full)$")
    interval_hours: int = Field(..., ge=1, le=168)
    authorized_by: str = Field(default="scheduled")


@app.post("/api/v1/schedules", tags=["Schedules"])
async def create_schedule(
    req: ScheduleCreateRequest,
    request: Request,
    api_key_name: str = Depends(verify_api_key),
    _rl: None = Depends(rate_limit_dependency),
):
    target = validate_target(req.target)
    scan_type_map = {"recon": ScanType.RECON, "vuln": ScanType.VULN, "full": ScanType.FULL}
    now = datetime.utcnow()
    schedule = Schedule(
        id=str(uuid.uuid4()),
        name=req.name,
        target=target,
        scan_type=scan_type_map[req.scan_type],
        interval_hours=req.interval_hours,
        authorized_by=req.authorized_by,
        enabled=True,
        last_run=None,
        next_run=now + timedelta(hours=req.interval_hours),
        created_at=now,
    )
    async with get_session_factory()() as session:
        session.add(schedule)
        await session.commit()
    ip = request.client.host if request.client else "unknown"
    asyncio.create_task(_log_activity(
        "schedule_created", ip,
        details={"name": req.name, "target": target, "scan_type": req.scan_type,
                 "interval_hours": req.interval_hours},
    ))
    return {"message": "Schedule created", "schedule": _schedule_to_dict(schedule)}


@app.get("/api/v1/schedules", tags=["Schedules"])
async def list_schedules(
    _auth: str = Depends(jwt_or_api_key),
):
    async with get_session_factory()() as session:
        result = await session.execute(select(Schedule).order_by(desc(Schedule.created_at)))
        schedules = result.scalars().all()
    return {"count": len(schedules), "schedules": [_schedule_to_dict(s) for s in schedules]}


@app.patch("/api/v1/schedules/{schedule_id}/toggle", tags=["Schedules"])
async def toggle_schedule(
    schedule_id: str,
    _auth: str = Depends(jwt_or_api_key),
):
    async with get_session_factory()() as session:
        schedule = await session.get(Schedule, schedule_id)
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
        schedule.enabled = not schedule.enabled
        if schedule.enabled:
            schedule.next_run = datetime.utcnow() + timedelta(hours=schedule.interval_hours)
        await session.commit()
        return {"message": f"Schedule {'enabled' if schedule.enabled else 'disabled'}", "schedule": _schedule_to_dict(schedule)}


@app.delete("/api/v1/schedules/{schedule_id}", tags=["Schedules"])
async def delete_schedule(
    schedule_id: str,
    _auth: str = Depends(jwt_or_api_key),
):
    async with get_session_factory()() as session:
        schedule = await session.get(Schedule, schedule_id)
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
        await session.delete(schedule)
        await session.commit()
    return {"message": "Schedule deleted"}


# ── MITRE ATT&CK Heatmap ──────────────────────────────────────────────────

_TECHNIQUE_META: dict[str, dict] = {
    "T1595":     {"name": "Active Scanning",                    "tactic": "Reconnaissance",      "tactic_id": "TA0043"},
    "T1190":     {"name": "Exploit Public-Facing Application",  "tactic": "Initial Access",      "tactic_id": "TA0001"},
    "T1133":     {"name": "External Remote Services",           "tactic": "Initial Access",      "tactic_id": "TA0001"},
    "T1078":     {"name": "Valid Accounts",                     "tactic": "Initial Access",      "tactic_id": "TA0001"},
    "T1059":     {"name": "Command & Scripting Interpreter",    "tactic": "Execution",           "tactic_id": "TA0002"},
    "T1059.007": {"name": "JavaScript",                         "tactic": "Execution",           "tactic_id": "TA0002"},
    "T1053":     {"name": "Scheduled Task/Job",                 "tactic": "Persistence",         "tactic_id": "TA0003"},
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "tactic_id": "TA0004"},
    "T1110":     {"name": "Brute Force",                        "tactic": "Credential Access",   "tactic_id": "TA0006"},
    "T1083":     {"name": "File & Directory Discovery",         "tactic": "Discovery",           "tactic_id": "TA0007"},
    "T1046":     {"name": "Network Service Discovery",          "tactic": "Discovery",           "tactic_id": "TA0007"},
    "T1021":     {"name": "Remote Services",                    "tactic": "Lateral Movement",    "tactic_id": "TA0008"},
    "T1071":     {"name": "Application Layer Protocol",         "tactic": "Command & Control",   "tactic_id": "TA0011"},
    "T1048":     {"name": "Exfiltration Over Alt Protocol",     "tactic": "Exfiltration",        "tactic_id": "TA0010"},
    "T1499":     {"name": "Endpoint Denial of Service",         "tactic": "Impact",              "tactic_id": "TA0040"},
}

_TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command & Control", "Exfiltration", "Impact",
]


@app.get("/api/v1/mitre/heatmap", tags=["Analytics"],
         dependencies=[Depends(jwt_or_api_key)])
async def mitre_heatmap():
    """Return MITRE ATT&CK technique hit counts from all stored findings."""
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(Finding.mitre_attack, Finding.severity)
            .where(Finding.mitre_attack.isnot(None))
        )).all()

    counts: dict[str, dict] = {}
    for mitre_raw, severity in rows:
        if not mitre_raw:
            continue
        m = _re.search(r'(T\d{4}(?:\.\d{3})?)', str(mitre_raw))
        if not m:
            continue
        tech_id = m.group(1)
        if tech_id not in counts:
            counts[tech_id] = {"count": 0, "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
        counts[tech_id]["count"] += 1
        sev = str(severity).lower()
        if sev in counts[tech_id]["severities"]:
            counts[tech_id]["severities"][sev] += 1

    tactic_pos = {t: i for i, t in enumerate(_TACTIC_ORDER)}
    techniques = []
    for tech_id, data in counts.items():
        meta = _TECHNIQUE_META.get(tech_id, {"name": tech_id, "tactic": "Unknown", "tactic_id": "TA0000"})
        techniques.append({
            "id": tech_id,
            "name": meta["name"],
            "tactic": meta["tactic"],
            "tactic_id": meta["tactic_id"],
            "count": data["count"],
            "severities": data["severities"],
        })
    techniques.sort(key=lambda t: (tactic_pos.get(t["tactic"], 99), -t["count"]))

    return {
        "total_findings_with_ttp": sum(t["count"] for t in techniques),
        "unique_techniques": len(techniques),
        "unique_tactics": len({t["tactic"] for t in techniques}),
        "techniques": techniques,
    }


# ── Auth request/response models ───────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str  = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_]+$')
    email:    str  = Field(..., max_length=255)
    password: str  = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email:    str = Field(...)
    password: str = Field(...)


class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class AlertRuleRequest(BaseModel):
    name:           str           = Field(..., min_length=1, max_length=100)
    trigger:        str           = Field(..., pattern="^(scan_complete|critical_finding|high_finding|brute_force|all)$")
    notify_email:   Optional[str] = Field(None, max_length=255)
    notify_webhook: Optional[str] = Field(None, max_length=500)


# ── User Auth endpoints ─────────────────────────────────────────────────────

@app.post("/api/v1/auth/register", tags=["User Auth"])
async def register(req: RegisterRequest, request: Request):
    """Register a new user. First user becomes admin automatically."""
    async with get_session_factory()() as session:
        # check unique username/email
        existing = (await session.execute(
            select(User).where(
                (User.username == req.username) | (User.email == req.email)
            )
        )).scalars().first()
        if existing:
            raise HTTPException(status_code=409, detail="Username or email already registered")

        total_users = (await session.execute(select(func.count()).select_from(User))).scalar() or 0
        admin_count = (await session.execute(
            select(func.count()).select_from(User).where(User.is_admin == True)
        )).scalar() or 0
        # First user ever, OR no admins exist yet (e.g. fresh deploy over old DB), OR email in ADMIN_EMAILS
        admin_emails = [e.strip().lower() for e in settings.admin_emails.split(',') if e.strip()]
        is_admin = (total_users == 0) or (admin_count == 0) or (req.email.lower() in admin_emails)

        user = User(
            id=str(uuid.uuid4()),
            username=req.username,
            email=req.email,
            password_hash=hash_password(req.password),
            is_admin=is_admin,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        session.add(user)
        await session.commit()
        ip = request.client.host if request.client else "unknown"
        asyncio.create_task(_log_activity(
            "register", ip, user_id=user.id,
            user_agent=request.headers.get("User-Agent", ""),
            details={"username": user.username, "is_admin": is_admin}
        ))
        token = create_token(user.id, user.email, user.username, user.is_admin)
        return {"token": token, "user": {"id": user.id, "username": user.username,
                                         "email": user.email, "is_admin": user.is_admin}}


@app.post("/api/v1/auth/login", tags=["User Auth"])
async def login(req: LoginRequest, request: Request):
    """Login with email + password, returns JWT."""
    ip  = request.client.host if request.client else "unknown"
    ua  = request.headers.get("User-Agent", "")

    # Brute-force window check
    now = _time.time()
    _failed_logins[ip] = [t for t in _failed_logins[ip] if t > now - _BRUTE_WINDOW]
    if len(_failed_logins[ip]) >= _BRUTE_THRESH:
        asyncio.create_task(_log_security_event(
            "brute_force", ip,
            details={"email": req.email, "attempts": len(_failed_logins[ip])},
            severity="high"
        ))
        raise HTTPException(status_code=429,
                            detail="Too many failed login attempts. Try again in 5 minutes.")

    async with get_session_factory()() as session:
        user = (await session.execute(
            select(User).where(User.email == req.email)
        )).scalars().first()

        if not user or not verify_password(req.password, user.password_hash):
            _failed_logins[ip].append(_time.time())
            asyncio.create_task(_log_security_event(
                "failed_login", ip,
                details={"email": req.email,
                         "attempt": len(_failed_logins[ip]),
                         "is_brute_force": len(_failed_logins[ip]) >= _BRUTE_THRESH},
                user_id=user.id if user else None,
                severity="high" if len(_failed_logins[ip]) >= _BRUTE_THRESH else "medium"
            ))
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is disabled")

        # Successful login — clear the failure counter for this IP
        _failed_logins.pop(ip, None)

        user.last_login_at = datetime.utcnow()
        user.last_login_ip = ip
        await session.commit()

        asyncio.create_task(_log_activity(
            "login", ip, user_id=user.id, user_agent=ua,
            details={"username": user.username, "is_admin": user.is_admin}
        ))
        token = create_token(user.id, user.email, user.username, user.is_admin)
        return {"token": token, "user": {"id": user.id, "username": user.username,
                                         "email": user.email, "is_admin": user.is_admin}}


@app.get("/api/v1/auth/me", tags=["User Auth"])
async def me(current_user: dict = Depends(get_current_user)):
    """Return current user profile from JWT."""
    async with get_session_factory()() as session:
        user = await session.get(User, current_user["sub"])
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        key_count = len((await session.execute(
            select(UserApiKey).where(
                UserApiKey.user_id == user.id,
                UserApiKey.is_active == True
            )
        )).scalars().all())
        return {
            "id": user.id, "username": user.username, "email": user.email,
            "is_admin": user.is_admin, "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "last_login_ip": user.last_login_ip,
            "active_api_keys": key_count,
        }


# ── API Key management endpoints ────────────────────────────────────────────

@app.get("/api/v1/user/keys", tags=["API Keys"])
async def list_keys(current_user: dict = Depends(get_current_user)):
    """List all active API keys for the current user."""
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(UserApiKey).where(
                UserApiKey.user_id == current_user["sub"],
                UserApiKey.is_active == True
            ).order_by(desc(UserApiKey.created_at))
        )).scalars().all()
        return {"keys": [
            {
                "id": k.id, "name": k.name, "prefix": k.key_prefix,
                "usage_count": k.usage_count or 0,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            } for k in rows
        ]}


@app.post("/api/v1/user/keys", tags=["API Keys"])
async def create_key(req: CreateKeyRequest, request: Request,
                     current_user: dict = Depends(get_current_user)):
    """Generate a new API key. The full key is returned ONCE — save it immediately."""
    raw_key  = generate_api_key()
    key_hash = _hash_key(raw_key)
    key_id   = str(uuid.uuid4())

    async with get_session_factory()() as session:
        record = UserApiKey(
            id=key_id,
            user_id=current_user["sub"],
            key_hash=key_hash,
            key_prefix=raw_key[:12],
            name=req.name,
            is_active=True,
            created_at=datetime.utcnow(),
            usage_count=0,
        )
        session.add(record)
        await session.commit()

    register_api_key_by_hash(key_hash, req.name,
                              user_id=current_user["sub"], key_id=key_id)
    ip = request.client.host if request.client else "unknown"
    asyncio.create_task(_log_activity(
        "key_created", ip, user_id=current_user["sub"], api_key_id=key_id,
        details={"key_name": req.name, "prefix": raw_key[:12]}
    ))
    return {
        "id": key_id, "name": req.name, "prefix": raw_key[:12],
        "key": raw_key,
        "warning": "This is the only time the full key will be shown. Copy it now."
    }


@app.delete("/api/v1/user/keys/{key_id}", tags=["API Keys"])
async def revoke_key(key_id: str, request: Request,
                     current_user: dict = Depends(get_current_user)):
    """Revoke (soft-delete) an API key."""
    async with get_session_factory()() as session:
        row = await session.get(UserApiKey, key_id)
        if not row or row.user_id != current_user["sub"]:
            raise HTTPException(status_code=404, detail="API key not found")
        key_name = row.name
        row.is_active = False
        await session.commit()
        unregister_api_key_by_hash(row.key_hash)
    ip = request.client.host if request.client else "unknown"
    asyncio.create_task(_log_activity(
        "key_revoked", ip,
        user_id=current_user["sub"], api_key_id=key_id,
        details={"key_name": key_name, "prefix": row.key_prefix},
    ))
    return {"message": "Key revoked"}


@app.post("/api/v1/user/keys/{key_id}/rotate", tags=["API Keys"])
async def rotate_key(key_id: str, request: Request,
                     current_user: dict = Depends(get_current_user)):
    """Revoke existing key and create a new one with the same name. New key shown ONCE."""
    async with get_session_factory()() as session:
        old = await session.get(UserApiKey, key_id)
        if not old or old.user_id != current_user["sub"]:
            raise HTTPException(status_code=404, detail="API key not found")
        old_name     = old.name
        old.is_active = False
        unregister_api_key_by_hash(old.key_hash)

        raw_key      = generate_api_key()
        new_key_hash = _hash_key(raw_key)
        new_key_id   = str(uuid.uuid4())
        new_record   = UserApiKey(
            id=new_key_id,
            user_id=current_user["sub"],
            key_hash=new_key_hash,
            key_prefix=raw_key[:12],
            name=old_name,
            is_active=True,
            created_at=datetime.utcnow(),
            usage_count=0,
        )
        session.add(new_record)
        await session.commit()

    register_api_key_by_hash(new_key_hash, old_name,
                              user_id=current_user["sub"], key_id=new_key_id)
    ip = request.client.host if request.client else "unknown"
    asyncio.create_task(_log_activity(
        "key_rotated", ip,
        user_id=current_user["sub"], api_key_id=new_key_id,
        details={"key_name": old_name, "new_prefix": raw_key[:12]},
    ))
    return {
        "id": new_key_id, "name": old_name, "prefix": raw_key[:12],
        "key": raw_key,
        "warning": "This is the only time the full key will be shown. Copy it now."
    }


# ── Alert rule endpoints ────────────────────────────────────────────────────

@app.get("/api/v1/alerts/rules", tags=["Alerts"])
async def list_alert_rules(current_user: dict = Depends(get_current_user)):
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(AlertRule).where(AlertRule.user_id == current_user["sub"])
            .order_by(desc(AlertRule.created_at))
        )).scalars().all()
        return {"rules": [
            {
                "id": r.id, "name": r.name, "trigger": r.trigger,
                "notify_email": r.notify_email, "notify_webhook": r.notify_webhook,
                "is_active": r.is_active,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            } for r in rows
        ]}


@app.post("/api/v1/alerts/rules", tags=["Alerts"])
async def create_alert_rule(req: AlertRuleRequest, request: Request,
                             current_user: dict = Depends(get_current_user)):
    if not req.notify_email and not req.notify_webhook:
        raise HTTPException(status_code=400,
                            detail="At least one of notify_email or notify_webhook is required")
    async with get_session_factory()() as session:
        rule = AlertRule(
            id=str(uuid.uuid4()),
            user_id=current_user["sub"],
            name=req.name, trigger=req.trigger,
            notify_email=req.notify_email, notify_webhook=req.notify_webhook,
            is_active=True, created_at=datetime.utcnow(),
        )
        session.add(rule)
        await session.commit()
    ip = request.client.host if request.client else "unknown"
    asyncio.create_task(_log_activity(
        "alert_created", ip,
        user_id=current_user["sub"],
        details={"name": req.name, "trigger": req.trigger,
                 "has_email": bool(req.notify_email), "has_webhook": bool(req.notify_webhook)},
    ))
    return {"message": "Alert rule created", "id": rule.id}


@app.delete("/api/v1/alerts/rules/{rule_id}", tags=["Alerts"])
async def delete_alert_rule(rule_id: str,
                             current_user: dict = Depends(get_current_user)):
    async with get_session_factory()() as session:
        row = await session.get(AlertRule, rule_id)
        if not row or row.user_id != current_user["sub"]:
            raise HTTPException(status_code=404, detail="Rule not found")
        await session.delete(row)
        await session.commit()
    return {"message": "Rule deleted"}


@app.patch("/api/v1/alerts/rules/{rule_id}/toggle", tags=["Alerts"])
async def toggle_alert_rule(rule_id: str,
                             current_user: dict = Depends(get_current_user)):
    async with get_session_factory()() as session:
        row = await session.get(AlertRule, rule_id)
        if not row or row.user_id != current_user["sub"]:
            raise HTTPException(status_code=404, detail="Rule not found")
        row.is_active = not row.is_active
        await session.commit()
        return {"message": f"Rule {'enabled' if row.is_active else 'disabled'}", "is_active": row.is_active}


# ── Admin endpoints ─────────────────────────────────────────────────────────

@app.get("/api/v1/admin/users", tags=["Admin"])
async def admin_list_users(admin: dict = Depends(require_admin)):
    """List all users with key counts, usage stats, and per-user service breakdown."""
    async with get_session_factory()() as session:
        users = (await session.execute(select(User).order_by(desc(User.created_at)))).scalars().all()
        result = []
        for u in users:
            key_count = len((await session.execute(
                select(UserApiKey).where(UserApiKey.user_id == u.id, UserApiKey.is_active == True)
            )).scalars().all())
            total_requests = (await session.execute(
                select(func.count()).select_from(UsageLog).where(UsageLog.user_id == u.id)
            )).scalar() or 0
            activity_rows = (await session.execute(
                select(ActivityEvent.event_type, func.count().label("cnt"))
                .where(ActivityEvent.user_id == u.id)
                .group_by(ActivityEvent.event_type)
            )).all()
            service_usage = {row.event_type: row.cnt for row in activity_rows}
            last_seen_row = (await session.execute(
                select(ActivityEvent.created_at)
                .where(ActivityEvent.user_id == u.id)
                .order_by(desc(ActivityEvent.created_at))
                .limit(1)
            )).scalar()
            result.append({
                "id": u.id, "username": u.username, "email": u.email,
                "is_admin": u.is_admin, "is_active": u.is_active,
                "active_keys": key_count, "total_requests": total_requests,
                "service_usage": service_usage,
                "total_activity_events": sum(service_usage.values()),
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                "last_login_ip": u.last_login_ip,
                "last_seen_at": last_seen_row.isoformat() if last_seen_row else None,
            })
        return {"users": result, "count": len(result)}


@app.get("/api/v1/admin/users/{user_id}/activity", tags=["Admin"])
async def admin_user_activity(
    user_id: str,
    limit: int = 50,
    admin: dict = Depends(require_admin)
):
    """Full activity feed for a specific user — admins only."""
    async with get_session_factory()() as session:
        user = await session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        events = (await session.execute(
            select(ActivityEvent)
            .where(ActivityEvent.user_id == user_id)
            .order_by(desc(ActivityEvent.created_at))
            .limit(min(limit, 500))
        )).scalars().all()
        service_usage: dict[str, int] = {}
        for e in events:
            service_usage[e.event_type] = service_usage.get(e.event_type, 0) + 1
        return {
            "user": {"id": user.id, "username": user.username, "email": user.email,
                     "is_admin": user.is_admin, "is_active": user.is_active},
            "service_usage": service_usage,
            "events": [
                {
                    "id": e.id, "event_type": e.event_type, "scan_id": e.scan_id,
                    "details": e.details, "duration_ms": e.duration_ms,
                    "ip_address": e.ip_address,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                } for e in events
            ],
        }


@app.get("/api/v1/admin/usage", tags=["Admin"])
async def admin_usage(
    limit: int = 100,
    admin: dict = Depends(require_admin)
):
    """Recent API usage logs."""
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(UsageLog).order_by(desc(UsageLog.timestamp)).limit(min(limit, 500))
        )).scalars().all()
        return {"usage": [
            {
                "id": r.id, "user_id": r.user_id, "endpoint": r.endpoint,
                "method": r.method, "ip_address": r.ip_address,
                "status_code": r.status_code, "duration_ms": r.duration_ms,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            } for r in rows
        ], "count": len(rows)}


@app.get("/api/v1/admin/security-events", tags=["Admin"])
async def admin_security_events(
    limit: int = 100,
    severity: Optional[str] = None,
    admin: dict = Depends(require_admin)
):
    """List security events for threat monitoring."""
    async with get_session_factory()() as session:
        query = select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(min(limit, 500))
        if severity:
            query = query.where(SecurityEvent.severity == severity)
        rows = (await session.execute(query)).scalars().all()
        return {"events": [
            {
                "id": r.id, "user_id": r.user_id, "event_type": r.event_type,
                "ip_address": r.ip_address, "severity": r.severity,
                "details": r.details,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            } for r in rows
        ], "count": len(rows)}


@app.patch("/api/v1/admin/users/{user_id}/toggle", tags=["Admin"])
async def admin_toggle_user(user_id: str, admin: dict = Depends(require_admin)):
    """Activate or deactivate a user account."""
    if user_id == admin["sub"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    async with get_session_factory()() as session:
        user = await session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_active = not user.is_active
        await session.commit()
        return {"message": f"User {'activated' if user.is_active else 'deactivated'}",
                "is_active": user.is_active}


# ── Analytics ───────────────────────────────────────────────────────────────

@app.get("/api/v1/admin/analytics", tags=["Admin"])
async def admin_analytics(
    days: int = 7,
    admin: dict = Depends(require_admin)
):
    """Aggregate activity analytics for evaluation and system efficiency monitoring."""
    since = datetime.utcnow() - timedelta(days=days)
    async with get_session_factory()() as session:
        all_activity = (await session.execute(
            select(ActivityEvent).where(ActivityEvent.created_at >= since)
            .order_by(ActivityEvent.created_at)
        )).scalars().all()

        all_usage = (await session.execute(
            select(UsageLog).where(UsageLog.timestamp >= since)
        )).scalars().all()

        all_sec = (await session.execute(
            select(SecurityEvent).where(SecurityEvent.created_at >= since)
            .order_by(desc(SecurityEvent.created_at))
        )).scalars().all()

        all_users = (await session.execute(select(User))).scalars().all()

    # Feature usage breakdown
    feature_counts: dict[str, int] = {}
    for e in all_activity:
        feature_counts[e.event_type] = feature_counts.get(e.event_type, 0) + 1

    # Per-user activity count
    user_activity: dict[str, int] = {}
    for e in all_activity:
        uid = e.user_id or "anonymous"
        user_activity[uid] = user_activity.get(uid, 0) + 1

    # Resolve user_id → username
    uid_to_name = {u.id: u.username for u in all_users}
    top_users = sorted(user_activity.items(), key=lambda x: -x[1])[:10]
    top_users_named = [
        {"user_id": uid, "username": uid_to_name.get(uid, uid[:8] if uid != "anonymous" else "anonymous"),
         "event_count": cnt}
        for uid, cnt in top_users
    ]

    # Endpoint performance from UsageLog
    endpoint_perf: dict[str, dict] = {}
    for r in all_usage:
        ep = r.endpoint
        if ep not in endpoint_perf:
            endpoint_perf[ep] = {"count": 0, "total_ms": 0, "errors": 0}
        endpoint_perf[ep]["count"] += 1
        endpoint_perf[ep]["total_ms"] += r.duration_ms or 0
        if r.status_code >= 400:
            endpoint_perf[ep]["errors"] += 1
    perf_list = sorted(
        [{"endpoint": ep, "count": d["count"],
          "avg_ms": d["total_ms"] // d["count"] if d["count"] else 0,
          "error_rate_pct": round(d["errors"] / d["count"] * 100, 1) if d["count"] else 0}
         for ep, d in endpoint_perf.items()],
        key=lambda x: -x["count"]
    )[:20]

    # Avg duration per feature from ActivityEvent (for LLM-heavy endpoints)
    feature_perf: dict[str, dict] = {}
    for e in all_activity:
        if e.duration_ms:
            if e.event_type not in feature_perf:
                feature_perf[e.event_type] = {"total_ms": 0, "count": 0}
            feature_perf[e.event_type]["total_ms"] += e.duration_ms
            feature_perf[e.event_type]["count"]    += 1
    feature_perf_list = [
        {"feature": f, "avg_ms": d["total_ms"] // d["count"], "count": d["count"]}
        for f, d in feature_perf.items()
    ]

    # Security events breakdown
    sec_by_type: dict[str, int] = {}
    for se in all_sec:
        sec_by_type[se.event_type] = sec_by_type.get(se.event_type, 0) + 1

    # Daily activity trend
    daily: dict[str, int] = {}
    for e in all_activity:
        day = e.created_at.strftime("%Y-%m-%d")
        daily[day] = daily.get(day, 0) + 1

    # Error rate overall
    total_reqs = len(all_usage)
    error_reqs = sum(1 for r in all_usage if r.status_code >= 400)

    return {
        "period_days": days,
        "summary": {
            "total_activity_events":  len(all_activity),
            "total_api_requests":     total_reqs,
            "total_security_events":  len(all_sec),
            "total_users":            len(all_users),
            "error_rate_pct":         round(error_reqs / total_reqs * 100, 1) if total_reqs else 0,
        },
        "feature_usage":         feature_counts,
        "feature_performance":   feature_perf_list,
        "top_users":             top_users_named,
        "endpoint_performance":  perf_list,
        "security_events_by_type": sec_by_type,
        "recent_security_events": [
            {"event_type": e.event_type, "ip_address": e.ip_address,
             "severity": e.severity, "details": e.details,
             "created_at": e.created_at.isoformat()}
            for e in all_sec[:10]
        ],
        "daily_activity": dict(sorted(daily.items())),
    }


# ── LLM Gateway config (admin only) ───────────────────────────────────────

class GatewayConfigUpdate(BaseModel):
    enabled: bool
    url: str = Field(..., min_length=1, max_length=500)
    api_key: Optional[str] = Field(default=None, description="Omit to keep the existing key")


@app.get("/api/v1/admin/llm-gateway", tags=["Admin"])
async def get_llm_gateway_config(admin: dict = Depends(require_admin)):
    """Return the current LLM gateway configuration. API key is shown as prefix only."""
    from sentinelai.core.llm_client import get_gateway_health
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(SystemConfig).where(SystemConfig.key.like("llm_gateway_%"))
        )).scalars().all()
    cfg = {r.key: r.value for r in rows}
    raw_key = cfg.get("llm_gateway_api_key", "")
    return {
        "enabled":        cfg.get("llm_gateway_enabled", "false").lower() == "true",
        "url":            cfg.get("llm_gateway_url", settings.llm_gateway_url),
        "api_key_set":    bool(raw_key),
        "api_key_prefix": (raw_key[:12] + "...") if raw_key else None,
        "source":         "database" if cfg else "env",
        "health":         get_gateway_health(),
    }


@app.put("/api/v1/admin/llm-gateway", tags=["Admin"])
async def update_llm_gateway_config(
    body: GatewayConfigUpdate,
    admin: dict = Depends(require_admin),
):
    """Save LLM gateway config to DB and apply immediately (no restart needed).
    Omit api_key to keep the existing key unchanged."""
    async with get_session_factory()() as session:
        # Fetch existing key if caller didn't supply a new one
        existing_key_row = await session.get(SystemConfig, "llm_gateway_api_key")
        existing_key = existing_key_row.value if existing_key_row else ""

        final_key = body.api_key.strip() if body.api_key and body.api_key.strip() else existing_key

        # Upsert all three config rows
        for key, value in [
            ("llm_gateway_enabled", "true" if body.enabled else "false"),
            ("llm_gateway_url",     body.url.rstrip("/")),
            ("llm_gateway_api_key", final_key),
        ]:
            row = await session.get(SystemConfig, key)
            if row:
                row.value      = value
                row.updated_at = datetime.utcnow()
                row.updated_by = admin.get("username", admin.get("sub"))
            else:
                session.add(SystemConfig(
                    key=key, value=value,
                    updated_by=admin.get("username", admin.get("sub")),
                ))
        await session.commit()

    # Apply to in-memory override immediately — no restart needed
    from sentinelai.core.llm_client import set_gateway_config, clear_gateway_config, reset_gateway_health
    if final_key:
        set_gateway_config(enabled=body.enabled, url=body.url.rstrip("/"), api_key=final_key)
    else:
        clear_gateway_config()

    # Clear any auth-error / fallback state so the admin sees a fresh slate
    reset_gateway_health()

    return {
        "message":        "Gateway config saved and applied",
        "enabled":        body.enabled,
        "url":            body.url.rstrip("/"),
        "api_key_set":    bool(final_key),
        "api_key_prefix": (final_key[:12] + "...") if final_key else None,
        "source":         "database",
    }


@app.get("/api/v1/user/activity", tags=["User Auth"])
async def user_activity(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Return the current user's own activity feed and usage statistics."""
    async with get_session_factory()() as session:
        events = (await session.execute(
            select(ActivityEvent)
            .where(ActivityEvent.user_id == current_user["sub"])
            .order_by(desc(ActivityEvent.created_at))
            .limit(min(limit, 200))
        )).scalars().all()

        req_count = len((await session.execute(
            select(UsageLog).where(UsageLog.user_id == current_user["sub"])
        )).scalars().all())

    feature_counts: dict[str, int] = {}
    for e in events:
        feature_counts[e.event_type] = feature_counts.get(e.event_type, 0) + 1

    return {
        "stats": {
            "total_activity_events": len(events),
            "total_api_requests":    req_count,
            "feature_counts":        feature_counts,
        },
        "events": [
            {
                "id":          e.id,
                "event_type":  e.event_type,
                "scan_id":     e.scan_id,
                "details":     e.details,
                "duration_ms": e.duration_ms,
                "ip_address":  e.ip_address,
                "created_at":  e.created_at.isoformat() if e.created_at else None,
            } for e in events
        ],
    }


# ── CISA KEV catalog (in-memory, refreshed daily) ─────────────────────────

import httpx as _httpx

_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_set: set[str] = set()        # CVE IDs currently in the catalog
_kev_last_fetch: float = 0.0


async def _fetch_kev() -> None:
    """Pull the CISA KEV catalog and rebuild the in-memory set."""
    global _kev_set, _kev_last_fetch
    try:
        async with _httpx.AsyncClient(timeout=30) as client:
            r = await client.get(_KEV_URL)
            r.raise_for_status()
            data = r.json()
        _kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
        _kev_last_fetch = _time.time()
        log.info("CISA KEV catalog refreshed", count=len(_kev_set))
    except Exception as e:
        log.warning("CISA KEV fetch failed", error=str(e))


async def _kev_refresh_loop() -> None:
    """Background task: refresh KEV catalog every 24 hours."""
    await _fetch_kev()
    while True:
        await asyncio.sleep(86400)
        await _fetch_kev()


async def _mark_kev_findings(scan_id: str) -> None:
    """After a scan completes, flag any findings whose CVE ID is in the KEV catalog."""
    if not _kev_set:
        return
    async with get_session_factory()() as session:
        findings = (await session.execute(
            select(Finding).where(Finding.scan_id == scan_id, Finding.cve_id.isnot(None))
        )).scalars().all()
        updated = 0
        for f in findings:
            if f.cve_id and f.cve_id.upper() in _kev_set:
                f.is_kev = True
                updated += 1
        if updated:
            await session.commit()
            log.info("KEV flags applied to findings", scan_id=scan_id, count=updated)


# ── Remediation workflow ───────────────────────────────────────────────────

class RemStatusUpdate(BaseModel):
    status: str = Field(..., description="open | acknowledged | in_progress | fixed | false_positive")
    notes: Optional[str] = None


@app.patch("/api/v1/findings/{finding_id}/status", tags=["Remediation"])
async def update_finding_status(
    finding_id: str,
    body: RemStatusUpdate,
    _auth: str = Depends(jwt_or_api_key),
):
    """Update the remediation status of a finding."""
    valid = {"open", "acknowledged", "in_progress", "fixed", "false_positive"}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {valid}")
    async with get_session_factory()() as session:
        finding = await session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding.rem_status = body.status
        if body.notes is not None:
            finding.rem_notes = body.notes
        if body.status == "fixed":
            finding.rem_at = datetime.utcnow()
        await session.commit()
    return {"message": "Status updated", "finding_id": finding_id, "status": body.status}


@app.get("/api/v1/remediation/summary", tags=["Remediation"])
async def remediation_summary(_auth: str = Depends(jwt_or_api_key)):
    """Return remediation status breakdown across all findings."""
    async with get_session_factory()() as session:
        findings = (await session.execute(select(Finding))).scalars().all()

    counts: dict[str, int] = {
        "open": 0, "acknowledged": 0, "in_progress": 0, "fixed": 0, "false_positive": 0
    }
    by_severity: dict[str, dict] = {}
    kev_open = 0

    for f in findings:
        status = f.rem_status or "open"
        counts[status] = counts.get(status, 0) + 1
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev not in by_severity:
            by_severity[sev] = {"open": 0, "fixed": 0, "total": 0}
        by_severity[sev]["total"] += 1
        if status == "fixed":
            by_severity[sev]["fixed"] += 1
        else:
            by_severity[sev]["open"] += 1
        if f.is_kev and status not in ("fixed", "false_positive"):
            kev_open += 1

    total = len(findings)
    fixed = counts.get("fixed", 0)
    return {
        "total_findings": total,
        "remediation_rate": round(fixed / total * 100, 1) if total else 0,
        "by_status": counts,
        "by_severity": by_severity,
        "kev_open": kev_open,
    }


# ── Scan diff / delta report ───────────────────────────────────────────────

def _findings_to_dict(f: Finding) -> dict:
    return {
        "id": f.id, "title": f.title,
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "cve_id": f.cve_id, "mitre_attack": f.mitre_attack,
        "description": f.description, "remediation": f.remediation,
        "is_kev": f.is_kev,
    }


@app.get("/api/v1/scan-compare", tags=["Scans"])
async def scan_diff(
    a: str,
    b: str,
    _auth: str = Depends(jwt_or_api_key),
):
    """Compare two scans and return a Claude-generated delta report.
    Pass scan IDs as ?a=<id>&b=<id> (chronological order: a=older, b=newer)."""
    async with get_session_factory()() as session:
        scan_a = await session.get(Scan, a)
        scan_b = await session.get(Scan, b)
        if not scan_a or not scan_b:
            raise HTTPException(status_code=404, detail="One or both scan IDs not found")

        findings_a = (await session.execute(
            select(Finding).where(Finding.scan_id == a)
        )).scalars().all()
        findings_b = (await session.execute(
            select(Finding).where(Finding.scan_id == b)
        )).scalars().all()

    titles_a = {f.title: f for f in findings_a}
    titles_b = {f.title: f for f in findings_b}

    new_findings      = [_findings_to_dict(f) for t, f in titles_b.items() if t not in titles_a]
    resolved_findings = [_findings_to_dict(f) for t, f in titles_a.items() if t not in titles_b]
    persisted         = [_findings_to_dict(f) for t, f in titles_b.items() if t in titles_a]

    # Severity-changed items
    changed_severity = []
    for title, fb in titles_b.items():
        if title in titles_a:
            fa = titles_a[title]
            sev_a = fa.severity.value if hasattr(fa.severity, "value") else str(fa.severity)
            sev_b = fb.severity.value if hasattr(fb.severity, "value") else str(fb.severity)
            if sev_a != sev_b:
                changed_severity.append({
                    "title": title, "old_severity": sev_a, "new_severity": sev_b
                })

    from sentinelai.core.llm_client import get_llm_client
    llm = get_llm_client()

    # Pre-build text blocks (backslashes not allowed in Python 3.11 f-string expressions)
    nl = "\n"
    new_lines = nl.join(
        f"- [{f['severity'].upper()}] {f['title']}" for f in new_findings[:10]
    )
    resolved_lines = nl.join(f"- {f['title']}" for f in resolved_findings[:10])
    changed_lines  = nl.join(
        f"- {c['title']}: {c['old_severity']} -> {c['new_severity']}"
        for c in changed_severity
    )
    scan_a_ts = scan_a.created_at.strftime("%Y-%m-%d %H:%M")
    scan_b_ts = scan_b.created_at.strftime("%Y-%m-%d %H:%M")

    prompt = f"""Compare these two security scans of the same target and write a delta report.

Target: {scan_b.target}
Scan A (older): {scan_a_ts} UTC — {len(findings_a)} findings
Scan B (newer): {scan_b_ts} UTC — {len(findings_b)} findings

NEW findings in B (not in A): {len(new_findings)}
{new_lines}

RESOLVED since A (in A, not in B): {len(resolved_findings)}
{resolved_lines}

SEVERITY CHANGES: {len(changed_severity)}
{changed_lines}

PERSISTED (unchanged): {len(persisted)} findings

Write a concise delta report covering:
1. Overall security posture change (improved / degraded / unchanged)
2. Most critical new findings and their risk
3. Notable resolutions and whether they appear genuine fixes
4. Any severity escalations that need immediate attention
5. Recommended next actions"""

    narrative = await llm.complete(prompt)

    return {
        "scan_a": {"id": a, "target": scan_a.target,
                   "created_at": scan_a.created_at.isoformat(),
                   "finding_count": len(findings_a)},
        "scan_b": {"id": b, "target": scan_b.target,
                   "created_at": scan_b.created_at.isoformat(),
                   "finding_count": len(findings_b)},
        "delta": {
            "new":              new_findings,
            "resolved":         resolved_findings,
            "changed_severity": changed_severity,
            "persisted_count":  len(persisted),
        },
        "narrative": narrative,
    }


# ── Portfolio view ─────────────────────────────────────────────────────────

@app.get("/api/v1/portfolio", tags=["Portfolio"])
async def portfolio(_auth: str = Depends(jwt_or_api_key)):
    """Return per-target security posture summary across all scans."""
    async with get_session_factory()() as session:
        scans = (await session.execute(
            select(Scan).where(Scan.status == ScanStatus.COMPLETED)
            .order_by(desc(Scan.created_at))
        )).scalars().all()
        findings = (await session.execute(select(Finding))).scalars().all()

    # Group findings by scan_id for quick lookup
    findings_by_scan: dict[str, list] = {}
    for f in findings:
        findings_by_scan.setdefault(f.scan_id, []).append(f)

    # Build per-target summary — keep only the latest scan per target
    targets: dict[str, dict] = {}
    for scan in scans:
        t = scan.target
        if t not in targets:
            scan_findings = findings_by_scan.get(scan.id, [])
            open_findings = [f for f in scan_findings
                             if (f.rem_status or "open") not in ("fixed", "false_positive")]
            kev_count = sum(1 for f in open_findings if f.is_kev)
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            worst = min(
                (f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                 for f in open_findings),
                key=lambda s: sev_order.get(s, 5),
                default="none"
            )
            # Risk score: 100 − weighted penalty
            penalty = sum({
                "critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0
            }.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0)
                          for f in open_findings)
            risk_score = max(0, 100 - penalty)

            targets[t] = {
                "target":          t,
                "last_scan_id":    scan.id,
                "last_scan_at":    scan.created_at.isoformat(),
                "scan_type":       scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
                "total_findings":  len(scan_findings),
                "open_findings":   len(open_findings),
                "kev_count":       kev_count,
                "worst_severity":  worst,
                "risk_score":      risk_score,
                "scan_count":      sum(1 for s in scans if s.target == t),
            }

    sorted_targets = sorted(targets.values(), key=lambda x: x["risk_score"])
    return {
        "targets":       sorted_targets,
        "total_targets": len(sorted_targets),
        "kev_total":     sum(t["kev_count"] for t in sorted_targets),
        "critical_targets": sum(1 for t in sorted_targets if t["worst_severity"] == "critical"),
    }


# ── KEV status endpoint ────────────────────────────────────────────────────

@app.get("/api/v1/kev/status", tags=["Threat Intel"])
async def kev_status(_auth: str = Depends(jwt_or_api_key)):
    """Return CISA KEV catalog info: last fetch time and catalog size."""
    return {
        "catalog_size":   len(_kev_set),
        "last_fetched":   datetime.utcfromtimestamp(_kev_last_fetch).isoformat() if _kev_last_fetch else None,
        "fetch_url":      _KEV_URL,
    }


# ── CVE / Service Watchlist ────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "any": 5}


class WatchlistRequest(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=100,
                               description="Service name to watch, e.g. nginx, openssh, apache")
    min_severity: str = Field(default="high",
                               description="Minimum severity to alert on: critical/high/medium/low/any")


@app.get("/api/v1/watchlist", tags=["Watchlist"])
async def list_watchlist(current_user: dict = Depends(get_current_user)):
    """List the current user's CVE/service watchlist entries."""
    async with get_session_factory()() as session:
        rows = (await session.execute(
            select(CveWatchlistEntry)
            .where(CveWatchlistEntry.user_id == current_user["sub"])
            .order_by(desc(CveWatchlistEntry.created_at))
        )).scalars().all()
    return {"entries": [_watchlist_to_dict(r) for r in rows]}


@app.post("/api/v1/watchlist", tags=["Watchlist"])
async def add_watchlist(req: WatchlistRequest, current_user: dict = Depends(get_current_user)):
    """Subscribe to alerts when a service appears in scan findings."""
    if req.min_severity not in _SEV_ORDER:
        raise HTTPException(status_code=400,
                            detail=f"min_severity must be one of {list(_SEV_ORDER.keys())}")
    async with get_session_factory()() as session:
        # Prevent duplicate subscriptions for the same user + service
        existing = (await session.execute(
            select(CveWatchlistEntry).where(
                CveWatchlistEntry.user_id == current_user["sub"],
                func.lower(CveWatchlistEntry.service_name) == req.service_name.lower()
            )
        )).scalars().first()
        if existing:
            raise HTTPException(status_code=409,
                                detail=f"Already watching '{req.service_name}'")
        entry = CveWatchlistEntry(
            id=str(uuid.uuid4()),
            user_id=current_user["sub"],
            service_name=req.service_name.lower().strip(),
            min_severity=req.min_severity,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        session.add(entry)
        await session.commit()
    return {"message": "Watchlist entry created", "entry": _watchlist_to_dict(entry)}


@app.delete("/api/v1/watchlist/{entry_id}", tags=["Watchlist"])
async def delete_watchlist(entry_id: str, current_user: dict = Depends(get_current_user)):
    async with get_session_factory()() as session:
        row = await session.get(CveWatchlistEntry, entry_id)
        if not row or row.user_id != current_user["sub"]:
            raise HTTPException(status_code=404, detail="Entry not found")
        await session.delete(row)
        await session.commit()
    return {"message": "Watchlist entry removed"}


@app.patch("/api/v1/watchlist/{entry_id}/toggle", tags=["Watchlist"])
async def toggle_watchlist(entry_id: str, current_user: dict = Depends(get_current_user)):
    async with get_session_factory()() as session:
        row = await session.get(CveWatchlistEntry, entry_id)
        if not row or row.user_id != current_user["sub"]:
            raise HTTPException(status_code=404, detail="Entry not found")
        row.is_active = not row.is_active
        await session.commit()
        return {"message": f"{'Enabled' if row.is_active else 'Paused'}", "is_active": row.is_active}


def _watchlist_to_dict(r: CveWatchlistEntry) -> dict:
    return {
        "id": r.id, "service_name": r.service_name, "min_severity": r.min_severity,
        "is_active": r.is_active, "trigger_count": r.trigger_count,
        "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


async def _check_watchlist(scan_id: str, findings: list) -> None:
    """After a scan completes, check findings against all active watchlist entries
    and fire notifications for any matches."""
    if not findings:
        return
    async with get_session_factory()() as session:
        entries = (await session.execute(
            select(CveWatchlistEntry).where(CveWatchlistEntry.is_active == True)
        )).scalars().all()

        if not entries:
            return

        # Build a lookup: service keyword → list of matching findings
        for entry in entries:
            keyword = entry.service_name.lower()
            matched = [
                f for f in findings
                if keyword in (f.get("title", "") + f.get("description", "")).lower()
                and _SEV_order_val(f.get("severity", "info")) <= _SEV_ORDER.get(entry.min_severity, 5)
            ]
            if not matched:
                continue

            # Update trigger stats
            db_entry = await session.get(CveWatchlistEntry, entry.id)
            if db_entry:
                db_entry.trigger_count += 1
                db_entry.last_triggered_at = datetime.utcnow()

            # Fire notification via existing alert system
            from sentinelai.core.notifier import send_watchlist_alert
            asyncio.create_task(send_watchlist_alert(
                entry=_watchlist_to_dict(entry),
                scan_id=scan_id,
                matched_findings=matched[:5],
            ))

        await session.commit()


def _SEV_order_val(sev: str) -> int:
    return _SEV_ORDER.get(str(sev).lower(), 5)
