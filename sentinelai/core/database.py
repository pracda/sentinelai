"""
Database setup and models for SentinelAI.
Uses SQLAlchemy async with SQLite (dev) or PostgreSQL (prod).
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime, Enum, JSON, Integer, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import enum

from sentinelai.core.config import get_settings


# ── Base ──────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────

class ScanType(str, enum.Enum):
    RECON       = "recon"
    VULN        = "vuln"
    LOG_ANALYSE = "log_analyse"
    FULL        = "full"


class ScanStatus(str, enum.Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ── Models ─────────────────────────────────────────────────────────────────

class Scan(Base):
    """Top-level record for each security scan."""
    __tablename__ = "scans"

    id:            Mapped[str]             = mapped_column(String(36), primary_key=True)
    target:        Mapped[str]             = mapped_column(String(255))
    scan_type:     Mapped[ScanType]        = mapped_column(Enum(ScanType))
    status:        Mapped[ScanStatus]      = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    authorized_by: Mapped[str]             = mapped_column(String(255))
    created_at:    Mapped[datetime]        = mapped_column(DateTime, default=datetime.utcnow)
    completed_at:  Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error:         Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    raw_results:   Mapped[Optional[dict]]  = mapped_column(JSON, nullable=True)
    llm_analysis:  Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    summary:       Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    finding_count: Mapped[int]             = mapped_column(Integer, default=0)
    critical_count: Mapped[int]            = mapped_column(Integer, default=0)
    high_count:    Mapped[int]             = mapped_column(Integer, default=0)


class Finding(Base):
    """Individual security finding from a scan."""
    __tablename__ = "findings"

    id:            Mapped[str]      = mapped_column(String(36), primary_key=True)
    scan_id:       Mapped[str]      = mapped_column(String(36))
    title:         Mapped[str]      = mapped_column(String(500))
    description:   Mapped[str]      = mapped_column(Text)
    severity:      Mapped[Severity] = mapped_column(Enum(Severity))
    cvss_score:    Mapped[Optional[float]] = mapped_column(nullable=True)
    cve_id:        Mapped[Optional[str]]   = mapped_column(String(20), nullable=True)
    mitre_attack:  Mapped[Optional[str]]   = mapped_column(String(50), nullable=True)
    evidence:      Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    remediation:   Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    created_at:    Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Schedule(Base):
    """Recurring scan schedule — triggers a scan automatically at a fixed interval."""
    __tablename__ = "schedules"

    id:            Mapped[str]           = mapped_column(String(36), primary_key=True)
    name:          Mapped[str]           = mapped_column(String(255))
    target:        Mapped[str]           = mapped_column(String(255))
    scan_type:     Mapped[ScanType]      = mapped_column(Enum(ScanType))
    interval_hours: Mapped[int]          = mapped_column(Integer)           # 1, 6, 24, 168
    authorized_by: Mapped[str]           = mapped_column(String(255))
    enabled:       Mapped[bool]          = mapped_column(Boolean, default=True)
    last_run:      Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_run:      Mapped[datetime]      = mapped_column(DateTime)
    created_at:    Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)


class LogAnalysis(Base):
    """Results from a log file analysis."""
    __tablename__ = "log_analyses"

    id:              Mapped[str]      = mapped_column(String(36), primary_key=True)
    scan_id:         Mapped[str]      = mapped_column(String(36))
    log_source:      Mapped[str]      = mapped_column(String(255))
    log_type:        Mapped[str]      = mapped_column(String(50))
    lines_analysed:  Mapped[int]      = mapped_column(Integer, default=0)
    anomalies_found: Mapped[int]      = mapped_column(Integer, default=0)
    iocs_extracted:  Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    attack_timeline: Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    llm_analysis:    Mapped[Optional[str]]  = mapped_column(Text, nullable=True)
    created_at:      Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ── User & Auth models ─────────────────────────────────────────────────────

class User(Base):
    """Registered SentinelAI user."""
    __tablename__ = "users"

    id:            Mapped[str]      = mapped_column(String(36), primary_key=True)
    username:      Mapped[str]      = mapped_column(String(100), unique=True)
    email:         Mapped[str]      = mapped_column(String(255), unique=True)
    password_hash: Mapped[str]      = mapped_column(String(255))
    is_admin:      Mapped[bool]     = mapped_column(Boolean, default=False)
    is_active:     Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at:    Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[Optional[str]]      = mapped_column(String(45), nullable=True)


class UserApiKey(Base):
    """API key belonging to a user — used to authenticate scan endpoints."""
    __tablename__ = "user_api_keys"

    id:           Mapped[str]      = mapped_column(String(36), primary_key=True)
    user_id:      Mapped[str]      = mapped_column(String(36))
    key_hash:     Mapped[str]      = mapped_column(String(64))   # sha256 hex
    key_prefix:   Mapped[str]      = mapped_column(String(12))   # first 12 chars for display
    name:         Mapped[str]      = mapped_column(String(100))
    is_active:    Mapped[bool]     = mapped_column(Boolean, default=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    usage_count:  Mapped[int]      = mapped_column(Integer, default=0)


class UsageLog(Base):
    """Per-request audit log — tracks who called what, when, and from where."""
    __tablename__ = "usage_logs"

    id:          Mapped[str]           = mapped_column(String(36), primary_key=True)
    user_id:     Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    api_key_id:  Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    endpoint:    Mapped[str]           = mapped_column(String(255))
    method:      Mapped[str]           = mapped_column(String(10))
    ip_address:  Mapped[str]           = mapped_column(String(45))
    status_code: Mapped[int]           = mapped_column(Integer)
    duration_ms: Mapped[int]           = mapped_column(Integer, default=0)
    timestamp:   Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)


class SecurityEvent(Base):
    """Security-relevant events: failed logins, brute force, rate limit hits, etc."""
    __tablename__ = "security_events"

    id:         Mapped[str]           = mapped_column(String(36), primary_key=True)
    user_id:    Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str]           = mapped_column(String(50))
    ip_address: Mapped[str]           = mapped_column(String(45))
    details:    Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    severity:   Mapped[str]           = mapped_column(String(20), default="medium")
    created_at: Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)


class AlertRule(Base):
    """User-defined alert rule — triggers email/webhook on scan events."""
    __tablename__ = "alert_rules"

    id:             Mapped[str]           = mapped_column(String(36), primary_key=True)
    user_id:        Mapped[str]           = mapped_column(String(36))
    name:           Mapped[str]           = mapped_column(String(100))
    trigger:        Mapped[str]           = mapped_column(String(50))
    notify_email:   Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notify_webhook: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active:      Mapped[bool]          = mapped_column(Boolean, default=True)
    created_at:     Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)


class ActivityEvent(Base):
    """Semantic audit of user actions — captures WHAT users did and how the system performed.

    Complements UsageLog (raw HTTP) with intent-level context:
    event_type values: log_analysis, attack_chain, vuln_scan, pdf_download,
                       key_created, key_rotated, key_revoked,
                       alert_created, alert_deleted, schedule_created,
                       login, logout, register
    """
    __tablename__ = "activity_events"

    id:          Mapped[str]           = mapped_column(String(36), primary_key=True)
    user_id:     Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    api_key_id:  Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    event_type:  Mapped[str]           = mapped_column(String(100))
    scan_id:     Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    details:     Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ip_address:  Mapped[str]           = mapped_column(String(45))
    user_agent:  Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at:  Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)


# ── Engine and session ─────────────────────────────────────────────────────

_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.environment == "development"
        )
    return _engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _session_factory


async def init_db():
    """Create all tables on startup."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
