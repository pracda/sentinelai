"""
Database setup and models for SentinelAI.
Uses SQLAlchemy async with SQLite (dev) or PostgreSQL (prod).
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime, Enum, JSON, Integer
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
    authorized_by: Mapped[str]             = mapped_column(String(255))  # who authorized the scan
    created_at:    Mapped[datetime]        = mapped_column(DateTime, default=datetime.utcnow)
    completed_at:  Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error:         Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    raw_results:   Mapped[Optional[dict]]  = mapped_column(JSON, nullable=True)
    llm_analysis:  Mapped[Optional[str]]   = mapped_column(Text, nullable=True)
    summary:       Mapped[Optional[str]]   = mapped_column(Text, nullable=True)


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
