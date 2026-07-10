"""
Shared fixtures for SentinelAI integration tests.

Event-loop strategy:
  - `client` is session-scoped (loop_scope="session") — lifespan runs once.
  - `clear_db` is a SYNC fixture (no event loop) — uses stdlib sqlite3 to
    truncate tables before each test.  This avoids all cross-loop aiosqlite
    errors that occur when an async fixture tries to reuse a connection
    created in a different asyncio.Runner.
  - All other async fixtures use loop_scope="session" so they share the
    client's event loop.
  - Every test file must add:
      pytestmark = pytest.mark.asyncio(loop_scope="session")
"""
import os
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

# ── MUST come before any sentinelai import ────────────────────────────────
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_sentinel.db"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-do-not-use-in-production"
os.environ["SENTINELAI_API_KEYS"] = "test-service-key"
os.environ["ANTHROPIC_API_KEY"] = "test"
os.environ["ADMIN_EMAILS"] = ""
os.environ["SENTINELAI_ENV"] = "testing"
os.environ["ALERT_MIN_SEVERITY"] = "critical"

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine as _create_sync_engine, delete
from sqlalchemy.ext.asyncio import create_async_engine as _create_async_engine
from sqlalchemy.pool import NullPool as _NullPool

from sentinelai.core.config import get_settings
get_settings.cache_clear()

from sentinelai.api.main import app, _load_db_api_keys, _failed_logins
import sentinelai.core.database as _db_module
from sentinelai.core.database import (
    get_session_factory, Base,
    User, Scan, Finding, Schedule, AlertRule,
    CveWatchlistEntry, UserApiKey,
    ScanType, ScanStatus, Severity,
)
from sentinelai.core.security import _API_KEY_STORE, init_api_keys

# ── Constants ─────────────────────────────────────────────────────────────
SERVICE_HEADERS = {"X-API-Key": "test-service-key"}
_TEST_DB_PATH = "./test_sentinel.db"

# ── One-time DB bootstrap (runs at conftest import, before any event loop) ──
#
# 1. Sync engine: creates all tables so clear_db can DELETE from them.
# 2. Async engine with NullPool: closes connections immediately after each
#    use, preventing the "database is locked" error when clear_db writes.
_sync_setup = _create_sync_engine("sqlite:///./test_sentinel.db", echo=False)
Base.metadata.create_all(_sync_setup)
_sync_setup.dispose()

_db_module._engine = _create_async_engine(
    "sqlite+aiosqlite:///./test_sentinel.db",
    poolclass=_NullPool,
    echo=False,
)
_db_module._session_factory = None  # recreated lazily from the NullPool engine

# ── Shared LLM mock ───────────────────────────────────────────────────────
_mock_llm = MagicMock()
_mock_llm.complete = AsyncMock(return_value="Mock LLM analysis: security posture is stable.")
_mock_llm.log_analyst_system = MagicMock(return_value="")


async def _mock_run_log_analysis(log_source, log_content, api_key_name, context=None):
    scan_id = str(uuid.uuid4())
    now = datetime.utcnow()
    async with get_session_factory()() as session:
        session.add(Scan(
            id=scan_id,
            target=log_source or "test.log",
            scan_type=ScanType.LOG_ANALYSE,
            status=ScanStatus.COMPLETED,
            authorized_by=api_key_name or "test",
            created_at=now, completed_at=now,
            finding_count=0,
            llm_analysis="Mock log analysis",
            summary=f"Test scan of {log_source} completed. 0 findings.",
        ))
        await session.commit()
    return scan_id


# ── Session-scoped test client (one lifespan for the whole test run) ──────

@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client():
    """HTTPX client backed by the FastAPI ASGI app; all external I/O mocked."""
    with (
        patch("sentinelai.api.main._fetch_kev", new_callable=AsyncMock),
        patch("sentinelai.core.notifier.send_alert", new_callable=AsyncMock),
        patch("sentinelai.core.notifier.send_watchlist_alert", new_callable=AsyncMock),
        patch("sentinelai.core.scan_service.ScanService.run_recon", new_callable=AsyncMock),
        patch("sentinelai.core.scan_service.ScanService.run_vuln", new_callable=AsyncMock),
        patch("sentinelai.core.scan_service.ScanService.run_full_scan", new_callable=AsyncMock),
        patch(
            "sentinelai.core.scan_service.ScanService.run_log_analysis",
            side_effect=_mock_run_log_analysis,
        ),
        patch("sentinelai.core.llm_client.get_llm_client", return_value=_mock_llm),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as c:
            yield c


# ── Per-test cleanup (ASYNC, session loop) ────────────────────────────────
# Tables were created synchronously at import time, so no "no such table"
# errors.  The NullPool async engine closes connections immediately after
# each use, so there are no lock conflicts with previous test requests.

@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clear_db(client: AsyncClient):
    """Truncate all rows before each test; reset in-memory singletons."""
    async with get_session_factory()() as session:
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(delete(table))
        await session.commit()

    _API_KEY_STORE.clear()
    init_api_keys()        # re-register "test-service-key" from env
    _failed_logins.clear() # reset brute-force counters


# ── Auth helpers ──────────────────────────────────────────────────────────

async def register_user(
    client: AsyncClient,
    username: str = "testuser",
    email: str = "test@example.com",
    password: str = "testpass123",
) -> tuple[str, dict]:
    resp = await client.post("/api/v1/auth/register", json={
        "username": username, "email": email, "password": password,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["token"], data["user"]


@pytest_asyncio.fixture(loop_scope="session")
async def user_token(client: AsyncClient, clear_db):
    """Register a test user after each DB clear; return (token, user_dict)."""
    return await register_user(client)


@pytest_asyncio.fixture(loop_scope="session")
async def auth_headers(user_token):
    token, _ = user_token
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(loop_scope="session")
async def second_user(client: AsyncClient, user_token):
    """
    Register a second (non-admin) user after user_token has registered the first.
    Returns (token, user_dict) for the second user only.
    """
    return await register_user(client, "user2", "user2@example.com", "password456")


@pytest_asyncio.fixture(loop_scope="session")
async def second_auth_headers(second_user):
    token, _ = second_user
    return {"Authorization": f"Bearer {token}"}


# ── DB seed helpers (async; call inside test bodies) ──────────────────────

async def make_scan(
    target: str = "example.com",
    scan_type: ScanType = ScanType.RECON,
    status: ScanStatus = ScanStatus.COMPLETED,
    finding_count: int = 0,
    critical_count: int = 0,
    high_count: int = 0,
) -> str:
    scan_id = str(uuid.uuid4())
    now = datetime.utcnow()
    async with get_session_factory()() as session:
        session.add(Scan(
            id=scan_id, target=target, scan_type=scan_type,
            status=status, authorized_by="test",
            created_at=now,
            completed_at=now if status == ScanStatus.COMPLETED else None,
            finding_count=finding_count,
            critical_count=critical_count,
            high_count=high_count,
            summary=f"Test scan of {target}.",
        ))
        await session.commit()
    return scan_id


async def make_finding(
    scan_id: str,
    title: str = "Test Finding",
    severity: Severity = Severity.HIGH,
    cve_id: str | None = None,
    mitre_attack: str | None = None,
    rem_status: str = "open",
    is_kev: bool = False,
) -> str:
    finding_id = str(uuid.uuid4())
    async with get_session_factory()() as session:
        session.add(Finding(
            id=finding_id, scan_id=scan_id,
            title=title, description="Test finding description.",
            severity=severity, rem_status=rem_status,
            cve_id=cve_id, mitre_attack=mitre_attack,
            is_kev=is_kev, created_at=datetime.utcnow(),
        ))
        await session.commit()
    return finding_id
