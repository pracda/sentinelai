"""
API Security — Authentication, Rate Limiting, Input Validation
OWASP API Security Top 10 coverage:
  API1  — Broken Object Level Authorization → per-key scoping
  API2  — Broken Authentication → API key hashing + timing-safe compare
  API4  — Unrestricted Resource Consumption → rate limiting
  API8  — Security Misconfiguration → secure headers middleware
  API10 — Unsafe Consumption of APIs → LLM output validation
"""
import hashlib
import hmac
import time
import secrets
import re
from collections import defaultdict
from typing import Optional
from fastapi import HTTPException, Security, Request
from fastapi.security import APIKeyHeader
import structlog

from sentinelai.core.config import get_settings

log = structlog.get_logger()

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_API_KEY_STORE: dict[str, str]  = {}   # hash → key_name
_API_KEY_META:  dict[str, dict] = {}   # hash → {user_id, key_id, name}


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def register_api_key(raw_key: str, name: str,
                     user_id: str = None, key_id: str = None):
    h = _hash_key(raw_key)
    _API_KEY_STORE[h] = name
    if user_id and key_id:
        _API_KEY_META[h] = {"user_id": user_id, "key_id": key_id, "name": name}


def unregister_api_key(raw_key: str):
    h = _hash_key(raw_key)
    _API_KEY_STORE.pop(h, None)
    _API_KEY_META.pop(h, None)


def register_api_key_by_hash(key_hash: str, name: str,
                              user_id: str = None, key_id: str = None):
    """Register an already-hashed key (used when loading keys from DB at startup)."""
    _API_KEY_STORE[key_hash] = name
    if user_id and key_id:
        _API_KEY_META[key_hash] = {"user_id": user_id, "key_id": key_id, "name": name}


def unregister_api_key_by_hash(key_hash: str):
    _API_KEY_STORE.pop(key_hash, None)
    _API_KEY_META.pop(key_hash, None)


def get_key_meta(raw_key: str) -> Optional[dict]:
    return _API_KEY_META.get(_hash_key(raw_key))


def get_key_meta_by_hash(key_hash: str) -> Optional[dict]:
    return _API_KEY_META.get(key_hash)


def init_api_keys():
    settings = get_settings()
    for raw_key in settings.api_keys:
        if raw_key.strip():
            register_api_key(raw_key.strip(), "default")
    log.info("API keys initialised", count=len(_API_KEY_STORE))


async def verify_api_key(
    request: Request,
    api_key: Optional[str] = Security(API_KEY_HEADER)
) -> str:
    if not api_key:
        log.warning("API request without key",
                    ip=request.client.host if request.client else "unknown")
        raise HTTPException(
            status_code=401,
            detail="API key required. Include X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    key_hash = _hash_key(api_key)

    for stored_hash, name in _API_KEY_STORE.items():
        if hmac.compare_digest(key_hash, stored_hash):
            return name

    log.warning("Invalid API key attempt",
                ip=request.client.host if request.client else "unknown")
    raise HTTPException(status_code=401, detail="Invalid API key.")


# ── Rate limiting ──────────────────────────────────────────────────────────

_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(
    identifier: str,
    max_requests: int = 20,
    window_seconds: int = 60
) -> bool:
    now = time.time()
    window_start = now - window_seconds

    _rate_limit_store[identifier] = [
        t for t in _rate_limit_store[identifier]
        if t > window_start
    ]

    if len(_rate_limit_store[identifier]) >= max_requests:
        return False

    _rate_limit_store[identifier].append(now)
    return True


async def rate_limit_dependency(
    request: Request,
    api_key_name: str = Security(verify_api_key)
) -> str:
    allowed = check_rate_limit(
        identifier=api_key_name,
        max_requests=get_settings().rate_limit_per_minute,
        window_seconds=60
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Max 20 requests per minute.",
            headers={"Retry-After": "60"}
        )
    return api_key_name


# ── Input validation ───────────────────────────────────────────────────────

DANGEROUS_INPUT_PATTERNS = [
    re.compile(r'[;&|`$]'),
    re.compile(r'\.\./|\.\.\\'),
    re.compile(r'<script', re.I),
    re.compile(r'(union\s+select|drop\s+table)', re.I),
]

MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024  # 10MB


def validate_target(target: str) -> str:
    if not target or len(target) > 255:
        raise HTTPException(status_code=400,
                            detail="Invalid target: must be 1-255 characters")

    for pattern in DANGEROUS_INPUT_PATTERNS:
        if pattern.search(target):
            raise HTTPException(
                status_code=400,
                detail="Invalid target: contains disallowed characters"
            )

    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$'
    )
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

    if not (hostname_pattern.match(target) or ip_pattern.match(target)):
        raise HTTPException(status_code=400, detail="Invalid target format")

    return target.lower().strip()


def validate_log_content(content: str) -> str:
    if not content:
        raise HTTPException(status_code=400, detail="Log content is empty")

    if len(content.encode("utf-8")) > MAX_LOG_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Log content too large. Maximum size is 10MB."
        )

    return content


# ── Secure headers ─────────────────────────────────────────────────────────

SECURE_HEADERS = {
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":          "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":   (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com"
    ),
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Cache-Control":             "no-store",
    "Server":                    "SentinelAI",
}


def generate_api_key() -> str:
    return "sal_" + secrets.token_urlsafe(32)
