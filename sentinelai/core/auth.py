"""
JWT authentication and password hashing for SentinelAI user accounts.
"""
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sentinelai.core.config import get_settings

_bearer = HTTPBearer(auto_error=False)


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(user_id: str, email: str, username: str, is_admin: bool) -> str:
    s = get_settings()
    payload = {
        "sub":      user_id,
        "email":    email,
        "username": username,
        "admin":    is_admin,
        "exp":      datetime.utcnow() + timedelta(hours=s.jwt_expire_hours),
    }
    return jwt.encode(payload, s.jwt_secret_key, algorithm="HS256")


def _decode(token: str) -> dict:
    s = get_settings()
    try:
        return jwt.decode(token, s.jwt_secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired — please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """FastAPI dependency — returns decoded JWT payload or raises 401."""
    if not creds:
        raise HTTPException(status_code=401, detail="Authentication required")
    return _decode(creds.credentials)


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """FastAPI dependency — same as get_current_user but requires admin flag."""
    if not user.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
