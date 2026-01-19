from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from jose import jwt

def _get_env(name: str, default: str | None = None) -> str:
    val = os.getenv(name, default)
    if not val:
        raise RuntimeError(f"Missing env var: {name}")
    return val

def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    secret = _get_env("JWT_SECRET")
    alg = os.getenv("JWT_ALG", "HS256")
    exp_min = int(os.getenv("JWT_EXPIRE_MINUTES", "60")) if expires_minutes is None else expires_minutes

    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=exp_min)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm=alg)
