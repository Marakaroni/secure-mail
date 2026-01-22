from __future__ import annotations

from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import jwt, JWTError

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
from starlette.requests import Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.crypto.aead import decrypt_aesgcm
from app.crypto.kdf import params_from_json, derive_key_from_password


_ph = PasswordHasher(
    time_cost=2,
    memory_cost=102400, 
    parallelism=8,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def create_access_token(subject: str, extra: dict | None = None) -> str:
    payload = {
        "sub": subject,
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
    }
    if extra:
        payload.update(extra)

    token = jwt.encode(
        payload,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError:
        return None


_security = HTTPBearer()


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> "User":

    from app.models.user import User  # avoid circular imports
    
    # Get authorization header
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowe dane uwierzytelniania",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    payload = decode_access_token(token)
    
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowe dane uwierzytelniania",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify token has mfa claim (user completed 2FA if enabled)
    if not payload.get("mfa"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowe dane uwierzytelniania",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = int(payload["sub"])
    user = db.get(User, user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowe dane uwierzytelniania",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


def decrypt_user_private_key(
    encrypted_key: bytes,
    password: str,
    salt: bytes,
    kdf_params_json: str,
    aad: bytes,
) -> bytes:
    kdf_params = params_from_json(kdf_params_json)
    kek = derive_key_from_password(password, salt, kdf_params)
    
    try:
        private_key = decrypt_aesgcm(kek, encrypted_key, aad=aad)
        return private_key
    except Exception as e:
        raise ValueError(f"Failed to decrypt private key: {str(e)}")
