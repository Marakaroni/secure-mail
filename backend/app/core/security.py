from __future__ import annotations

from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import jwt, JWTError

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.crypto.aead import decrypt_aesgcm
from app.crypto.kdf import params_from_json, derive_key_from_password


# Parametry Argon2 – OK na start
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=102400,  # ~100 MB
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
    credentials: HTTPAuthCredentials = Depends(_security),
    db: Session = Depends(get_db),
):
    """
    Dependency: Extract JWT token, verify it, and fetch User object from DB.
    Expects: Authorization: Bearer <token>
    Returns: User object
    Raises: HTTPException 401 if token invalid/expired/user not found
    """
    from app.models.user import User  # avoid circular imports
    
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify token has mfa claim (user completed 2FA if enabled)
    if not payload.get("mfa"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = int(payload["sub"])
    user = db.get(User, user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
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
    """
    Decrypt a user's private key using their password.
    
    Args:
        encrypted_key: Encrypted private key (nonce+ciphertext)
        password: User's password
        salt: KDF salt
        kdf_params_json: KDF parameters (JSON string)
        aad: AAD used during encryption (usually email)
    
    Returns:
        Decrypted private key
    
    Raises:
        ValueError: If decryption fails (wrong password, corrupted data, etc.)
    """
    kdf_params = params_from_json(kdf_params_json)
    kek = derive_key_from_password(password, salt, kdf_params)
    
    try:
        private_key = decrypt_aesgcm(kek, encrypted_key, aad=aad)
        return private_key
    except Exception as e:
        raise ValueError(f"Failed to decrypt private key: {str(e)}")
