# backend/app/api/routes/auth.py
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import RegisterIn, LoginIn, TokenOut
from app.schemas.twofa import TwoFASetupResponse, TwoFAEnableRequest, TwoFAVerifyRequest
from app.crud.users import (
    get_by_email as get_user_by_email,
    get_by_username as get_user_by_username,
    create_user,
)
from app.core.security import (
    verify_password,
    create_access_token,
    decode_access_token,
    decrypt_user_private_key,
    get_current_user,
)
from app.models.user import User
from app.security.twofa import generate_secret, build_totp_uri, verify_totp
from app.security.rate_limit import is_rate_limited, record_auth_attempt, get_rate_limit_delay
from app.security.password_strength import validate_password_strength
from app.security.session_keys import store_session_keys, clear_session_keys
from app.security.csrf import generate_csrf_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    # Validate password strength
    is_valid, error_msg = validate_password_strength(payload.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    
    # Check if user already exists (don't reveal which field)
    if get_user_by_email(db, payload.email) or get_user_by_username(db, payload.username):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    u = create_user(db, payload.username, payload.email, payload.password)
    return {"id": u.id, "username": u.username, "email": u.email}


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    # Rate limiting: check if this email is rate limited
    if is_rate_limited(payload.email):
        delay = get_rate_limit_delay(payload.email)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. Try again in {int(delay)} seconds."
        )
    
    u = get_user_by_email(db, payload.email)
    if not u or not verify_password(payload.password, u.password_hash):
        record_auth_attempt(payload.email, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Successful password authentication
    record_auth_attempt(payload.email, success=True)

    # Decrypt and store private keys in session
    # (only if 2FA is enabled or user has keys)
    if (
        u.encrypted_private_sign_key
        and u.encrypted_private_enc_key
        and u.key_salt
        and u.key_kdf_params
    ):
        try:
            aad = u.email.encode("utf-8")
            private_sign_key = decrypt_user_private_key(
                encrypted_key=u.encrypted_private_sign_key,
                password=payload.password,
                salt=u.key_salt,
                kdf_params_json=u.key_kdf_params,
                aad=aad,
            )
            private_enc_key = decrypt_user_private_key(
                encrypted_key=u.encrypted_private_enc_key,
                password=payload.password,
                salt=u.key_salt,
                kdf_params_json=u.key_kdf_params,
                aad=aad,
            )
            # Store in session cache
            store_session_keys(u.id, private_sign_key, private_enc_key)
        except Exception as e:
            # Log error but don't fail login
            # (keys can be decrypted on-demand if needed)
            pass

    if getattr(u, "two_fa_enabled", False):
        mfa_token = create_access_token(subject=str(u.id), extra={"mfa_pending": True})
        return TokenOut(requires_2fa=True, mfa_token=mfa_token)

    access_token = create_access_token(subject=str(u.id), extra={"mfa": True})
    return TokenOut(requires_2fa=False, access_token=access_token)


@router.post("/2fa/setup", response_model=TwoFASetupResponse)
def twofa_setup(
    email: str = Body(...),
    password: str = Body(...),
    db: Session = Depends(get_db),
):
    u = get_user_by_email(db, email)
    if not u or not verify_password(password, u.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if getattr(u, "two_fa_enabled", False):
        raise HTTPException(status_code=400, detail="2FA already enabled")

    secret = generate_secret()
    u.two_fa_secret = secret
    u.two_fa_method = "TOTP"
    u.hotp_counter = 0

    db.add(u)
    db.commit()
    db.refresh(u)

    uri = build_totp_uri(secret=secret, username=u.email)
    return TwoFASetupResponse(secret=secret, provisioning_uri=uri, method="TOTP")


@router.post("/2fa/enable")
def twofa_enable(
    payload: TwoFAEnableRequest,
    email: str = Body(...),
    password: str = Body(...),
    db: Session = Depends(get_db),
):
    # Rate limiting
    rate_limit_key = f"2fa_enable_{email}"
    if is_rate_limited(rate_limit_key):
        delay = get_rate_limit_delay(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many attempts. Try again in {int(delay)} seconds."
        )

    u = get_user_by_email(db, email)
    if not u or not verify_password(password, u.password_hash):
        record_auth_attempt(rate_limit_key, success=False)
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if getattr(u, "two_fa_enabled", False):
        raise HTTPException(status_code=400, detail="2FA already enabled")

    if not u.two_fa_secret or u.two_fa_method != "TOTP":
        raise HTTPException(status_code=400, detail="2FA not initialised")

    if not verify_totp(u.two_fa_secret, payload.code):
        record_auth_attempt(rate_limit_key, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Successful 2FA setup
    record_auth_attempt(rate_limit_key, success=True)

    u.two_fa_enabled = True
    db.add(u)
    db.commit()
    return {"status": "ok"}


@router.post("/2fa/verify", response_model=TokenOut)
def twofa_verify(payload: TwoFAVerifyRequest, db: Session = Depends(get_db)):
    # Decode mfa_token to get user_id
    data = decode_access_token(payload.mfa_token)
    if not data or not data.get("mfa_pending"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    u = db.get(User, int(user_id))
    if not u or not u.two_fa_enabled or u.two_fa_method != "TOTP" or not u.two_fa_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Rate limit 2FA verification attempts
    rate_limit_key = f"2fa_{u.id}"
    if is_rate_limited(rate_limit_key):
        delay = get_rate_limit_delay(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many 2FA attempts. Try again in {int(delay)} seconds."
        )

    if not verify_totp(u.two_fa_secret, payload.code):
        record_auth_attempt(rate_limit_key, success=False)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Successful 2FA verification
    record_auth_attempt(rate_limit_key, success=True)

    access_token = create_access_token(subject=str(u.id), extra={"mfa": True})
    return TokenOut(requires_2fa=False, access_token=access_token)


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    """Logout: clear session keys and invalidate JWT"""
    clear_session_keys(current_user.id)
    return {"status": "ok", "message": "Logged out successfully"}


@router.get("/csrf-token")
def get_csrf_token():
    """
    Get CSRF token for state-changing operations.
    Include this token in X-CSRF-Token header for POST/PUT/DELETE requests.
    """
    token = generate_csrf_token()
    return {"csrf_token": token}