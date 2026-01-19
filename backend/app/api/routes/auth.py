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
from app.core.security import verify_password, create_access_token, decode_access_token
from app.models.user import User
from app.security.twofa import generate_secret, build_totp_uri, verify_totp

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if get_user_by_email(db, payload.email) or get_user_by_username(db, payload.username):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    u = create_user(db, payload.username, payload.email, payload.password)
    return {"id": u.id, "username": u.username, "email": u.email}


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    u = get_user_by_email(db, payload.email)
    if not u or not verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

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
    u = get_user_by_email(db, email)
    if not u or not verify_password(password, u.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if getattr(u, "two_fa_enabled", False):
        raise HTTPException(status_code=400, detail="2FA already enabled")

    if not u.two_fa_secret or u.two_fa_method != "TOTP":
        raise HTTPException(status_code=400, detail="2FA not initialised")

    if not verify_totp(u.two_fa_secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    u.two_fa_enabled = True
    db.add(u)
    db.commit()
    return {"status": "ok"}


@router.post("/2fa/verify", response_model=TokenOut)
def twofa_verify(payload: TwoFAVerifyRequest, db: Session = Depends(get_db)):
    data = decode_access_token(payload.mfa_token)
    if not data or not data.get("mfa_pending"):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    u = db.get(User, int(user_id))
    if not u or not u.two_fa_enabled or u.two_fa_method != "TOTP" or not u.two_fa_secret:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_totp(u.two_fa_secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(subject=str(u.id), extra={"mfa": True})
    return TokenOut(requires_2fa=False, access_token=access_token)