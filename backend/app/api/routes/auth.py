from __future__ import annotations
from fastapi import Depends
from sqlalchemy.orm import Session
from fastapi import APIRouter, HTTPException, status

from app.db.session import get_db  # jeśli masz inaczej, dopasuj import
from app.schemas.auth import RegisterIn, LoginIn, TokenOut
from app.crud.users import get_by_username, get_by_email, create_user
from app.core.security import verify_password
from app.core.tokens import create_access_token


router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if get_by_email(db, payload.email) or get_by_username(db, payload.username):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    u = create_user(db, payload.username, payload.email, payload.password)
    return {"id": u.id, "username": u.username, "email": u.email}

@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    u = get_by_email(db, payload.email)
    if not u or not verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token(subject=str(u.id))
    return TokenOut(access_token=token)
