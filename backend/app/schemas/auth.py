from __future__ import annotations

from pydantic import BaseModel, Field, EmailStr

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class TokenOut(BaseModel):
    requires_2fa: bool
    access_token: str | None = None
    mfa_token: str | None = None