from __future__ import annotations

from pydantic import BaseModel, Field, EmailStr

class RegisterIn(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=64,
        description="Username (3-64 characters)"
    )
    email: EmailStr
    password: str = Field(
        min_length=12,
        max_length=128,
        description="Password (12+ characters, must include uppercase, lowercase, digit, special char)"
    )

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class TokenOut(BaseModel):
    requires_2fa: bool
    access_token: str | None = None
    mfa_token: str | None = None