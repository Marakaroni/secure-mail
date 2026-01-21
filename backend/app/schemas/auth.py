from __future__ import annotations

import re
from pydantic import BaseModel, Field, EmailStr, field_validator, ConfigDict
from app.security.sanitizer import InputSanitizer

class RegisterIn(BaseModel):
    """Registration request with comprehensive validation (Etap 7)."""
    model_config = ConfigDict(extra='forbid')
    
    username: str = Field(
        min_length=3,
        max_length=64,
        pattern=r'^[a-zA-Z0-9_\-]+$',
        description="Username (3-64 alphanumeric/dash/underscore)"
    )
    email: EmailStr
    password: str = Field(
        min_length=12,
        max_length=128,
        description="Password (12+ chars, uppercase, lowercase, digit, special char)"
    )
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Sanitize username."""
        return InputSanitizer.sanitize_username(v)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain digit')
        if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'\"<>,.?/]', v):
            raise ValueError('Password must contain special character')
        return v

class LoginIn(BaseModel):
    """Login request with input validation (Etap 7)."""
    model_config = ConfigDict(extra='forbid')
    
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    
    @field_validator('password')
    @classmethod
    def validate_password_not_empty(cls, v: str) -> str:
        """Ensure password is not whitespace-only."""
        if not v.strip():
            raise ValueError('Password cannot be empty')
        return v

class TokenOut(BaseModel):
    """Auth response (no external input, safe)."""
    model_config = ConfigDict(extra='forbid')
    
    requires_2fa: bool
    access_token: str | None = None
    mfa_token: str | None = None