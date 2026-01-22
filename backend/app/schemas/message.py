from __future__ import annotations

from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import List, Optional
from datetime import datetime
from app.security.sanitizer import InputSanitizer


class MessageSendRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    recipients: List[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description='List of recipient emails (max 20)',
    )
    subject: str = Field(
        default='',
        max_length=255,
        description='Message subject (max 255 chars)',
    )
    body: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description='Message body (1-50000 chars, allows newlines)',
    )
    
    @field_validator('recipients')
    @classmethod
    def validate_recipients(cls, v: List[str]) -> List[str]:
        return InputSanitizer.validate_recipient_list(v, max_recipients=20)
    
    @field_validator('subject')
    @classmethod
    def validate_subject(cls, v: str) -> str:
        return InputSanitizer.sanitize_subject(v)
    
    @field_validator('body')
    @classmethod
    def validate_body(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Zawartość wiadomości nie może być pusta')
        return InputSanitizer.sanitize_body(v)


class MessageSendResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    message_id: int


class MessageListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    sender_id: Optional[int] = None
    created_at: datetime
    is_read: bool
    is_deleted: bool
    subject: str


class MessageReceiveResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    
    id: int
    sender_username: Optional[str] = None
    sender_email: Optional[str] = None
    subject: str
    body: str
    created_at: datetime
    is_read: bool
    is_deleted: bool
    signature_valid: bool
    attachments: List['AttachmentListItem'] = []


class MessageUpdateResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: str


class AttachmentUploadResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    
    attachment_id: int
    message_id: int
    filename: str
    size_bytes: int


class AttachmentListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    message_id: int
    filename: str
    size_bytes: int
    mime_type: str


class AttachmentDownloadResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    
    filename: str
    data_base64: str
    mime_type: str
