from __future__ import annotations

from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import List, Optional
from datetime import datetime
from app.security.sanitizer import InputSanitizer


class MessageSendRequest(BaseModel):
    """
    Etap 7: Message send with comprehensive input validation.
    Prevents injection, XSS, path traversal in attachments.
    """
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
        """Validate and sanitize recipient list."""
        return InputSanitizer.validate_recipient_list(v, max_recipients=20)
    
    @field_validator('subject')
    @classmethod
    def validate_subject(cls, v: str) -> str:
        """Sanitize subject."""
        return InputSanitizer.sanitize_subject(v)
    
    @field_validator('body')
    @classmethod
    def validate_body(cls, v: str) -> str:
        """Sanitize body (allow newlines)."""
        if not v or not v.strip():
            raise ValueError('Body cannot be empty')
        return InputSanitizer.sanitize_body(v)


class MessageSendResponse(BaseModel):
    """Response after sending message."""
    model_config = ConfigDict(extra='forbid')

    message_id: int


class MessageListItem(BaseModel):
    """Item in inbox/sent list with basic metadata."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    sender_id: Optional[int] = None
    created_at: datetime
    is_read: bool
    is_deleted: bool
    subject: str


class MessageReceiveResponse(BaseModel):
    """
    Etap 6: Decrypted message for recipient.
    Contains plaintext body + metadata + attachments.
    """
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
    """Response for read/delete operations."""
    model_config = ConfigDict(extra='forbid')
    status: str


class AttachmentUploadResponse(BaseModel):
    """Response after uploading attachment."""
    model_config = ConfigDict(extra='forbid')
    
    attachment_id: int
    message_id: int
    filename: str
    size_bytes: int


class AttachmentListItem(BaseModel):
    """Attachment metadata for listing."""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    message_id: int
    filename: str
    size_bytes: int
    mime_type: str


class AttachmentDownloadResponse(BaseModel):
    """Response for attachment download."""
    model_config = ConfigDict(extra='forbid')
    
    filename: str
    data_base64: str
    mime_type: str
