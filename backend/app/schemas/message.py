from __future__ import annotations

from pydantic import BaseModel, Field, ConfigDict
from typing import List


class MessageSendRequest(BaseModel):
    """
    Stage 5: minimal request for sending encrypted messages.
    Attachments will be added next (integral part of message payload),
    but for now we keep a placeholder design.
    """
    model_config = ConfigDict(extra='forbid')

    recipients: List[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description='List of recipient usernames or emails (depending on your auth model).',
    )
    subject: str = Field(
        default='',
        max_length=120,
        description='Optional subject (metadata; will be covered by signature/AAD later).',
    )
    body: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description='Plaintext message body (will be encrypted server-side).',
    )


class MessageSendResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    message_id: int
