# backend/app/models/__init__.py
from .user import User
from .message import Message
from .message_recipient import MessageRecipient
from .attachment import Attachment

__all__ = ["User", "Message", "MessageRecipient", "Attachment"]
