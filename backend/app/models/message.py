# backend/app/models/message.py
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)

    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    # Message encryption: ciphertext includes encrypted body + attachments together
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # AEAD nonce (12 bytes for GCM)
    
    # AAD (Associated Authenticated Data): metadata that's authenticated but not secret
    aad: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    
    # Digital signature over (nonce + ciphertext + aad) by sender
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    sender = relationship("User", back_populates="sent_messages")
    recipients = relationship("MessageRecipient", back_populates="message", cascade="all,delete-orphan")
    attachments = relationship("Attachment", back_populates="message", cascade="all,delete-orphan")
