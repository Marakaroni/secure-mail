# backend/app/models/message_recipient.py
from sqlalchemy import Boolean, ForeignKey, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

class MessageRecipient(Base):
    __tablename__ = "message_recipients"

    id: Mapped[int] = mapped_column(primary_key=True)

    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True, nullable=False)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    encrypted_session_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    message = relationship("Message", back_populates="recipients")
    recipient = relationship("User")
