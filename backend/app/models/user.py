# backend/app/models/user.py
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    two_fa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    two_fa_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    two_fa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hotp_counter: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    public_sign_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    public_enc_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    encrypted_private_sign_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encrypted_private_enc_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    key_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    key_kdf_params: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    sent_messages = relationship(
        "Message",
        back_populates="sender",
        cascade="all,delete",
    )
