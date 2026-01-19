# backend/app/models/user.py
from datetime import datetime

from sqlalchemy import Boolean, DateTime, LargeBinary, String, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    two_fa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    two_fa_method: Mapped[str | None] = mapped_column(String(10), nullable=True) 
    two_fa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True) 
    hotp_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    public_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True) 

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    sent_messages = relationship("Message", back_populates="sender", cascade="all,delete")
