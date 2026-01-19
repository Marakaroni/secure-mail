# backend/app/db/init_db.py
from app.db.base import Base
from app.db.session import engine

# WAŻNE: import modeli, żeby SQLAlchemy "zobaczył" tabele
from app import models  # noqa: F401

def init_db() -> None:
    Base.metadata.create_all(bind=engine)
