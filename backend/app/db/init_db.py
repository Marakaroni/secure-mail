# backend/app/db/init_db.py
from app.db.base import Base
from app.db.session import engine

from app import models 

def init_db() -> None:
    Base.metadata.create_all(bind=engine)
