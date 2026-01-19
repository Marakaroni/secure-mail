from fastapi import FastAPI
from app.db.init_db import init_db

app = FastAPI(title="Secure Mail", version="0.0.1")

@app.on_event("startup")
def _startup() -> None:
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}
