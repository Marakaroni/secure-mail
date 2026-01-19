from fastapi import FastAPI
from app.db.init_db import init_db
from app.api.routes.auth import router as auth_router

app = FastAPI(title="Secure Mail", version="0.0.1")

app.include_router(auth_router)

@app.on_event("startup")
def _startup() -> None:
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}
