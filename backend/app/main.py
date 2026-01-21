from fastapi import FastAPI
from app.db.init_db import init_db
from app.api.routes.auth import router as auth_router
from app.api.routes.messages import router as messages_router


app = FastAPI(title="Secure Mail", version="0.0.1")

app.include_router(auth_router)
app.include_router(messages_router)

@app.on_event("startup")
def _startup() -> None:
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}
