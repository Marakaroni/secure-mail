from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from app.db.init_db import init_db
from app.api.routes.auth import router as auth_router
from app.api.routes.messages import router as messages_router
from app.core.config import settings
from app.security.csrf import init_csrf_manager
from app.middleware.csrf import CSRFMiddleware


app = FastAPI(title="Secure Mail", version="0.0.1")

# Initialize CSRF manager
init_csrf_manager(settings.JWT_SECRET)

# Add CSRF middleware
app.add_middleware(CSRFMiddleware)

app.include_router(auth_router)
app.include_router(messages_router)

@app.on_event("startup")
def _startup() -> None:
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}
