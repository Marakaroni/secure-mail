"""
CSRF middleware for FastAPI.
Validates CSRF tokens for state-changing requests (POST, PUT, DELETE).
"""
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from app.security.csrf import verify_csrf_token


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF middleware: validate token for state-changing methods.
    Token should be in X-CSRF-Token header.
    Skip for safe methods (GET, HEAD, OPTIONS).
    """
    
    async def dispatch(self, request: Request, call_next):
        # Safe methods - no CSRF protection needed
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)
        
        # Skip CSRF check for /auth endpoints (they have their own security)
        if request.url.path.startswith("/auth/"):
            return await call_next(request)
        
        # For state-changing methods: require CSRF token
        csrf_token = request.headers.get("X-CSRF-Token")
        
        if not csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing. Include X-CSRF-Token header.",
            )
        
        if not verify_csrf_token(csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token invalid or expired.",
            )
        
        return await call_next(request)
