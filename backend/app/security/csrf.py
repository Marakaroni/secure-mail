"""
CSRF (Cross-Site Request Forgery) token generation and validation.
Provides double-submit cookie pattern with secure token generation.
"""
import os
import hmac
import hashlib
from typing import Optional
from datetime import datetime, timedelta


class CSRFTokenManager:
    """
    CSRF token manager using double-submit pattern.
    Token includes: random_value + HMAC(secret, random_value)
    """
    
    def __init__(self, secret: str):
        """
        Initialize with CSRF secret.
        In production: load from secure config/HSM.
        """
        self.secret = secret.encode('utf-8')
        self.token_ttl = 3600  # 1 hour
    
    def generate_token(self) -> str:
        """Generate a new CSRF token."""
        # Generate random bytes
        random_part = os.urandom(32)
        
        # Create HMAC signature
        signature = hmac.new(
            self.secret,
            random_part,
            hashlib.sha256
        ).digest()
        
        # Combine and encode as hex
        token = (random_part + signature).hex()
        return token
    
    def verify_token(self, token: str) -> bool:
        """
        Verify CSRF token is valid.
        Returns True if token is authentic, False otherwise.
        """
        try:
            # Decode from hex
            token_bytes = bytes.fromhex(token)
            
            # Split into random part and signature
            random_part = token_bytes[:32]
            signature = token_bytes[32:]
            
            # Recompute HMAC
            expected_signature = hmac.new(
                self.secret,
                random_part,
                hashlib.sha256
            ).digest()
            
            # Constant-time comparison
            return hmac.compare_digest(signature, expected_signature)
        except (ValueError, IndexError):
            return False


# Global instance (in production: load secret from config)
_csrf_manager = None


def init_csrf_manager(secret: str) -> None:
    """Initialize CSRF manager with secret."""
    global _csrf_manager
    _csrf_manager = CSRFTokenManager(secret)


def generate_csrf_token() -> str:
    """Generate new CSRF token."""
    if not _csrf_manager:
        raise RuntimeError("CSRF manager not initialized. Call init_csrf_manager() first.")
    return _csrf_manager.generate_token()


def verify_csrf_token(token: str) -> bool:
    """Verify CSRF token."""
    if not _csrf_manager:
        raise RuntimeError("CSRF manager not initialized. Call init_csrf_manager() first.")
    return _csrf_manager.verify_token(token)
