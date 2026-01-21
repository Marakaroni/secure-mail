"""
Rate limiting utilities for Etap 7 - Security Hardening.

Implements basic in-memory rate limiting for message operations.
"""
from datetime import datetime, timedelta
from typing import Dict, List
import asyncio


class RateLimiter:
    """Simple in-memory rate limiter for per-user operations."""
    
    def __init__(self):
        self._attempts: Dict[str, List[datetime]] = {}
    
    def is_allowed(
        self,
        user_id: int,
        operation: str,
        max_attempts: int = 10,
        window_seconds: int = 60
    ) -> bool:
        """
        Check if user can perform operation within rate limit.
        
        Args:
            user_id: User ID
            operation: Operation name (e.g., 'send_message', 'upload_attachment')
            max_attempts: Max attempts allowed in window
            window_seconds: Time window in seconds
            
        Returns:
            True if allowed, False if rate limited
        """
        key = f"{user_id}:{operation}"
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        
        # Get or create attempt list for this key
        if key not in self._attempts:
            self._attempts[key] = []
        
        # Remove attempts outside the window
        self._attempts[key] = [
            attempt for attempt in self._attempts[key]
            if attempt > window_start
        ]
        
        # Check if under limit
        if len(self._attempts[key]) < max_attempts:
            self._attempts[key].append(now)
            return True
        
        return False
    
    def cleanup_old_entries(self, max_age_seconds: int = 3600):
        """Remove old entries from memory (call periodically to prevent memory leak)."""
        cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds)
        
        keys_to_remove = []
        for key, attempts in self._attempts.items():
            # Keep only recent attempts
            self._attempts[key] = [a for a in attempts if a > cutoff]
            
            # Mark keys with no attempts for removal
            if not self._attempts[key]:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._attempts[key]


# Global rate limiter instance
_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    return _rate_limiter
