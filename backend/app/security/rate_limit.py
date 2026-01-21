"""
Rate limiting for auth endpoints (login, 2FA).
Prevents brute-force attacks using exponential backoff.
"""
import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    """
    Simple in-memory rate limiter with exponential backoff.
    Tracks failed attempts per key (email/user_id).
    """
    
    def __init__(self):
        self._attempts = defaultdict(lambda: {"count": 0, "last_time": 0})
        self._lock = Lock()
        
        # Config
        self.max_attempts = 5  # Allow 5 failed attempts
        self.base_delay = 2.0  # Start with 2 seconds delay
        self.max_delay = 300.0  # Cap at 5 minutes
    
    def is_allowed(self, key: str) -> bool:
        """
        Check if an attempt is allowed for this key.
        Returns False if too many attempts or backoff period active.
        """
        with self._lock:
            entry = self._attempts[key]
            now = time.time()
            
            # Reset if enough time has passed since last attempt
            if now - entry["last_time"] > self.max_delay * 2:
                entry["count"] = 0
                entry["last_time"] = now
                return True
            
            # Calculate required delay
            if entry["count"] >= self.max_attempts:
                required_delay = min(
                    self.base_delay * (2 ** (entry["count"] - self.max_attempts)),
                    self.max_delay
                )
                time_since_last = now - entry["last_time"]
                
                if time_since_last < required_delay:
                    return False
                else:
                    # Reset after backoff period
                    entry["count"] = 0
                    entry["last_time"] = now
                    return True
            
            return True
    
    def record_attempt(self, key: str, success: bool = False) -> None:
        """
        Record an attempt (failed by default).
        Reset counter on success.
        """
        with self._lock:
            entry = self._attempts[key]
            entry["last_time"] = time.time()
            
            if success:
                entry["count"] = 0
            else:
                entry["count"] += 1
    
    def get_retry_after(self, key: str) -> float:
        """
        Get seconds to wait before next attempt.
        Returns 0 if attempt is allowed.
        """
        with self._lock:
            entry = self._attempts[key]
            now = time.time()
            
            if entry["count"] < self.max_attempts:
                return 0.0
            
            required_delay = min(
                self.base_delay * (2 ** (entry["count"] - self.max_attempts)),
                self.max_delay
            )
            time_since_last = now - entry["last_time"]
            
            return max(0.0, required_delay - time_since_last)


# Global instance
_limiter = RateLimiter()


def is_rate_limited(key: str) -> bool:
    """Check if a request should be rate limited."""
    return not _limiter.is_allowed(key)


def record_auth_attempt(key: str, success: bool = False) -> None:
    """Record an auth attempt."""
    _limiter.record_attempt(key, success=success)


def get_rate_limit_delay(key: str) -> float:
    """Get time to wait in seconds."""
    return _limiter.get_retry_after(key)
