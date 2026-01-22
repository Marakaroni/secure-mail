from datetime import datetime, timedelta
from typing import Dict, List
import asyncio


class RateLimiter:
    def __init__(self):
        self._attempts: Dict[str, List[datetime]] = {}
    
    def is_allowed(
        self,
        user_id: int,
        operation: str,
        max_attempts: int = 10,
        window_seconds: int = 60
    ) -> bool:
        key = f"{user_id}:{operation}"
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        
        if key not in self._attempts:
            self._attempts[key] = []
        
        self._attempts[key] = [
            attempt for attempt in self._attempts[key]
            if attempt > window_start
        ]

        if len(self._attempts[key]) < max_attempts:
            self._attempts[key].append(now)
            return True
        
        return False
    
    def cleanup_old_entries(self, max_age_seconds: int = 3600):
        cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds)
        
        keys_to_remove = []
        for key, attempts in self._attempts.items():
            self._attempts[key] = [a for a in attempts if a > cutoff]

            if not self._attempts[key]:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._attempts[key]


_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    return _rate_limiter
