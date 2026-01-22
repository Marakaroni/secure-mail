import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    
    def __init__(self):
        self._attempts = defaultdict(lambda: {"count": 0, "last_time": 0})
        self._lock = Lock()

        self.max_attempts = 5 
        self.base_delay = 2.0  
        self.max_delay = 300.0  
    
    def is_allowed(self, key: str) -> bool:
        with self._lock:
            entry = self._attempts[key]
            now = time.time()

            if now - entry["last_time"] > self.max_delay * 2:
                entry["count"] = 0
                entry["last_time"] = now
                return True

            if entry["count"] >= self.max_attempts:
                required_delay = min(
                    self.base_delay * (2 ** (entry["count"] - self.max_attempts)),
                    self.max_delay
                )
                time_since_last = now - entry["last_time"]
                
                if time_since_last < required_delay:
                    return False
                else:
                    entry["count"] = 0
                    entry["last_time"] = now
                    return True
            
            return True
    
    def record_attempt(self, key: str, success: bool = False) -> None:
        with self._lock:
            entry = self._attempts[key]
            entry["last_time"] = time.time()
            
            if success:
                entry["count"] = 0
            else:
                entry["count"] += 1
    
    def get_retry_after(self, key: str) -> float:
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


_limiter = RateLimiter()


def is_rate_limited(key: str) -> bool:
    return not _limiter.is_allowed(key)


def record_auth_attempt(key: str, success: bool = False) -> None:
    _limiter.record_attempt(key, success=success)


def get_rate_limit_delay(key: str) -> float:
    return _limiter.get_retry_after(key)
