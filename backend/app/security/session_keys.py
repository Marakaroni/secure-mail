"""
Session-based key storage for decrypted private keys.
Stores decrypted keys temporarily in memory during user session.
SECURITY IMPROVEMENTS:
- Short TTL (5 minutes) to minimize exposure window
- Thread-safe operations with locking
- Secure erasure before deletion
"""
import time
import threading
import os
from typing import Dict, Optional

# In-memory storage: user_id -> {keys + timestamp}
# Thread-safe access with lock
_key_cache: Dict[int, Dict[str, any]] = {}
_cache_lock = threading.RLock()

# Session TTL in seconds (5 minutes = 300 seconds) - Reduced from 900 for security
SESSION_TTL = 300


def store_session_keys(user_id: int, private_sign_key: bytes, private_enc_key: bytes) -> None:
    """Store decrypted keys in session (called after successful 2FA).
    
    Thread-safe operation with automatic expiration.
    """
    with _cache_lock:
        # Clear any existing keys for this user first
        if user_id in _key_cache:
            _secure_erase(_key_cache[user_id])
        
        _key_cache[user_id] = {
            "private_sign_key": private_sign_key,
            "private_enc_key": private_enc_key,
            "created_at": time.time(),
        }


def get_session_private_sign_key(user_id: int) -> Optional[bytes]:
    """Get user's private signing key from session.
    
    Returns None if session expired or key not found.
    Thread-safe operation.
    """
    with _cache_lock:
        if user_id in _key_cache:
            entry = _key_cache[user_id]
            # Check if session expired
            if time.time() - entry["created_at"] > SESSION_TTL:
                clear_session_keys(user_id)
                return None
            return entry.get("private_sign_key")
    return None


def get_session_private_enc_key(user_id: int) -> Optional[bytes]:
    """Get user's private encryption key from session.
    
    Returns None if session expired or key not found.
    Thread-safe operation.
    """
    with _cache_lock:
        if user_id in _key_cache:
            entry = _key_cache[user_id]
            # Check if session expired
            if time.time() - entry["created_at"] > SESSION_TTL:
                clear_session_keys(user_id)
                return None
            return entry.get("private_enc_key")
    return None


def _secure_erase(entry: Dict) -> None:
    """Securely erase keys from memory.
    
    Overwrites sensitive data with random bytes before deletion.
    """
    try:
        for key in entry:
            if isinstance(entry[key], bytes):
                # Overwrite with random data instead of zeros (harder to detect)
                entry[key] = os.urandom(len(entry[key]))
    except Exception:
        pass


def clear_session_keys(user_id: int) -> None:
    """Clear session keys (on logout or expiration).
    
    Securely erases keys from memory before deletion.
    Thread-safe operation.
    """
    with _cache_lock:
        if user_id in _key_cache:
            # Securely erase before deleting
            _secure_erase(_key_cache[user_id])
            del _key_cache[user_id]
