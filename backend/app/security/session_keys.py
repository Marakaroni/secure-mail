"""
Session-based key storage for decrypted private keys.
Stores decrypted keys temporarily in memory during user session.
!!! NOT PRODUCTION SAFE - For development/testing only !!!
"""
import time
from typing import Dict, Optional

# In-memory storage: user_id -> {keys + timestamp}
# In production: use Redis/Memcache or load from HSM on demand
_key_cache: Dict[int, Dict[str, any]] = {}

# Session TTL in seconds (15 minutes = 900 seconds)
SESSION_TTL = 900


def store_session_keys(user_id: int, private_sign_key: bytes, private_enc_key: bytes) -> None:
    """Store decrypted keys in session (called after successful 2FA)."""
    _key_cache[user_id] = {
        "private_sign_key": private_sign_key,
        "private_enc_key": private_enc_key,
        "created_at": time.time(),
    }


def get_session_private_sign_key(user_id: int) -> Optional[bytes]:
    """Get user's private signing key from session."""
    if user_id in _key_cache:
        entry = _key_cache[user_id]
        # Check if session expired
        if time.time() - entry["created_at"] > SESSION_TTL:
            clear_session_keys(user_id)
            return None
        return entry.get("private_sign_key")
    return None


def get_session_private_enc_key(user_id: int) -> Optional[bytes]:
    """Get user's private encryption key from session."""
    if user_id in _key_cache:
        entry = _key_cache[user_id]
        # Check if session expired
        if time.time() - entry["created_at"] > SESSION_TTL:
            clear_session_keys(user_id)
            return None
        return entry.get("private_enc_key")
    return None


def clear_session_keys(user_id: int) -> None:
    """Clear session keys (on logout)."""
    if user_id in _key_cache:
        # Overwrite with zeros before deleting
        key_data = _key_cache[user_id]
        for key in key_data:
            if isinstance(key_data[key], bytes):
                key_data[key] = b'\x00' * len(key_data[key])
        del _key_cache[user_id]
