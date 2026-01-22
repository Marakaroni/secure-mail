import time
import threading
import os
from typing import Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_session_master_key = os.urandom(32)

_key_cache: Dict[int, Dict[str, any]] = {}
_cache_lock = threading.RLock()

SESSION_TTL = 300


def _encrypt_envelope(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(_session_master_key).encrypt(nonce, plaintext, b"")
    return nonce + ct


def _decrypt_envelope(ciphertext: bytes) -> bytes:
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    return AESGCM(_session_master_key).decrypt(nonce, ct, b"")


def store_session_keys(user_id: int, private_sign_key: bytes, private_enc_key: bytes) -> None:
    with _cache_lock:
        if user_id in _key_cache:
            _secure_erase(_key_cache[user_id])
        
        encrypted_sign_key = _encrypt_envelope(private_sign_key)
        encrypted_enc_key = _encrypt_envelope(private_enc_key)
        
        _key_cache[user_id] = {
            "private_sign_key": encrypted_sign_key, 
            "private_enc_key": encrypted_enc_key,    
            "created_at": time.time(),
        }


def get_session_private_sign_key(user_id: int) -> Optional[bytes]:
    with _cache_lock:
        if user_id in _key_cache:
            entry = _key_cache[user_id]
            
            if time.time() - entry["created_at"] > SESSION_TTL:
                clear_session_keys(user_id)
                return None
            
            try:
                return _decrypt_envelope(entry["private_sign_key"])
            except Exception:
                clear_session_keys(user_id)
                return None
    
    return None


def get_session_private_enc_key(user_id: int) -> Optional[bytes]:
    with _cache_lock:
        if user_id in _key_cache:
            entry = _key_cache[user_id]
            
            if time.time() - entry["created_at"] > SESSION_TTL:
                clear_session_keys(user_id)
                return None
            
            try:
                return _decrypt_envelope(entry["private_enc_key"])
            except Exception:
                clear_session_keys(user_id)
                return None
    
    return None


def _secure_erase(entry: Dict) -> None:
    try:
        for key in entry:
            if isinstance(entry[key], bytes):
                entry[key] = os.urandom(len(entry[key]))
    except Exception:
        pass


def clear_session_keys(user_id: int) -> None:
    with _cache_lock:
        if user_id in _key_cache:
            _secure_erase(_key_cache[user_id])
            del _key_cache[user_id]
