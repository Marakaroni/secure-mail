import os
import hmac
import hashlib
from typing import Optional
from datetime import datetime, timedelta


class CSRFTokenManager:
    def __init__(self, secret: str):
        self.secret = secret.encode('utf-8')
        self.token_ttl = 3600  
    
    def generate_token(self) -> str:
        random_part = os.urandom(32)

        signature = hmac.new(
            self.secret,
            random_part,
            hashlib.sha256
        ).digest()

        token = (random_part + signature).hex()
        return token
    
    def verify_token(self, token: str) -> bool:
        try:
            token_bytes = bytes.fromhex(token)
            
            random_part = token_bytes[:32]
            signature = token_bytes[32:]
            
            expected_signature = hmac.new(
                self.secret,
                random_part,
                hashlib.sha256
            ).digest()
            
            return hmac.compare_digest(signature, expected_signature)
        except (ValueError, IndexError):
            return False


_csrf_manager = None


def init_csrf_manager(secret: str) -> None:
    global _csrf_manager
    _csrf_manager = CSRFTokenManager(secret)


def generate_csrf_token() -> str:
    if not _csrf_manager:
        raise RuntimeError("Menedżer CSRF nie został zainicjalizowany. Wywołaj init_csrf_manager() najpierw.")
    return _csrf_manager.generate_token()


def verify_csrf_token(token: str) -> bool:
    if not _csrf_manager:
        raise RuntimeError("Menedżer CSRF nie został zainicjalizowany. Wywołaj init_csrf_manager() najpierw.")
    return _csrf_manager.verify_token(token)
