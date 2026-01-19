from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Parametry: rozsądne na start; dopracujemy pod serwer w Etapie 7
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=102400,  # ~100 MB
    parallelism=8,
    hash_len=32,
    salt_len=16,
)

def hash_password(password: str) -> str:
    return _ph.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
