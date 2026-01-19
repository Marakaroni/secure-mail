# app/crypto/kdf.py
import os
import json
from dataclasses import asdict, dataclass
from argon2.low_level import hash_secret_raw, Type

@dataclass
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 64 * 1024  # KiB (64 MiB)
    parallelism: int = 1
    hash_len: int = 32
    salt_len: int = 16
    type: str = "argon2id"

def default_params() -> Argon2Params:
    return Argon2Params()

def params_to_json(params: Argon2Params) -> str:
    return json.dumps(asdict(params), separators=(",", ":"))

def params_from_json(s: str) -> Argon2Params:
    d = json.loads(s)
    return Argon2Params(**d)

def new_salt(params: Argon2Params) -> bytes:
    return os.urandom(params.salt_len)

def derive_key_from_password(password: str, salt: bytes, params: Argon2Params) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password required")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
    )
