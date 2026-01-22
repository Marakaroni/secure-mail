from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AESGCM_KEY_LEN = 32        
AESGCM_NONCE_LEN = 12       


@dataclass(frozen=True)
class AeadCiphertext:
    nonce: bytes
    ciphertext: bytes 


def generate_msg_key() -> bytes:
    return os.urandom(AESGCM_KEY_LEN)


def aead_encrypt(*, key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> AeadCiphertext:
    if len(key) != AESGCM_KEY_LEN:
        raise ValueError('Nieprawidłowa długość klucza AESGCM')
    nonce = os.urandom(AESGCM_NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return AeadCiphertext(nonce=nonce, ciphertext=ct)


def aead_decrypt(*, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(key) != AESGCM_KEY_LEN:
        raise ValueError('Nieprawidłowa długość klucza AESGCM')
    if len(nonce) != AESGCM_NONCE_LEN:
        raise ValueError('Nieprawidłowa długość nonce AESGCM')
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
