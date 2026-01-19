# app/crypto/aead.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12

def encrypt_aesgcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires 32-byte key")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct

def decrypt_aesgcm(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires 32-byte key")
    if len(blob) < NONCE_LEN + 16:
        raise ValueError("Invalid ciphertext blob")
    nonce = blob[:NONCE_LEN]
    ct = blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, aad)
