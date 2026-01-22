#app/crypto/signatures.py
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def sign_ed25519_raw(private_sign_key_raw: bytes, payload: bytes) -> bytes:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(private_sign_key_raw)
    return sk.sign(payload)


def verify_ed25519_raw(public_sign_key_raw: bytes, signature: bytes, payload: bytes) -> bool:
    pk = ed25519.Ed25519PublicKey.from_public_bytes(public_sign_key_raw)
    try:
        pk.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def sign_ed25519_pem(private_key_pem: bytes, payload: bytes, password: bytes | None = None) -> bytes:
    sk = load_pem_private_key(private_key_pem, password=password)
    if not isinstance(sk, ed25519.Ed25519PrivateKey):
        raise ValueError("Klucz prywatny nie jest Ed25519")
    return sk.sign(payload)


def verify_ed25519_pem(public_key_pem: bytes, signature: bytes, payload: bytes) -> bool:
    pk = load_pem_public_key(public_key_pem)
    if not isinstance(pk, ed25519.Ed25519PublicKey):
        raise ValueError("Klucz publiczny nie jest Ed25519")
    try:
        pk.verify(signature, payload)
        return True
    except InvalidSignature:
        return False
