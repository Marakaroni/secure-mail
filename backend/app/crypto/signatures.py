# app/crypto/signatures.py
from cryptography.hazmat.primitives.asymmetric import ed25519

def sign_ed25519(private_sign_key_raw: bytes, payload: bytes) -> bytes:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(private_sign_key_raw)
    return sk.sign(payload)

def verify_ed25519(public_sign_key_raw: bytes, payload: bytes, signature: bytes) -> bool:
    pk = ed25519.Ed25519PublicKey.from_public_bytes(public_sign_key_raw)
    try:
        pk.verify(signature, payload)
        return True
    except Exception:
        return False
