from __future__ import annotations

import os

from app.crypto.symmetric import generate_msg_key, aead_encrypt, aead_decrypt
from app.crypto.signatures import sign_ed25519_raw, verify_ed25519_raw


def main() -> None:
    # --- AES-GCM roundtrip ---
    key = generate_msg_key()
    aad = b'meta:test'
    pt = b'hello encrypted world'

    out = aead_encrypt(key=key, plaintext=pt, aad=aad)
    back = aead_decrypt(key=key, nonce=out.nonce, ciphertext=out.ciphertext, aad=aad)
    assert back == pt, 'AES-GCM roundtrip failed'

    # --- Ed25519 sign/verify ---
    sk_raw = os.urandom(32)  # Ed25519 private key bytes length
    # NOTE: for Ed25519, public key is derived from private key object
    # Here we derive via cryptography object so we test properly:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_raw)
    pk_raw = sk.public_key().public_bytes_raw()

    payload = out.nonce + out.ciphertext + aad
    sig = sign_ed25519_raw(sk_raw, payload)
    assert verify_ed25519_raw(pk_raw, sig, payload) is True, 'Signature verify failed'

    bad_payload = payload[:-1] + bytes([payload[-1] ^ 0x01])
    assert verify_ed25519_raw(pk_raw, sig, bad_payload) is False, 'Signature should fail on modified payload'

    print('OK: crypto selftest passed')


if __name__ == '__main__':
    main()
