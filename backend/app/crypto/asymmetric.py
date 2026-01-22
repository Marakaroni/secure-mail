from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def load_public_key(pem: bytes):
    return load_pem_public_key(pem)


def load_private_key(pem: bytes, password: bytes | None = None):
    return load_pem_private_key(pem, password=password)


def wrap_key_for_recipient(*, recipient_public_key_pem: bytes, msg_key: bytes) -> bytes:
    pub = load_public_key(recipient_public_key_pem)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError('Klucz publiczny odbiorcy musi być RSA dla szyfrowania OAEP')

    wrapped = pub.encrypt(
        msg_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped


def unwrap_key_for_recipient(*, recipient_private_key_pem: bytes, wrapped_key: bytes, password: bytes | None = None) -> bytes:
    priv = load_private_key(recipient_private_key_pem, password=password)
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise ValueError('Klucz prywatny odbiorcy musi być RSA dla deszyfrowania OAEP')

    msg_key = priv.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return msg_key


def public_key_to_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
