from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def load_public_key(pem: bytes):
    return load_pem_public_key(pem)


def load_private_key(pem: bytes, password: bytes | None = None):
    return load_pem_private_key(pem, password=password)


def wrap_key_for_recipient(*, recipient_public_key_pem: bytes, msg_key: bytes) -> bytes:
    """
    Hybrid encryption: wrap the session key K_msg for a given recipient using RSA-OAEP.
    
    Args:
        recipient_public_key_pem: Recipient's RSA-4096 public key (PEM encoded)
        msg_key: Session key to wrap (32 bytes for AES-256)
    
    Returns:
        Encrypted session key (RSA-4096 ciphertext)
    """
    pub = load_public_key(recipient_public_key_pem)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError('Recipient public key must be RSA for OAEP wrapping')

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
    """
    Hybrid decryption: unwrap the session key K_msg using recipient's RSA private key.
    
    Args:
        recipient_private_key_pem: Recipient's RSA-4096 private key (PEM encoded)
        wrapped_key: Encrypted session key (RSA-4096 ciphertext)
        password: Optional password for encrypted private key
    
    Returns:
        Decrypted session key (32 bytes for AES-256)
    """
    priv = load_private_key(recipient_private_key_pem, password=password)
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise ValueError('Recipient private key must be RSA for OAEP unwrapping')

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
