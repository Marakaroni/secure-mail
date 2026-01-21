# app/crypto/keys.py
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

@dataclass
class UserKeyMaterial:
    """
    User's cryptographic key material (asymmetric).
    
    - Sign key (Ed25519): Used for signing messages
    - Encryption key (RSA-4096): Used for hybrid encryption (wrapping session keys)
    """
    public_sign_key: bytes  # Ed25519 public key (raw 32 bytes)
    public_enc_key: bytes   # RSA public key (PEM encoded)
    private_sign_key: bytes # Ed25519 private key (raw 32 bytes)
    private_enc_key: bytes  # RSA private key (PEM encoded)

def generate_user_keys() -> UserKeyMaterial:
    """
    Generate user's keypair:
    - Ed25519 for signing (fast, secure, deterministic)
    - RSA-4096 for hybrid encryption (robust, compatible with OAEP)
    """
    # Signing key pair: Ed25519
    sk_sign = ed25519.Ed25519PrivateKey.generate()
    pk_sign = sk_sign.public_key()

    # Encryption key pair: RSA-4096
    sk_enc = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    pk_enc = sk_enc.public_key()

    # Serialize signing keys as raw bytes (32 bytes for Ed25519)
    public_sign_key = pk_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_sign_key = sk_sign.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize RSA keys as PEM (for RSA-OAEP)
    public_enc_key = pk_enc.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_enc_key = sk_enc.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return UserKeyMaterial(
        public_sign_key=public_sign_key,
        public_enc_key=public_enc_key,
        private_sign_key=private_sign_key,
        private_enc_key=private_enc_key,
    )
