# app/crypto/keys.py
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

@dataclass
class UserKeyMaterial:
    public_sign_key: bytes  
    public_enc_key: bytes   
    private_sign_key: bytes 
    private_enc_key: bytes  

def generate_user_keys() -> UserKeyMaterial:
    sk_sign = ed25519.Ed25519PrivateKey.generate()
    pk_sign = sk_sign.public_key()

    sk_enc = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    pk_enc = sk_enc.public_key()

    public_sign_key = pk_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_sign_key = sk_sign.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

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
