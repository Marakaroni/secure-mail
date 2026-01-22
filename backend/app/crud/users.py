# backend/app/crud/users.py
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User
from app.crypto.keys import generate_user_keys
from app.crypto.kdf import default_params, new_salt, derive_key_from_password, params_to_json
from app.crypto.aead import encrypt_aesgcm


def get_by_email(db: Session, email: str) -> User | None:
    stmt = select(User).where(User.email == email)
    return db.execute(stmt).scalar_one_or_none()


def get_by_username(db: Session, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return db.execute(stmt).scalar_one_or_none()


def create_user(db: Session, username: str, email: str, password: str) -> User:
    password_hash = hash_password(password)

    km = generate_user_keys()

    kdf_params = default_params()
    salt = new_salt(kdf_params)
    kek = derive_key_from_password(password, salt, kdf_params)

    aad = email.encode("utf-8")

    enc_priv_sign = encrypt_aesgcm(kek, km.private_sign_key, aad=aad)
    enc_priv_enc = encrypt_aesgcm(kek, km.private_enc_key, aad=aad)

    u = User(
        username=username,
        email=email,
        password_hash=password_hash,
        public_sign_key=km.public_sign_key,
        public_enc_key=km.public_enc_key,
        encrypted_private_sign_key=enc_priv_sign,
        encrypted_private_enc_key=enc_priv_enc,
        key_salt=salt,
        key_kdf_params=params_to_json(kdf_params),
    )

    db.add(u)
    db.commit()
    db.refresh(u)
    return u
