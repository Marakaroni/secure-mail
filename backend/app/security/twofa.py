# backend/app/security/twofa.py
import pyotp

DEFAULT_ISSUER = "secure-mail"


def generate_secret() -> str:
    return pyotp.random_base32()


def build_totp_uri(secret: str, username: str, issuer: str = DEFAULT_ISSUER) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def verify_hotp(secret: str, code: str, counter: int) -> bool:
    return pyotp.HOTP(secret).verify(code, counter)
