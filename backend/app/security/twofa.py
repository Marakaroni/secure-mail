import pyotp

DEFAULT_ISSUER = "secure-mail"

def generate_secret() -> str:
    return pyotp.random_base32()  # base32

def build_totp_uri(secret: str, username: str, issuer: str = DEFAULT_ISSUER) -> str:
    totp = pyotp.TOTP(secret)
    # label zwykle "issuer:username"
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret: str, code: str) -> bool:
    # valid_window=1 toleruje lekkie rozjazdy czasu (±30s)
    return pyotp.TOTP(secret).verify(code, valid_window=1)

def verify_hotp(secret: str, code: str, counter: int) -> bool:
    return pyotp.HOTP(secret).verify(code, counter)
