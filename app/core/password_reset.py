import hashlib
import secrets

def new_password_reset_token() -> str:
    # URL-safe, high entropy
    return secrets.token_urlsafe(48)

def hash_password_reset_token(token: str) -> str:
    # stable hash, store only this
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
