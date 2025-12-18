import datetime as dt
import jwt
from jwt import InvalidTokenError
from typing import Any, Dict
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from app.core.config import settings

# Reasonable Argon2 defaults for auth
ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)

def hash_password(plain: str) -> str:
    return ph.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, plain)
    except VerifyMismatchError:
        return False

def create_access_token(sub: str, extra: Dict[str, Any] | None = None) -> str:
    """
    Always use *aware* UTC datetimes so .timestamp() yields true UTC seconds.
    Clamp TTL to >= 1 minute to prevent zero-minute tokens from .env issues.
    """
    # AWARE UTC datetime (critical fix vs. naive utcnow())
    now = dt.datetime.now(dt.timezone.utc)

    try:
        minutes = int(settings.ACCESS_TOKEN_EXPIRES_MIN)
    except Exception:
        minutes = 15
    minutes = max(1, minutes)

    exp = now + dt.timedelta(minutes=minutes)

    payload: Dict[str, Any] = {
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "access",
    }
    if extra:
        payload.update(extra)

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> dict:
    """
    Verify signature & standard claims with small leeway for iat/exp.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "iat", "exp"]},
        leeway=30,
    )

def new_refresh_token() -> tuple[str, str]:
    import secrets, hashlib
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash

def hash_refresh_token(token_plain: str) -> str:
    import hashlib
    return hashlib.sha256(token_plain.encode("utf-8")).hexdigest()

def get_jwt_subject(payload: dict) -> str:
    sub = payload.get("sub")
    if not sub:
        raise InvalidTokenError("Missing subject (sub)")
    return sub
