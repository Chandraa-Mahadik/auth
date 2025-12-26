from fastapi import Response
from app.core.config import settings

REFRESH_COOKIE_NAME = "refresh_token"

def set_refresh_cookie(response: Response, token: str, *, secure: bool):
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        domain=settings.APP_COOKIE_DOMAIN or None,
        max_age=settings.REFRESH_TOKEN_EXPIRES_DAYS * 24 * 3600,
        path="/auth",
    )

def clear_refresh_cookie(response: Response):
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        domain=settings.APP_COOKIE_DOMAIN or None,
        path="/auth",
    )
