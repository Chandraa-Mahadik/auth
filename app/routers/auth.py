from fastapi import Body, APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
import logging
import traceback
from collections import defaultdict
import time

from app.db import get_session
from app.models import User, Session, LoginEvent
from app.schemas import LoginIn, TokenOut
from app.core.security import (
    verify_password,
    create_access_token,
    new_refresh_token,
    hash_refresh_token,
    decode_access_token,
)
from app.core.config import settings
from app.utils import get_client_ip, parse_user_agent, subdomain_of
from app.deps.auth import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("app")

# --- simple in-memory token bucket per IP for login ---
RATE_BUCKET_SIZE = 5            # max attempts in bucket
RATE_REFILL_PER_SEC = 0.1       # 1 token per 10s
BUCKET = defaultdict(lambda: {"tokens": RATE_BUCKET_SIZE, "ts": time.monotonic()})

def rate_limit_ok(ip: str | None) -> bool:
    key = ip or "unknown"
    now = time.monotonic()
    b = BUCKET[key]
    elapsed = now - b["ts"]
    b["ts"] = now
    b["tokens"] = min(RATE_BUCKET_SIZE, b["tokens"] + elapsed * RATE_REFILL_PER_SEC)
    if b["tokens"] >= 1:
        b["tokens"] -= 1
        return True
    return False

REFRESH_COOKIE_NAME = "refresh_token"

def set_refresh_cookie(response: Response, token: str, *, secure: bool):
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=secure,  # True in prod (https + domain), False on localhost
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

@router.post("/login", response_model=TokenOut)
async def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    ip = get_client_ip(request)

    try:
        if not rate_limit_ok(ip):
            session.add(
                LoginEvent(
                    user_id=None,
                    success=False,
                    failure_reason="rate_limited",
                    ip=ip,
                    user_agent=request.headers.get("user-agent"),
                    device=parse_user_agent(request.headers.get("user-agent")),
                    app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                    subdomain=subdomain_of(payload.app_base_url),
                )
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Please wait.",
            )

        res = await session.execute(select(User).where(User.email == payload.email))
        user = res.scalar_one_or_none()

        if not user or not user.is_active or not verify_password(
            payload.password, user.password_hash
        ):
            if user:
                await session.execute(
                    update(User)
                    .where(User.user_id == user.user_id)
                    .values(failed_login_count=User.failed_login_count + 1)
                )
            session.add(
                LoginEvent(
                    user_id=(user.user_id if user else None),
                    success=False,
                    failure_reason=("inactive" if user and not user.is_active else "bad_credentials"),
                    ip=ip,
                    user_agent=request.headers.get("user-agent"),
                    device=parse_user_agent(request.headers.get("user-agent")),
                    app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                    subdomain=subdomain_of(payload.app_base_url),
                )
            )
            await session.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        # session + refresh
        refresh_plain, refresh_hash = new_refresh_token()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRES_DAYS)
        sess = Session(
            user_id=user.user_id,
            refresh_token_hash=refresh_hash,
            ip=ip,
            user_agent=request.headers.get("user-agent"),
            device=parse_user_agent(request.headers.get("user-agent")),
            expires_at=expires_at,
        )
        session.add(sess)

        # audit + user stats
        await session.execute(
            update(User)
            .where(User.user_id == user.user_id)
            .values(last_login_at=now, failed_login_count=0)
        )
        session.add(
            LoginEvent(
                user_id=user.user_id,
                success=True,
                failure_reason=None,
                ip=ip,
                user_agent=request.headers.get("user-agent"),
                device=parse_user_agent(request.headers.get("user-agent")),
                app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                subdomain=subdomain_of(payload.app_base_url),
            )
        )
        await session.commit()

        # mint access (UTC iat/exp inside)
        uid = str(user.user_id)
        if not uid:
            raise HTTPException(status_code=500, detail="User id missing")
        access = create_access_token(uid, extra={"email": user.email})

        # DEV: make responses non-cacheable and surface timing explicitly
        import jwt
        payload_dbg = jwt.decode(access, options={"verify_signature": False})
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Token-IAT"] = str(payload_dbg.get("iat"))
        response.headers["X-Server-Now"] = str(int(time.time()))

        secure_flag = (request.url.scheme == "https") and bool(settings.APP_COOKIE_DOMAIN)
        set_refresh_cookie(response, refresh_plain, secure=secure_flag)
        return TokenOut(access_token=access)

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        log.error(
            "login_unhandled_error",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "error": str(e),
                "trace": traceback.format_exc(),
            },
        )
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post("/refresh", response_model=TokenOut)
async def refresh(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    token_plain = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token_plain:
        raise HTTPException(status_code=401, detail="No refresh token")

    try:
        token_hash = hash_refresh_token(token_plain)
        res = await session.execute(
            select(Session, User)
            .join(User, Session.user_id == User.user_id)
            .where(
                Session.refresh_token_hash == token_hash,
                Session.revoked == False,
                Session.expires_at > datetime.now(timezone.utc),
            )
        )
        row = res.first()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid/expired refresh")

        sess, user = row[0], row[1]
        new_plain, new_hash = new_refresh_token()
        sess.refresh_token_hash = new_hash
        sess.last_seen_at = datetime.now(timezone.utc)
        await session.commit()

        secure_flag = (request.url.scheme == "https") and bool(settings.APP_COOKIE_DOMAIN)
        set_refresh_cookie(response, new_plain, secure=secure_flag)
        access = create_access_token(str(user.user_id), extra={"email": user.email})
        return TokenOut(access_token=access)

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        log.error(
            "refresh_unhandled_error",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "error": str(e),
                "trace": traceback.format_exc(),
            },
        )
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post("/logout")
async def logout(
    request: Request, response: Response, session: AsyncSession = Depends(get_session)
):
    token_plain = request.cookies.get(REFRESH_COOKIE_NAME)
    if token_plain:
        token_hash = hash_refresh_token(token_plain)
        res = await session.execute(
            select(Session).where(
                Session.refresh_token_hash == token_hash, Session.revoked == False
            )
        )
        sess = res.scalar_one_or_none()
        if sess:
            sess.revoked = True
            await session.commit()
    clear_refresh_cookie(response)
    return {"ok": True}

@router.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "user_id": str(user.user_id),
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "failed_login_count": user.failed_login_count,
    }

# --- DEV-ONLY token inspector: shows verified or unverified payload & server now ---
@router.post("/token/inspect")
def token_inspect(token: str = Body(..., embed=True)):
    import jwt, time
    try:
        payload = decode_access_token(token)
        return {"ok": True, "verified": True, "payload": payload, "now_epoch": int(time.time())}
    except Exception as e:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            unverified = None
        return {
            "ok": False,
            "verified": False,
            "error": str(e),
            "unverified_payload": unverified,
            "now_epoch": int(time.time()),
        }

# --- DEV-ONLY: create a token now and show its payload & server time ---
@router.post("/token/mint-debug")
def token_mint_debug(user_id: str = Body(..., embed=True)):
    import jwt, time
    tok = create_access_token(user_id, extra={"email": "debug@example.com"})
    payload = jwt.decode(tok, options={"verify_signature": False})
    return {"now_epoch": int(time.time()), "token": tok, "payload": payload}
