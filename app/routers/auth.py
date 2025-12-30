from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
import logging
import traceback
import time
import uuid

from app.db import get_session
from app.models import User, Session, LoginEvent
from app.schemas import LoginIn, TokenOut
from app.core.security import (
    verify_password,
    create_access_token,
    new_refresh_token,
    hash_refresh_token,
)
from app.core.config import settings
from app.utils import get_client_ip, parse_user_agent, subdomain_of
from app.deps.auth import get_current_user

# Redis-backed rate limiting
from app.core.redis_client import get_redis
from app.security.rate_limit import token_bucket_allow

from app.core.cookies import set_refresh_cookie, clear_refresh_cookie, REFRESH_COOKIE_NAME

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("app")

# REFRESH_COOKIE_NAME = "refresh_token"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# def set_refresh_cookie(response: Response, token: str, *, secure: bool):
#     response.set_cookie(
#         key=REFRESH_COOKIE_NAME,
#         value=token,
#         httponly=True,
#         secure=secure,  # True in prod (https + domain), False on localhost
#         samesite="lax",
#         domain=settings.APP_COOKIE_DOMAIN or None,
#         max_age=settings.REFRESH_TOKEN_EXPIRES_DAYS * 24 * 3600,
#         path="/auth",
#     )


# def clear_refresh_cookie(response: Response):
#     response.delete_cookie(
#         key=REFRESH_COOKIE_NAME,
#         domain=settings.APP_COOKIE_DOMAIN or None,
#         path="/auth",
#     )


@router.post("/login", response_model=TokenOut)
async def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent")
    device = parse_user_agent(ua)

    try:
        # --- Redis-backed token bucket limiter (IP + email) ---
        redis = get_redis()
        email_norm = (payload.email or "").strip().lower()

        ip_key = f"rl:login:ip:{ip or 'unknown'}"
        email_key = f"rl:login:email:{email_norm or 'unknown'}"

        ip_allowed = await token_bucket_allow(
            redis,
            ip_key,
            capacity=settings.RATE_BUCKET_SIZE,
            refill_per_sec=settings.RATE_REFILL_PER_SEC,
        )
        email_allowed = await token_bucket_allow(
            redis,
            email_key,
            capacity=settings.RATE_BUCKET_SIZE,
            refill_per_sec=settings.RATE_REFILL_PER_SEC,
        )

        if not ip_allowed or not email_allowed:
            reason = "rate_limited_ip" if not ip_allowed else "rate_limited_email"

            session.add(
                LoginEvent(
                    user_id=None,
                    success=False,
                    failure_reason=reason,
                    ip=ip,
                    user_agent=ua,
                    device=device,
                    app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                    subdomain=subdomain_of(payload.app_base_url),
                )
            )
            await session.commit()
            raise HTTPException(status_code=429, detail="Too many attempts. Please wait.")

        # --- auth check ---
        res = await session.execute(select(User).where(User.email == payload.email))
        user = res.scalar_one_or_none()

        if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
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
                    user_agent=ua,
                    device=device,
                    app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                    subdomain=subdomain_of(payload.app_base_url),
                )
            )
            await session.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # --- create a NEW family for this device-login ---
        family_id = uuid.uuid4()

        refresh_plain, refresh_hash = new_refresh_token()
        now = utcnow()
        expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRES_DAYS)

        sess = Session(
            user_id=user.user_id,
            refresh_token_hash=refresh_hash,
            ip=ip,
            user_agent=ua,
            device=device,
            expires_at=expires_at,
            session_family_id=family_id,
            last_seen_at=now,
        )
        session.add(sess)

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
                user_agent=ua,
                device=device,
                app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                subdomain=subdomain_of(payload.app_base_url),
            )
        )

        await session.commit()

        access = create_access_token(
            str(user.user_id),
            extra={"email": user.email, "tv": int(user.token_version or 0)},
        )

        # DEV headers (optional)
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
        log.error("login_unhandled_error", extra={"error": str(e), "trace": traceback.format_exc()})
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

    ip = get_client_ip(request)
    ua = request.headers.get("user-agent")
    device = parse_user_agent(ua)

    try:
        now = utcnow()
        token_hash = hash_refresh_token(token_plain)

        # 1) Find ACTIVE session
        res = await session.execute(
            select(Session, User)
            .join(User, Session.user_id == User.user_id)
            .where(
                Session.refresh_token_hash == token_hash,
                Session.revoked_at.is_(None),
                Session.expires_at > now,
            )
        )
        row = res.first()

        if not row:
            # 2) Reuse detection check (token exists but no longer active)
            res2 = await session.execute(select(Session).where(Session.refresh_token_hash == token_hash))
            old_sess = res2.scalar_one_or_none()

            if old_sess and old_sess.session_family_id:
                family_id = old_sess.session_family_id

                await session.execute(
                    update(Session)
                    .where(Session.session_family_id == family_id, Session.revoked_at.is_(None))
                    .values(
                        revoked_at=now,
                        revoked_reason="compromised_refresh_reuse",
                        compromised_at=now,
                        compromised_reason="refresh_token_reuse_detected",
                    )
                )

                session.add(
                    LoginEvent(
                        user_id=old_sess.user_id,
                        success=False,
                        failure_reason="refresh_token_reuse",
                        ip=ip,
                        user_agent=ua,
                        device=device,
                        app_base_url=None,
                        subdomain=None,
                    )
                )

                await session.commit()
                clear_refresh_cookie(response)
                raise HTTPException(status_code=401, detail="Refresh token reuse detected. Please login again.")

            raise HTTPException(status_code=401, detail="Invalid/expired refresh")

        old_session, user = row[0], row[1]

        # Ensure family_id exists (for old legacy rows)
        family_id = old_session.session_family_id or uuid.uuid4()
        old_session.session_family_id = family_id  # critical: keep old in family too

        # Create new session row (rotation)
        new_plain, new_hash = new_refresh_token()
        new_session = Session(
            user_id=user.user_id,
            refresh_token_hash=new_hash,
            ip=ip,
            user_agent=ua,
            device=device,
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRES_DAYS),
            session_family_id=family_id,
            last_seen_at=now,
        )
        session.add(new_session)
        await session.flush()  # new_session.session_id available

        # Link and revoke old session
        old_session.replaced_by_session_id = new_session.session_id
        old_session.revoked_at = now
        old_session.revoked_reason = "rotated"
        old_session.rotated_at = now
        old_session.last_seen_at = now

        await session.commit()

        secure_flag = (request.url.scheme == "https") and bool(settings.APP_COOKIE_DOMAIN)
        set_refresh_cookie(response, new_plain, secure=secure_flag)

        access = create_access_token(
            str(user.user_id),
            extra={"email": user.email, "tv": int(user.token_version or 0)},
        )

        return TokenOut(access_token=access)

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        log.error("refresh_unhandled_error", extra={"error": str(e), "trace": traceback.format_exc()})
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    """
    Device logout: revoke the entire session family for the refresh token presented.
    """
    token_plain = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token_plain:
        clear_refresh_cookie(response)
        return {"ok": True}

    try:
        now = utcnow()
        token_hash = hash_refresh_token(token_plain)

        res = await session.execute(
            select(Session).where(
                Session.refresh_token_hash == token_hash,
                Session.revoked_at.is_(None),
            )
        )
        sess = res.scalar_one_or_none()

        if sess and sess.session_family_id:
            await session.execute(
                update(Session)
                .where(Session.session_family_id == sess.session_family_id, Session.revoked_at.is_(None))
                .values(revoked_at=now, revoked_reason="logout_family")
            )
            await session.commit()

        clear_refresh_cookie(response)
        return {"ok": True}

    except Exception as e:
        await session.rollback()
        log.error("logout_unhandled_error", extra={"error": str(e), "trace": traceback.format_exc()})
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/logout-all")
async def logout_all(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """
    Logout from all devices: revoke ALL active sessions for the user.
    """
    try:
        now = utcnow()
        await session.execute(
            update(Session)
            .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason="logout_all")
        )
        await session.commit()
        clear_refresh_cookie(response)
        return {"ok": True}
    except Exception as e:
        await session.rollback()
        log.error("logout_all_unhandled_error", extra={"error": str(e), "trace": traceback.format_exc()})
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/sessions")
async def list_sessions(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """
    List sessions for the current user (active + recently revoked).
    """
    try:
        # show last N days; tune as needed
        cutoff = utcnow() - timedelta(days=30)

        res = await session.execute(
            select(Session)
            .where(Session.user_id == user.user_id)
            .order_by(Session.created_at.desc())  # assuming created_at exists
        )
        rows = res.scalars().all()

        token_plain = request.cookies.get(REFRESH_COOKIE_NAME)
        token_hash = hash_refresh_token(token_plain) if token_plain else None

        out = []
        for s in rows:
            if getattr(s, "created_at", None) and s.created_at < cutoff:
                # keep old if still active; otherwise skip
                if s.revoked_at is not None:
                    continue

            out.append(
                {
                    "session_id": str(s.session_id),
                    "session_family_id": str(s.session_family_id) if s.session_family_id else None,
                    "is_current_cookie_session": (token_hash is not None and s.refresh_token_hash == token_hash),
                    "ip": s.ip,
                    "device": s.device,
                    "user_agent": s.user_agent,
                    "created_at": s.created_at,
                    "last_seen_at": s.last_seen_at,
                    "expires_at": s.expires_at,
                    "revoked_at": s.revoked_at,
                    "revoked_reason": s.revoked_reason,
                    "replaced_by_session_id": str(s.replaced_by_session_id) if s.replaced_by_session_id else None,
                    "compromised_at": s.compromised_at,
                    "compromised_reason": s.compromised_reason,
                }
            )

        return {"items": out}

    except Exception as e:
        log.error("list_sessions_unhandled_error", extra={"error": str(e), "trace": traceback.format_exc()})
        raise HTTPException(status_code=500, detail="Internal Server Error")


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
