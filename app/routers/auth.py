from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
import logging
import traceback
import time
import uuid

from app.db import get_session
from app.models import User, Session, LoginEvent, RefreshTokenHistory
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

# ✅ Security events
from app.services.security_events import write_security_event


router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("app")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def insert_refresh_history(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    session_id: uuid.UUID | None,
    session_family_id: uuid.UUID | None,
    token_hash: str,
    ip: str | None,
    user_agent: str | None,
    device: dict | None,
) -> None:
    """
    Insert a history row for a refresh token hash.

    If the hash already exists, that's a critical signal: the same refresh token
    got minted twice (should never happen) or reuse occurred and we somehow got
    here on a "mint" path. We'll treat as server error to surface quickly.
    """
    try:
        session.add(
            RefreshTokenHistory(
                user_id=user_id,
                session_id=session_id,
                session_family_id=session_family_id,
                token_hash=token_hash,
                ip=ip,
                user_agent=user_agent,
                device=device,
            )
        )
    except Exception:
        raise


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

            # existing audit
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

            # ✅ security event
            await write_security_event(
                session,
                event_type="login_rate_limited",
                severity="high",
                user_id=None,
                details={
                    "reason": reason,
                    "email": email_norm,
                },
                request=request,
            )

            await session.commit()
            raise HTTPException(status_code=429, detail="Too many attempts. Please wait.")

        # --- auth check ---
        res = await session.execute(select(User).where(User.email == payload.email))
        user = res.scalar_one_or_none()

        # Decide event taxonomy without changing external response semantics
        if not user:
            # ✅ security event (don’t leak externally; this is internal)
            await write_security_event(
                session,
                event_type="login_failed_user_not_found",
                severity="warning",
                user_id=None,
                details={"email": email_norm},
                request=request,
            )

            session.add(
                LoginEvent(
                    user_id=None,
                    success=False,
                    failure_reason="bad_credentials",
                    ip=ip,
                    user_agent=ua,
                    device=device,
                    app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                    subdomain=subdomain_of(payload.app_base_url),
                )
            )
            await session.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            await write_security_event(
                session,
                event_type="login_blocked_inactive_user",
                severity="high",
                user_id=user.user_id,
                details={"email": email_norm},
                request=request,
            )

            session.add(
                LoginEvent(
                    user_id=user.user_id,
                    success=False,
                    failure_reason="inactive",
                    ip=ip,
                    user_agent=ua,
                    device=device,
                    app_base_url=(str(payload.app_base_url) if payload.app_base_url else None),
                    subdomain=subdomain_of(payload.app_base_url),
                )
            )
            await session.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not verify_password(payload.password, user.password_hash):
            # increment failed count (existing)
            await session.execute(
                update(User)
                .where(User.user_id == user.user_id)
                .values(failed_login_count=User.failed_login_count + 1)
            )

            # ✅ security event
            await write_security_event(
                session,
                event_type="login_failed_invalid_password",
                severity="warning",
                user_id=user.user_id,
                details={"email": email_norm},
                request=request,
            )

            session.add(
                LoginEvent(
                    user_id=user.user_id,
                    success=False,
                    failure_reason="bad_credentials",
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
        await session.flush()  # sess.session_id available

        # Insert refresh token history row for minted token
        await insert_refresh_history(
            session,
            user_id=user.user_id,
            session_id=sess.session_id,
            session_family_id=family_id,
            token_hash=refresh_hash,
            ip=ip,
            user_agent=ua,
            device=device,
        )

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

        # ✅ optional security event (keep INFO to avoid noise)
        await write_security_event(
            session,
            event_type="login_success",
            severity="info",
            user_id=user.user_id,
            session_id=sess.session_id,
            session_family_id=family_id,
            details={},
            request=request,
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
        # (Optional) log, but don’t try DB writes if you want this super lean.
        raise HTTPException(status_code=401, detail="No refresh token")

    ip = get_client_ip(request)
    ua = request.headers.get("user-agent")
    device = parse_user_agent(ua)

    try:
        now = utcnow()
        token_hash = hash_refresh_token(token_plain)

        # 1) Find ACTIVE session by hash
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
            # 2) If token_hash exists in history => reuse detected
            hist_res = await session.execute(
                select(RefreshTokenHistory).where(RefreshTokenHistory.token_hash == token_hash)
            )
            hist = hist_res.scalar_one_or_none()

            if hist:
                # Revoke the entire family if we have it; else revoke all sessions for safety
                if hist.session_family_id:
                    await session.execute(
                        update(Session)
                        .where(
                            Session.user_id == hist.user_id,
                            Session.session_family_id == hist.session_family_id,
                            Session.revoked_at.is_(None),
                        )
                        .values(
                            revoked_at=now,
                            revoked_reason="compromised_refresh_reuse",
                            compromised_at=now,
                            compromised_reason="refresh_token_reuse_detected",
                        )
                    )
                else:
                    await session.execute(
                        update(Session)
                        .where(Session.user_id == hist.user_id, Session.revoked_at.is_(None))
                        .values(
                            revoked_at=now,
                            revoked_reason="compromised_refresh_reuse",
                            compromised_at=now,
                            compromised_reason="refresh_token_reuse_detected",
                        )
                    )

                session.add(
                    LoginEvent(
                        user_id=hist.user_id,
                        success=False,
                        failure_reason="refresh_token_reuse",
                        ip=ip,
                        user_agent=ua,
                        device=device,
                        app_base_url=None,
                        subdomain=None,
                    )
                )

                # ✅ security event (must-have)
                await write_security_event(
                    session,
                    event_type="refresh_token_reuse_detected",
                    severity="high",
                    user_id=hist.user_id,
                    session_id=hist.session_id,
                    session_family_id=hist.session_family_id,
                    details={
                        "action": "revoke_family" if hist.session_family_id else "revoke_all_user_sessions",
                        "reason": "old_refresh_token_used_again",
                    },
                    request=request,
                )

                # (Optional) second event for timeline clarity
                await write_security_event(
                    session,
                    event_type="session_family_revoked",
                    severity="high",
                    user_id=hist.user_id,
                    session_id=hist.session_id,
                    session_family_id=hist.session_family_id,
                    details={"reason": "refresh_token_reuse_detected"},
                    request=request,
                )

                await session.commit()
                clear_refresh_cookie(response)
                raise HTTPException(status_code=401, detail="Refresh token reuse detected. Please login again.")

            # Not in history => just invalid/expired
            await write_security_event(
                session,
                event_type="refresh_failed_invalid_token",
                severity="warning",
                user_id=None,
                details={},
                request=request,
            )
            await session.commit()
            raise HTTPException(status_code=401, detail="Invalid/expired refresh")

        old_session, user = row[0], row[1]

        # Ensure family_id exists
        family_id = old_session.session_family_id or uuid.uuid4()
        old_session.session_family_id = family_id

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

        # Insert history row for the newly minted refresh token hash
        await insert_refresh_history(
            session,
            user_id=user.user_id,
            session_id=new_session.session_id,
            session_family_id=family_id,
            token_hash=new_hash,
            ip=ip,
            user_agent=ua,
            device=device,
        )

        # Link and revoke old session
        old_session.replaced_by_session_id = new_session.session_id
        old_session.revoked_at = now
        old_session.revoked_reason = "rotated"
        old_session.rotated_at = now
        old_session.last_seen_at = now

        # ✅ optional event (INFO)
        await write_security_event(
            session,
            event_type="refresh_success",
            severity="info",
            user_id=user.user_id,
            session_id=new_session.session_id,
            session_family_id=family_id,
            details={},
            request=request,
        )

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

            # ✅ security event
            await write_security_event(
                session,
                event_type="logout",
                severity="info",
                user_id=sess.user_id,
                session_id=sess.session_id,
                session_family_id=sess.session_family_id,
                details={"action": "revoke_family"},
                request=request,
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

        # ✅ security event
        await write_security_event(
            session,
            event_type="logout_all",
            severity="info",
            user_id=user.user_id,
            details={"action": "revoke_all_sessions"},
            request=request,
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
        cutoff = utcnow() - timedelta(days=30)

        res = await session.execute(
            select(Session)
            .where(Session.user_id == user.user_id)
            .order_by(Session.created_at.desc())
        )
        rows = res.scalars().all()

        token_plain = request.cookies.get(REFRESH_COOKIE_NAME)
        token_hash = hash_refresh_token(token_plain) if token_plain else None

        out = []
        for s in rows:
            if getattr(s, "created_at", None) and s.created_at < cutoff:
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
