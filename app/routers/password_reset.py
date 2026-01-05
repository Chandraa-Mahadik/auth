from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import User, Session, LoginEvent, PasswordResetToken
from app.core.config import settings
from app.core.security import verify_password, hash_password  # ✅ use existing hash_password
from app.core.redis_client import get_redis
from app.security.rate_limit import token_bucket_allow
from app.utils import get_client_ip, parse_user_agent
from app.deps.auth import get_current_user

from app.core.password_reset import new_password_reset_token, hash_password_reset_token
from app.schemas_password_reset import PasswordForgotIn, PasswordResetIn, PasswordChangeIn
from app.services.mailer import DevMailer

from app.core.cookies import clear_refresh_cookie

from app.services.security_events import write_security_event  # ✅ ADD


router = APIRouter(prefix="/auth/password", tags=["auth-password"])
mailer = DevMailer()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/forgot", status_code=status.HTTP_200_OK)
async def forgot_password(
    payload: PasswordForgotIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Always return 200 (do not leak if email exists).
    Rate limit by IP + email.
    """
    ip = get_client_ip(request)
    email_norm = (payload.email or "").strip().lower()
    ua = request.headers.get("user-agent")

    # --- rate limit (IP + email) ---
    redis = get_redis()
    ip_key = f"rl:pwreset:ip:{ip or 'unknown'}"
    email_key = f"rl:pwreset:email:{email_norm or 'unknown'}"

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

    # Still return OK (anti-enumeration)
    if not ip_allowed or not email_allowed:
        # ✅ Security signal: rate limited password reset (high severity)
        await write_security_event(
            session,
            event_type="password_reset_rate_limited",
            severity="high",
            details={"email": email_norm},
            request=request,
        )
        await session.commit()
        return {"ok": True}

    # --- user lookup ---
    res = await session.execute(select(User).where(User.email == email_norm))
    user = res.scalar_one_or_none()

    # IMPORTANT: do NOT log user_not_found as an external signal; internal security log is OK.
    if not user or not user.is_active:
        await write_security_event(
            session,
            event_type="password_reset_requested_unknown_or_inactive",
            severity="info",
            details={"email": email_norm},
            request=request,
        )
        await session.commit()
        return {"ok": True}

    # ✅ Security event: password reset requested (for a real active user)
    await write_security_event(
        session,
        event_type="password_reset_requested",
        severity="info",
        user_id=user.user_id,
        details={"email": email_norm},
        request=request,
    )

    # --- create reset token ---
    token_plain = new_password_reset_token()
    token_hash = hash_password_reset_token(token_plain)
    expires_at = _now_utc() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_MINUTES)

    await session.execute(
        insert(PasswordResetToken).values(
            user_id=user.user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            used_at=None,
            requested_ip=ip,
            requested_user_agent=ua,
        )
    )

    # optional audit
    session.add(
        LoginEvent(
            user_id=user.user_id,
            success=True,
            failure_reason="password_reset_requested",
            ip=ip,
            user_agent=ua,
            device=parse_user_agent(ua),
            app_base_url=str(payload.app_base_url) if payload.app_base_url else None,
            subdomain=None,
        )
    )

    await session.commit()

    # build reset url (frontend handles reset screen)
    base = (str(payload.app_base_url) if payload.app_base_url else str(request.base_url)).rstrip("/")
    reset_url = f"{base}/reset-password?token={token_plain}"

    # send email (dev mailer logs)
    await mailer.send_password_reset(to_email=user.email, reset_url=reset_url)

    return {"ok": True}


@router.post("/reset", status_code=status.HTTP_200_OK)
async def reset_password(
    payload: PasswordResetIn,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    """
    Verify token -> set new password -> revoke all sessions -> bump token_version
    """
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent")
    now = _now_utc()

    token_hash = hash_password_reset_token(payload.token)

    # 1) Find token row (must be unused + unexpired)
    res_token = await session.execute(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
    )
    prt = res_token.scalar_one_or_none()
    if not prt:
        # ✅ Security event: invalid/expired reset attempt
        await write_security_event(
            session,
            event_type="password_reset_failed_invalid_or_expired",
            severity="warning",
            details={},
            request=request,
        )
        await session.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # 2) Load user
    res_user = await session.execute(select(User).where(User.user_id == prt.user_id))
    user = res_user.scalar_one_or_none()
    if not user or not user.is_active:
        await write_security_event(
            session,
            event_type="password_reset_failed_invalid_or_expired",
            severity="warning",
            details={},
            request=request,
        )
        await session.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    try:
        prt.used_at = now

        await session.execute(
            update(User)
            .where(User.user_id == user.user_id)
            .values(
                password_hash=hash_password(payload.new_password),
                password_changed_at=now,
                token_version=User.token_version + 1,
                failed_login_count=0,
            )
        )

        # Revoke all sessions
        res_revoke = await session.execute(
            update(Session)
            .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason="password_reset_logout_all")
            .returning(Session.session_id)
        )
        revoked_count = len(res_revoke.all())

        # ✅ Security event: password reset completed
        await write_security_event(
            session,
            event_type="password_reset_completed",
            severity="info",
            user_id=user.user_id,
            details={"sessions_revoked": revoked_count},
            request=request,
        )

        session.add(
            LoginEvent(
                user_id=user.user_id,
                success=True,
                failure_reason="password_reset_success",
                ip=ip,
                user_agent=ua,
                device=parse_user_agent(ua),
                app_base_url=str(request.base_url),
                subdomain=None,
            )
        )

        await session.commit()
    except Exception:
        await session.rollback()
        raise

    clear_refresh_cookie(response)
    return {"ok": True}


@router.post("/change", status_code=status.HTTP_200_OK)
async def change_password(
    payload: PasswordChangeIn,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """
    Logged-in password change -> verify current -> update password -> logout all devices
    """
    now = _now_utc()

    if not verify_password(payload.current_password, user.password_hash):
        await write_security_event(
            session,
            event_type="password_change_failed_invalid_current_password",
            severity="warning",
            user_id=user.user_id,
            details={},
            request=request,
        )
        await session.commit()
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    await session.execute(
        update(User)
        .where(User.user_id == user.user_id)
        .values(
            password_hash=hash_password(payload.new_password),
            password_changed_at=now,
            token_version=User.token_version + 1,
            failed_login_count=0,
        )
    )

    res_revoke = await session.execute(
        update(Session)
        .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason="password_change_logout_all")
        .returning(Session.session_id)
    )
    revoked_count = len(res_revoke.all())

    await write_security_event(
        session,
        event_type="password_change_completed",
        severity="info",
        user_id=user.user_id,
        details={"sessions_revoked": revoked_count},
        request=request,
    )

    await session.commit()
    clear_refresh_cookie(response)
    return {"ok": True}


@router.post("/logout-all", status_code=status.HTTP_200_OK)
async def logout_all(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """
    Explicit logout all devices from UI
    - revokes all refresh sessions
    - bumps token_version so access tokens also die
    """
    now = _now_utc()

    res_revoke = await session.execute(
        update(Session)
        .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason="logout_all")
        .returning(Session.session_id)
    )
    revoked_count = len(res_revoke.all())

    await session.execute(
        update(User)
        .where(User.user_id == user.user_id)
        .values(token_version=User.token_version + 1)
    )

    await write_security_event(
        session,
        event_type="logout_all",
        severity="info",
        user_id=user.user_id,
        details={"sessions_revoked": revoked_count},
        request=request,
    )

    await session.commit()
    clear_refresh_cookie(response)
    return {"ok": True}
