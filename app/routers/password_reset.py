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
        return {"ok": True}

    # --- user lookup ---
    res = await session.execute(select(User).where(User.email == email_norm))
    user = res.scalar_one_or_none()

    if not user or not user.is_active:
        return {"ok": True}

    # --- create reset token ---
    token_plain = new_password_reset_token()
    token_hash = hash_password_reset_token(token_plain)
    expires_at = _now_utc() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_MINUTES)

    # ✅ Correct insertion (ORM insert) — fixes your SQLAlchemy "text()" crash
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
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # 2) Load user
    res_user = await session.execute(select(User).where(User.user_id == prt.user_id))
    user = res_user.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # 3) Atomic changes (one transaction)
    #    - mark token used
    #    - update password + token_version++
    #    - revoke all sessions
    #    - audit
    try:
        # Mark token used (idempotency guard)
        prt.used_at = now

        await session.execute(
            update(User)
            .where(User.user_id == user.user_id)
            .values(
                password_hash=hash_password(payload.new_password),  # ✅ uses existing hash_password
                password_changed_at=now,
                token_version=User.token_version + 1,  # ✅ kills all access tokens
                failed_login_count=0,
            )
        )

        await session.execute(
            update(Session)
            .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason="password_reset_logout_all")
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

    # Clear refresh cookie for this browser (best-effort)
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

    await session.execute(
        update(Session)
        .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason="password_change_logout_all")
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

    await session.execute(
        update(Session)
        .where(Session.user_id == user.user_id, Session.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason="logout_all")
    )

    await session.execute(
        update(User)
        .where(User.user_id == user.user_id)
        .values(token_version=User.token_version + 1)
    )

    await session.commit()
    clear_refresh_cookie(response)
    return {"ok": True}
