# app/routers/dev.py
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
import time
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decode_access_token, create_access_token
from app.db import get_session
from app.services.security_events import write_security_event

router = APIRouter(tags=["dev"])


def _require_debug_enabled():
    if not getattr(settings, "ENABLE_DEBUG_ENDPOINTS", False):
        # Return 404 so it "doesn't exist" in prod-like environments
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@router.get("/debug/time")
async def debug_time(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    _require_debug_enabled()

    await write_security_event(
        session,
        event_type="dev_debug_time",
        severity="info",
        details={},
        request=request,
    )
    await session.commit()

    return {
        "utc_iso": datetime.utcnow().isoformat() + "Z",
        "local_iso": datetime.now().isoformat(),
        "epoch": int(time.time()),
    }


@router.get("/debug/config")
async def debug_config(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    _require_debug_enabled()

    await write_security_event(
        session,
        event_type="dev_debug_config",
        severity="info",
        details={},
        request=request,
    )
    await session.commit()

    # safe subset only (do not leak DATABASE_URL, secrets, etc.)
    return {
        "ACCESS_TOKEN_EXPIRES_MIN": settings.ACCESS_TOKEN_EXPIRES_MIN,
        "REFRESH_TOKEN_EXPIRES_DAYS": settings.REFRESH_TOKEN_EXPIRES_DAYS,
        "JWT_ALGORITHM": settings.JWT_ALGORITHM,
        "APP_COOKIE_DOMAIN": settings.APP_COOKIE_DOMAIN,
    }


# --- DEV-ONLY token inspector ---
@router.post("/auth/token/inspect")
async def token_inspect(
    request: Request,
    token: str = Body(..., embed=True),
    session: AsyncSession = Depends(get_session),
):
    _require_debug_enabled()

    import jwt

    # Log the use of a token-inspection endpoint (dev-only)
    await write_security_event(
        session,
        event_type="dev_token_inspect",
        severity="warning",
        details={},
        request=request,
    )

    try:
        payload = decode_access_token(token)
        await session.commit()
        return {"ok": True, "verified": True, "payload": payload, "now_epoch": int(time.time())}
    except Exception as e:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            unverified = None

        await session.commit()
        return {
            "ok": False,
            "verified": False,
            "error": str(e),
            "unverified_payload": unverified,
            "now_epoch": int(time.time()),
        }


# --- DEV-ONLY: mint token ---
@router.post("/auth/token/mint-debug")
async def token_mint_debug(
    request: Request,
    user_id: str = Body(..., embed=True),
    session: AsyncSession = Depends(get_session),
):
    _require_debug_enabled()

    import jwt

    # Log dev token minting (dev-only, but security-relevant)
    await write_security_event(
        session,
        event_type="dev_token_mint",
        severity="high",
        details={"user_id": user_id},
        request=request,
    )

    tok = create_access_token(user_id, extra={"email": "debug@example.com"})
    payload = jwt.decode(tok, options={"verify_signature": False})

    await session.commit()
    return {"now_epoch": int(time.time()), "token": tok, "payload": payload}
