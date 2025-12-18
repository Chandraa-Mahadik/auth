# app/routers/dev.py
from fastapi import APIRouter, Body
import time
from datetime import datetime

from app.core.config import settings
from app.core.security import decode_access_token, create_access_token

router = APIRouter(tags=["dev"])

@router.get("/debug/time")
def debug_time():
    return {
        "utc_iso": datetime.utcnow().isoformat() + "Z",
        "local_iso": datetime.now().isoformat(),
        "epoch": int(time.time()),
    }

@router.get("/debug/config")
def debug_config():
    # safe subset only (do not leak DATABASE_URL, secrets, etc.)
    return {
        "ACCESS_TOKEN_EXPIRES_MIN": settings.ACCESS_TOKEN_EXPIRES_MIN,
        "REFRESH_TOKEN_EXPIRES_DAYS": settings.REFRESH_TOKEN_EXPIRES_DAYS,
        "JWT_ALGORITHM": settings.JWT_ALGORITHM,
        "APP_COOKIE_DOMAIN": settings.APP_COOKIE_DOMAIN,
    }

# --- DEV-ONLY token inspector ---
@router.post("/auth/token/inspect")
def token_inspect(token: str = Body(..., embed=True)):
    import jwt
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

# --- DEV-ONLY: mint token ---
@router.post("/auth/token/mint-debug")
def token_mint_debug(user_id: str = Body(..., embed=True)):
    import jwt
    tok = create_access_token(user_id, extra={"email": "debug@example.com"})
    payload = jwt.decode(tok, options={"verify_signature": False})
    return {"now_epoch": int(time.time()), "token": tok, "payload": payload}
