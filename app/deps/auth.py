from __future__ import annotations
from typing import Optional, Iterable
import uuid
import logging
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.security import decode_access_token, get_jwt_subject
from app.db import get_session
from app.models import User

log = logging.getLogger("app")
bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_session),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        sub = get_jwt_subject(payload)
        user_id = uuid.UUID(str(sub))  # coerce to UUID
    except Exception as e:
        log.warning("jwt_decode_failed", extra={
            "request_id": getattr(request.state, "request_id", None),
            "error": str(e),
        })
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid/expired token")

    res = await session.execute(
        select(User).where(User.user_id == user_id, User.is_active == True)
    )
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found/inactive")
    request.state.user_id = str(user.user_id)
    return user
