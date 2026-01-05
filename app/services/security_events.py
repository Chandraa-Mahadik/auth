from __future__ import annotations

from typing import Any, Optional
import uuid

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SecurityEvent


def _uuid_or_none(value: object) -> uuid.UUID | None:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


async def write_security_event(
    session: AsyncSession,
    *,
    event_type: str,
    severity: str = "info",
    user_id: Optional[uuid.UUID] = None,
    session_id: Optional[uuid.UUID] = None,
    session_family_id: Optional[uuid.UUID] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[uuid.UUID] = None,
    details: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,  # ✅ NEW: pass request to auto-fill context
) -> None:
    # Auto-fill from middleware state if request is provided
    if request is not None:
        request_id = request_id or _uuid_or_none(getattr(request.state, "request_id", None))
        ip = ip or getattr(request.state, "client_ip", None)
        user_agent = user_agent or getattr(request.state, "user_agent", None)

    ev = SecurityEvent(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        session_id=session_id,
        session_family_id=session_family_id,
        ip=ip,
        user_agent=user_agent,
        request_id=request_id,
        details=details or {},
    )
    session.add(ev)
    # DO NOT commit here. Let the caller commit with its transaction.
