# Notes
# This is intentionally simple and robust: it queries the DB directly.
# It supports filters that are useful in debugging (event_type, user_id, request_id, etc.).
# IMP : No auth added because you asked dev-only; later we’ll gate by RBAC.

from __future__ import annotations

from typing import Optional, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.db import get_session  # adjust import if your project uses a different path

router = APIRouter(prefix="/security-events", tags=["security-events"])


@router.get("")
async def list_security_events(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
) -> dict[str, Any]:
    """
    Dev-only: returns latest security events (newest first).
    Filters are optional. This endpoint must be mounted only when ENABLE_DEBUG_ENDPOINTS=True.
    """

    where = []
    params: dict[str, Any] = {"limit": limit}

    if event_type:
        where.append("event_type = :event_type")
        params["event_type"] = event_type

    if severity:
        where.append("severity = :severity")
        params["severity"] = severity

    if user_id:
        where.append("user_id::text = :user_id")
        params["user_id"] = user_id

    if request_id:
        where.append("request_id::text = :request_id")
        params["request_id"] = request_id

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    rows = (
        await session.execute(
            text(
                f"""
                SELECT
                  event_id,
                  occurred_at,
                  event_type,
                  severity,
                  user_id,
                  session_id,
                  session_family_id,
                  request_id,
                  ip,
                  user_agent,
                  details
                FROM public.security_events
                {where_sql}
                ORDER BY occurred_at DESC
                LIMIT :limit
                """
            ),
            params,
        )
    ).mappings().all()

    return {"count": len(rows), "items": [dict(r) for r in rows]}
