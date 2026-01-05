from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from app.db import get_session
from app.models import Session, User
from app.deps.auth import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


def compute_session_status(sess: Session, now: datetime) -> str:
    """
    GOLD STANDARD derived session status.
    Never store this in DB.
    """

    if sess.compromised_at:
        return "compromised"

    if sess.revoked_at:
        if sess.revoked_reason == "rotated":
            return "rotated"
        return "revoked"

    if sess.expires_at <= now:
        return "expired"

    return "active"


@router.get("/sessions")
async def list_my_sessions(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """
    List all sessions for the logged-in user.
    """

    now = datetime.now(timezone.utc)

    res = await session.execute(
        select(Session)
        .where(Session.user_id == user.user_id)
        .order_by(Session.created_at.desc())
    )

    sessions = res.scalars().all()

    out = []

    for s in sessions:
        out.append(
            {
                "session_id": str(s.session_id),
                "session_family_id": str(s.session_family_id) if s.session_family_id else None,

                "session_status": compute_session_status(s, now),

                "created_at": s.created_at,
                "last_seen_at": s.last_seen_at,
                "expires_at": s.expires_at,

                "revoked_at": s.revoked_at,
                "revoked_reason": s.revoked_reason,

                "compromised_at": s.compromised_at,
                "compromised_reason": s.compromised_reason,

                "rotated_at": s.rotated_at,
                "replaced_by_session_id": (
                    str(s.replaced_by_session_id)
                    if s.replaced_by_session_id
                    else None
                ),

                "ip": s.ip,
                "device": s.device,
                "user_agent": s.user_agent,
            }
        )

    return {
        "user_id": str(user.user_id),
        "sessions": out,
    }
