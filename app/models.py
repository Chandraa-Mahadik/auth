from __future__ import annotations
from datetime import datetime
import uuid
from typing import Optional

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Boolean, Text, TIMESTAMP, ForeignKey, func, JSON, String, Index
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, INET, CITEXT

class Base(DeclarativeBase):
    pass

# ---- USERS ----
class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True),
                                               primary_key=True,
                                               default=uuid.uuid4)
    email: Mapped[str] = mapped_column(CITEXT, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True),
                                                 server_default=func.now(),
                                                 nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True),
                                                 server_default=func.now(),
                                                 nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True),
                                                              nullable=True)
    failed_login_count: Mapped[int] = mapped_column(nullable=False, default=0)

    sessions: Mapped[list["Session"]] = relationship(back_populates="user")

# ---- SESSIONS ----
class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True),
                                                  primary_key=True,
                                                  default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True),
                                                 server_default=func.now(),
                                                 nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True),
                                                   server_default=func.now(),
                                                   nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True),
                                                 nullable=False)

    refresh_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    user: Mapped["User"] = relationship(back_populates="sessions")

# ---- LOGIN EVENTS ----
class LoginEvent(Base):
    __tablename__ = "login_events"

    # Single PK (autoincrement) – avoids composite PK + autoincrement conflict
    event_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    occurred_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )

    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    country: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    latitude: Mapped[Optional[float]] = mapped_column(nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(nullable=True)

    app_base_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    subdomain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

# Optional index if you query by time a lot:
Index("idx_login_events_occurred_at", LoginEvent.occurred_at)
