from __future__ import annotations
from datetime import datetime
import uuid
from typing import Optional

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Boolean, Text, TIMESTAMP, ForeignKey, func, JSON, String, Index, DateTime
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

    # --- Identity lifecycle (present in DB; safe defaults keep current flows working) ---
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    token_version: Mapped[int] = mapped_column(nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    auth_provider: Mapped[str] = mapped_column(String, nullable=False, default="local")
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )

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
    
    session_family_id: Mapped[uuid.UUID | None] = mapped_column(PG_UUID(as_uuid=True), index=True, nullable=True)

    # replaced_by_session_id: Mapped[uuid.UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    replaced_by_session_id: Mapped[uuid.UUID | None] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=True)
    
    # compromised_at: Mapped[datetime | None] = mapped_column(nullable=True)
    compromised_at = mapped_column(DateTime(timezone=True), nullable=True)
    compromised_reason: Mapped[str | None] = mapped_column(nullable=True)

    # Gold-standard session control / rotation primitives
    refresh_token_family_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, default=uuid.uuid4
    )
    rotated_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    revoked_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    user: Mapped["User"] = relationship(back_populates="sessions")

# ---- LOGIN EVENTS ----
class LoginEvent(Base):
    __tablename__ = "login_events"

    # DB has a composite PK (event_id, occurred_at) due to partitioning.
    event_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    occurred_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
        primary_key=True,
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


# ---- PASSWORD RESET TOKENS ----
class PasswordResetToken(Base):
    """Stores *hashed* password reset tokens.

    Security notes:
    - Never store the plain token.
    - Single-use via used_at.
    - Short TTL via expires_at.
    """

    __tablename__ = "password_reset_tokens"

    token_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    requested_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


Index("idx_password_reset_tokens_user_id", PasswordResetToken.user_id)
Index("idx_password_reset_tokens_expires_at", PasswordResetToken.expires_at)
