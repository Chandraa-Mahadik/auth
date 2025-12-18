
---

## 📄 `docs/04_database.md`

```md
# Database Design

## Core Tables
- users
- sessions
- login_events (partitioned)

## users
Represents identities.

Notable fields:
- password_hash (Argon2)
- failed_login_count
- locked_until
- token_version

## sessions
Represents refresh-token backed sessions.

Security properties:
- refresh_token_hash (SHA-256)
- server-side revocation
- rotation timestamp

## login_events
Append-only audit table.

Partitioned by month on `occurred_at`.

## Migration Strategy
- Initial schema applied via DDL
- Alembic to be introduced as baseline
