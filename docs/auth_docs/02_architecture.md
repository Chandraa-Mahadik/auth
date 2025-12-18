
---

## 📄 `docs/02_architecture.md`

```md
# Architecture

## High-Level Components

Client → FastAPI → PostgreSQL

### API Layer
- FastAPI
- Pydantic schemas
- Router-based separation

### Auth Core
- Argon2 password verification
- JWT access tokens
- Refresh token rotation

### Persistence
- PostgreSQL (async SQLAlchemy)
- Explicit session table
- Partitioned login_events

## Key Architectural Decisions
- Refresh tokens are **stateful**
- Access tokens are **short-lived**
- Login events are **append-only**
- No soft-deletes for audit data

## Trust Boundaries
- Browser ↔ API
- API ↔ Database
- API ↔ Reverse proxy (X-Forwarded-For)
