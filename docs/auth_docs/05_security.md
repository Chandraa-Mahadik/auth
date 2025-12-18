# Security Model

## Implemented Controls
- Argon2 password hashing
- HTTP-only refresh cookies
- Refresh token hashing
- Token rotation
- Rate limiting (in-memory)
- Structured audit logs

## Known Gaps
- Redis-backed rate limiting
- Account lockout enforcement
- Token version invalidation
- MFA support

## Threat Model (High Level)
- Credential stuffing
- Refresh token replay
- Insider DB access

Mitigations documented per threat.
