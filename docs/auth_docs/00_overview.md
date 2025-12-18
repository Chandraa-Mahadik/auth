# CAP — Central Authentication Platform

## Purpose
CAP is a **centralized authentication service** designed to be the single source of truth
for identity, sessions, and login analytics across multiple applications.

## Core Responsibilities
- User authentication (email/password)
- Access token issuance (JWT)
- Refresh token lifecycle management
- Session persistence and revocation
- Login event auditing (success/failure)
- Platform-ready observability

## Design Philosophy
- Security-first
- Explicit session state (no “stateless magic”)
- Append-only audit trails
- Clear separation of concerns
- Designed for future expansion (MFA, SSO, analytics)

## Non-goals (for now)
- Authorization / RBAC
- OAuth2 / OpenID federation
- MFA enforcement
