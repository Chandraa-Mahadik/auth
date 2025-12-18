# ADR-0001: Refresh Token Cookie Strategy

## Status
Accepted

## Context
Refresh tokens must be protected from XSS and replay.

## Decision
Use HTTP-only cookies with server-side session records.

## Consequences
+ Strong replay protection
+ Logout is enforceable
- Requires DB lookup
