# ADR-0002: Access vs Refresh Token Strategy

## Status
Accepted

## Context
Need balance between performance and security.

## Decision
- Short-lived JWT access tokens
- Long-lived refresh tokens with rotation

## Consequences
+ Scales horizontally
+ Central revocation possible
