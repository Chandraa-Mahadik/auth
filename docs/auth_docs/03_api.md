# API Reference

## Health
### GET /healthz
Returns service liveness.

### GET /healthz/db
Verifies DB connectivity.

## Auth

### POST /auth/login
Authenticates user and creates session.

Request:
```json
{
  "email": "user@example.com",
  "password": "secret",
  "app_base_url": "https://app.example.com"
}

Response:
{
  "access_token": "<JWT>"
}

POST /auth/refresh
Rotates refresh token and issues new access token.

POST /auth/logout
Revokes current session.

GET /auth/me
Returns authenticated user profile.

Debug (Non-prod only)
    /debug/time
    /debug/config
    /auth/token/inspect
    /auth/token/mint-debug