# Operations

## Logging
- JSON structured logs
- X-Request-ID correlation

## Health Monitoring
- /healthz
- /healthz/db

## Deployment Notes
- HTTPS mandatory for prod
- Secure cookie domain configuration
- Reverse proxy must set X-Forwarded-For

## Backup & Recovery
- PostgreSQL backups required
- login_events is audit-critical
