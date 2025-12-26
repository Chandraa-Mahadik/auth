-- DB cron / scheduled SQL
--     This is production-friendly because:
--         works even if app is down
--         no dependency on app workers
--         predictable performance window

BEGIN;

-- sessions: delete long-expired/revoked (tune retention)
DELETE FROM sessions
WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '30 days')
   OR (expires_at < now() - interval '30 days');

-- login_events: keep 90 days (tune)
DELETE FROM login_events
WHERE occurred_at < now() - interval '90 days';

COMMIT;

--
-- Next step : 

-- Test manually (one-time)
-- From the machine that can access your DB:
-- psql "postgresql://USER:PASSWORD@HOST:5432/auth_db_dev" -f db/maintenance/cleanup.sql

--
-- Next Step : 

-- Linux (cron)
-- crontab -e
-- Add (runs daily at 03:10):

-- 10 3 * * * psql "postgresql://USER:PASSWORD@HOST:5432/auth_db_dev" -f /absolute/path/to/db/maintenance/cleanup.sql >> /var/log/auth_cleanup.log 2>&1

--
