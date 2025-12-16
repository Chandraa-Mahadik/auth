-- ============================================================
--  Extensions
-- ============================================================

-- UUID support (kept as-is from your original)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- You use CITEXT for email, so this must exist
CREATE EXTENSION IF NOT EXISTS citext;

-- NOTE : IMP.
-- (Optional) if you later want gen_random_uuid() instead of uuid-ossp:
-- CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- This is done.. and on choosing pgcrypto a change is required : 
-- Replace 'uuid_generate_v4' of uuid-ossp with 'gen_random_uuid' of pgcrytpo.


-- ============================================================
--  Utility: updated_at trigger
-- ============================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END; $$ LANGUAGE plpgsql;


-- ============================================================
--  Users (identity + lifecycle fields)
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
  user_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  email                CITEXT UNIQUE NOT NULL,      -- case-insensitive
  password_hash        TEXT NOT NULL,               -- argon2/bcrypt hash
  full_name            TEXT,

  -- Lifecycle / security flags
  is_active            BOOLEAN NOT NULL DEFAULT TRUE,

  -- Email verification lifecycle (needed for real-world auth)
  is_verified          BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified_at    TIMESTAMPTZ,

  -- Token/session invalidation primitive (gold standard kill-switch)
  -- When you bump token_version, APIs can reject access tokens that carry an older version.
  token_version        INTEGER NOT NULL DEFAULT 0,

  -- Account security / lockout primitives
  failed_login_count   INTEGER NOT NULL DEFAULT 0,
  locked_until         TIMESTAMPTZ,
  last_login_at        TIMESTAMPTZ,
  password_changed_at  TIMESTAMPTZ,

  -- Provider hint for future SSO/social linking
  auth_provider        TEXT NOT NULL DEFAULT 'local',

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Optional soft delete for compliance / retention workflows
  deleted_at           TIMESTAMPTZ

  -- NOTE: Avoid strict email regex checks at DB layer.
  -- It's better enforced at API boundary (Pydantic) and keeps DB future-proof.
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);
CREATE INDEX IF NOT EXISTS users_active_idx ON users (is_active) WHERE deleted_at IS NULL;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- ============================================================
--  Login events (append-only audit, partitioned monthly)
-- ============================================================

CREATE TABLE IF NOT EXISTS login_events (
  event_id          BIGSERIAL,
  user_id           UUID REFERENCES users(user_id) ON DELETE SET NULL,
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  success           BOOLEAN NOT NULL,
  failure_reason    TEXT,
  ip                INET,
  user_agent        TEXT,
  device            JSONB,
  country           TEXT,
  region            TEXT,
  city              TEXT,
  latitude          DOUBLE PRECISION,
  longitude         DOUBLE PRECISION,
  app_base_url      TEXT,
  subdomain         TEXT,
  PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Partitions (keep your approach; you can generate monthly via cron)
CREATE TABLE IF NOT EXISTS login_events_2025_11 PARTITION OF login_events
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE IF NOT EXISTS login_events_2025_12 PARTITION OF login_events
  FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');
CREATE TABLE IF NOT EXISTS login_events_2026_01 PARTITION OF login_events
  FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

-- Gold standard: define indexes at the parent level as PARTITIONED indexes.
-- This avoids manually creating indexes on each new monthly partition.
CREATE INDEX IF NOT EXISTS login_events_user_time_idx
  ON login_events (user_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS login_events_time_idx
  ON login_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS login_events_subdomain_idx
  ON login_events (subdomain);


-- ============================================================
--  Sessions (refresh token sessions, revocation-ready)
-- ============================================================

CREATE TABLE IF NOT EXISTS sessions (
  session_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at           TIMESTAMPTZ NOT NULL,

  -- Store ONLY salted hash of refresh token, never the token
  refresh_token_hash   TEXT NOT NULL,

  -- Optional: to support refresh-token rotation chains & theft detection later
  refresh_token_family_id UUID NOT NULL DEFAULT gen_random_uuid(),
  rotated_at           TIMESTAMPTZ,

  -- Device / context
  ip                   INET,
  user_agent           TEXT,
  device               JSONB,

  -- Gold standard revocation fields (replaces revoked boolean)
  revoked_at           TIMESTAMPTZ,
  revoked_reason       TEXT,

  UNIQUE (user_id, session_id)
);

-- Active session lookup index (revoked_at null = active)
CREATE INDEX IF NOT EXISTS sessions_user_active_idx
  ON sessions (user_id)
  WHERE revoked_at IS NULL;

-- Optional: quick lookup for refresh family operations
CREATE INDEX IF NOT EXISTS sessions_family_idx
  ON sessions (refresh_token_family_id);


-- ============================================================
--  Materialized view (optional)
-- ============================================================

-- NOTE: materialized views with partitioned parents can work, but refreshing can be heavy.
-- Keep it optional; you can also build this as a query or a separate analytics pipeline.
CREATE MATERIALIZED VIEW IF NOT EXISTS login_stats_30d AS
SELECT
  user_id,
  COUNT(*) FILTER (WHERE success)          AS success_count,
  COUNT(*) FILTER (WHERE NOT success)      AS failure_count,
  MAX(occurred_at) FILTER (WHERE success)  AS last_success_at
FROM login_events
WHERE occurred_at >= NOW() - INTERVAL '30 days'
GROUP BY user_id;
