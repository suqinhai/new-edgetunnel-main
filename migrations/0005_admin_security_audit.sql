-- Random admin sessions, login throttling, audit trail and notification cooldowns.
CREATE TABLE IF NOT EXISTS admin_sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  source_ip TEXT,
  source_asn TEXT,
  user_agent_hash TEXT NOT NULL,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry
  ON admin_sessions(expires_at, revoked_at);

CREATE TABLE IF NOT EXISTS admin_login_attempts (
  ip_hash TEXT PRIMARY KEY,
  window_started_at INTEGER NOT NULL,
  failure_count INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER,
  last_attempt_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  session_id TEXT,
  source_ip TEXT,
  source_asn TEXT,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL DEFAULT '',
  before_summary TEXT,
  after_summary TEXT,
  success INTEGER NOT NULL,
  error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_object ON audit_logs(object_type, object_id, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_state (
  event_key TEXT PRIMARY KEY,
  last_payload_hash TEXT NOT NULL,
  last_sent_at INTEGER NOT NULL,
  cooldown_until INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT INTO schema_metadata(key, value, updated_at)
VALUES ('access_management_schema', '5', CAST(strftime('%s','now') AS INTEGER) * 1000)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
