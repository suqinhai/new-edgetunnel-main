-- Access-link usage limits and crash-safe connection accounting.
-- D1 records applied migrations, so every statement runs once per database.
ALTER TABLE access_links ADD COLUMN connection_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_links ADD COLUMN active_connections INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_links ADD COLUMN last_client_ip TEXT;
ALTER TABLE access_links ADD COLUMN last_client_asn TEXT;
ALTER TABLE access_links ADD COLUMN max_concurrent_connections INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_links ADD COLUMN max_total_connections INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_links ADD COLUMN bind_first_ip INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_links ADD COLUMN bound_ip TEXT;
ALTER TABLE access_links ADD COLUMN tags TEXT NOT NULL DEFAULT '';
ALTER TABLE access_links ADD COLUMN connection_epoch INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_access_links_tags ON access_links(tags);

CREATE TABLE IF NOT EXISTS access_connection_leases (
  id TEXT PRIMARY KEY,
  access_link_id INTEGER NOT NULL,
  proxy_ip TEXT,
  created_at INTEGER NOT NULL,
  heartbeat_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(access_link_id) REFERENCES access_links(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_access_connection_leases_link
  ON access_connection_leases(access_link_id);
CREATE INDEX IF NOT EXISTS idx_access_connection_leases_expiry
  ON access_connection_leases(expires_at);

CREATE TABLE IF NOT EXISTS access_connection_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  access_link_id INTEGER NOT NULL,
  proxy_ip TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  success INTEGER,
  error_code TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(access_link_id) REFERENCES access_links(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_access_connection_events_started
  ON access_connection_events(started_at);
CREATE INDEX IF NOT EXISTS idx_access_connection_events_link
  ON access_connection_events(access_link_id, started_at);
