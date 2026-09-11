CREATE TABLE IF NOT EXISTS proxy_ip_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE,
  default_country TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  refresh_minutes INTEGER NOT NULL DEFAULT 30,
  max_per_country INTEGER NOT NULL DEFAULT 100,
  last_synced_at INTEGER,
  last_status TEXT NOT NULL DEFAULT 'never',
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_ip_source_sync (
  source_id INTEGER NOT NULL,
  country TEXT NOT NULL,
  last_synced_at INTEGER NOT NULL,
  last_status TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(source_id, country)
);
