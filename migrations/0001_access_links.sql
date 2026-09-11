CREATE TABLE IF NOT EXISTS access_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  uuid TEXT NOT NULL UNIQUE,
  country TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  proxy_ip TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  first_used_at INTEGER,
  expires_at INTEGER,
  last_used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_access_links_status_expires
  ON access_links(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_access_links_country
  ON access_links(country);

CREATE TABLE IF NOT EXISTS proxy_ip_pool (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  country TEXT NOT NULL,
  proxy_ip TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(country, proxy_ip)
);

CREATE INDEX IF NOT EXISTS idx_proxy_pool_country_enabled
  ON proxy_ip_pool(country, enabled);
