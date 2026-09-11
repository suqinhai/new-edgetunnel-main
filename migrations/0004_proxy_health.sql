-- Health scoring, real-traffic feedback and per-country capacity policy.
ALTER TABLE proxy_ip_pool ADD COLUMN health_score INTEGER NOT NULL DEFAULT 50;
ALTER TABLE proxy_ip_pool ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxy_ip_pool ADD COLUMN cooldown_until INTEGER;
ALTER TABLE proxy_ip_pool ADD COLUMN real_success_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxy_ip_pool ADD COLUMN real_failure_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxy_ip_pool ADD COLUMN last_real_failure INTEGER;

ALTER TABLE proxy_ip_sources ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_proxy_pool_score
  ON proxy_ip_pool(country, enabled, cooldown_until, health_score);

CREATE TABLE IF NOT EXISTS country_health_config (
  country TEXT PRIMARY KEY,
  min_healthy_ips INTEGER NOT NULL DEFAULT 3,
  updated_at INTEGER NOT NULL
);

