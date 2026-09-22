-- Track the address family verified by the PROXYIP health probe.
ALTER TABLE proxy_ip_pool ADD COLUMN ip_stack TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE proxy_ip_pool ADD COLUMN supports_ipv4 INTEGER;
ALTER TABLE proxy_ip_pool ADD COLUMN supports_ipv6 INTEGER;
ALTER TABLE proxy_ip_pool ADD COLUMN exit_ip TEXT;

CREATE INDEX IF NOT EXISTS idx_proxy_pool_ipv4
  ON proxy_ip_pool(country, enabled, supports_ipv4, health_status);
