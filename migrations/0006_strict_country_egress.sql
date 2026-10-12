-- A country label is not proof of the actual egress country.
ALTER TABLE proxy_ip_pool ADD COLUMN exit_country TEXT;
ALTER TABLE proxy_ip_pool ADD COLUMN exit_ip TEXT;
ALTER TABLE proxy_ip_pool ADD COLUMN country_verified_at INTEGER;
ALTER TABLE proxy_ip_pool ADD COLUMN country_error TEXT NOT NULL DEFAULT '';

-- Old active connections will be closed by the existing epoch status check.
-- Preserve duration, first-use time, credentials and usage statistics.
UPDATE access_links SET proxy_ip = NULL, connection_epoch = connection_epoch + 1;

INSERT INTO schema_metadata(key, value, updated_at)
VALUES ('access_management_schema', '6', unixepoch() * 1000)
ON CONFLICT(key) DO UPDATE SET value = '6', updated_at = excluded.updated_at;
