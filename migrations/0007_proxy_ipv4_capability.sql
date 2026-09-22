-- Track the address family verified by the PROXYIP health probe.
--
-- The Worker startup compatibility path adds these columns when an older D1
-- database is used before migrations are applied. SQLite/D1 has no portable
-- `ADD COLUMN IF NOT EXISTS`, so the column additions intentionally remain in
-- that runtime path; this migration records that compatibility step instead.
-- Runtime initialization creates the columns and index idempotently, which
-- keeps this migration safe after an older Worker has already added them.
INSERT OR IGNORE INTO schema_metadata(key, value, updated_at)
VALUES ('proxy_ipv4_capability', 'runtime_compat', CAST(strftime('%s','now') AS INTEGER) * 1000);
