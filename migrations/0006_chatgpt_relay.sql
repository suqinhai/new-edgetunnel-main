-- HMAC replay protection and per-client rate limiting for the fixed ChatGPT checkout relay.
-- Access tokens and plaintext nonces are never stored.
CREATE TABLE IF NOT EXISTS chatgpt_relay_nonces (
  nonce_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chatgpt_relay_nonces_expiry
  ON chatgpt_relay_nonces(expires_at);

CREATE TABLE IF NOT EXISTS chatgpt_relay_rate_limits (
  client_hash TEXT PRIMARY KEY,
  window_started_at INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chatgpt_relay_rate_expiry
  ON chatgpt_relay_rate_limits(expires_at);
