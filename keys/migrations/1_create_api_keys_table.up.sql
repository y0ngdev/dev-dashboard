-- API Keys table
-- id is a short publicid (NanoID, 8 alphanumeric chars) — safe to embed in URLs.
-- user_id has no FK constraint since users live in the auth service's database.
-- The full API key is never stored; only its SHA-256 hash and a display preview.
CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    user_id      UUID NOT NULL,
    key_hash     VARCHAR(64) UNIQUE NOT NULL,
    key_preview  VARCHAR(64) NOT NULL,
    key_type     VARCHAR(10) NOT NULL DEFAULT 'live' CHECK (key_type IN ('live', 'test')),
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    is_active    BOOLEAN NOT NULL DEFAULT true,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id   ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash  ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX idx_api_keys_key_type  ON api_keys(key_type);
