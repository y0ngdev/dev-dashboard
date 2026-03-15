-- API Keys table
-- id is a short publicid (NanoID, 8 alphanumeric chars) — safe to embed in URLs.
-- user_id has no FK constraint since users live in the auth service's database.
-- The full API key is never stored; only its SHA-256 hash and a display preview.
--
-- key_type       — environment:  'live' | 'test'
-- key_capability — access level: 'secret' | 'publishable' | 'webhook'
--
-- Combined these map to Stripe-style prefixes:
--   SKLIVE (sk_live_...) — secret      + live
--   SKTEST (sk_test_...) — secret      + test
--   PKLIVE (pk_live_...) — publishable + live
--   PKTEST (pk_test_...) — publishable + test
--   WHLIVE (wh_live_...) — webhook     + live
--   WHTEST (wh_test_...) — webhook     + test
--
-- Keys are generated with uuidkey.NewAPIKey (UUIDv7 + 256-bit BLAKE2b entropy)
-- following the GitHub Secret Scanning format so GitHub will auto-flag any
-- accidentally committed keys.
--
-- key_secret_enc — AES-256-GCM ciphertext (hex) of the raw webhook signing secret.
--   Only populated for webhook capability keys; NULL for secret/publishable keys.
--   Allows the server to sign outbound webhook payloads without the merchant
--   needing to re-supply the secret.
CREATE TABLE api_keys (
    id             TEXT PRIMARY KEY,
    user_id        UUID NOT NULL,
    key_hash       VARCHAR(64) UNIQUE NOT NULL,
    key_preview    VARCHAR(32) NOT NULL,
    key_type       VARCHAR(10) NOT NULL DEFAULT 'live'    CHECK (key_type       IN ('live', 'test')),
    key_capability VARCHAR(12) NOT NULL DEFAULT 'secret'  CHECK (key_capability IN ('secret', 'publishable', 'webhook')),
    name           VARCHAR(255) NOT NULL,
    description    TEXT,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    key_secret_enc TEXT,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id        ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash       ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active      ON api_keys(is_active);
CREATE INDEX idx_api_keys_key_type       ON api_keys(key_type);
CREATE INDEX idx_api_keys_key_capability ON api_keys(key_capability);
