-- Add permission scopes and API version tracking to api_keys.
--
-- scopes      — JSONB array of scope strings, e.g. ["*"] or ["charges:read","customers:read"]
--               Defaults to ["*"] (full access) for secret/webhook keys.
--               Defaults to ["charges:read","payments:read","customers:read"] for publishable keys.
--
-- api_version — The default API version for this key, e.g. "2026-03-15".
--               Inherited from the key's creation-time version; used by middleware
--               when no Stripe-Version header is present on the request.

ALTER TABLE api_keys
    ADD COLUMN scopes      JSONB        NOT NULL DEFAULT '["*"]',
    ADD COLUMN api_version VARCHAR(12)  NOT NULL DEFAULT '2026-03-15';

CREATE INDEX idx_api_keys_api_version ON api_keys(api_version);
