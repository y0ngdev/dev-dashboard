-- Usage tracking table
-- api_key_id and user_id reference other services' databases, so no FK constraints.
CREATE TABLE usage (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id   UUID,
    user_id      UUID NOT NULL,
    endpoint     VARCHAR(255) NOT NULL,
    method       VARCHAR(10) NOT NULL,
    status_code  INTEGER NOT NULL,
    duration_ms  INTEGER,
    requested_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_usage_user_id      ON usage(user_id);
CREATE INDEX idx_usage_api_key_id   ON usage(api_key_id);
CREATE INDEX idx_usage_requested_at ON usage(requested_at);
