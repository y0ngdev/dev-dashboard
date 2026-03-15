-- Webhook endpoints table
-- Stores merchant-registered URLs that should receive event notifications.
--
-- user_id       — references auth.users (no FK — cross-service boundary)
-- webhook_key_id — references api_keys.id for the WHLIVE/WHTEST signing key
-- url           — the HTTPS endpoint to POST events to
-- events        — JSON array of event types to subscribe to, e.g. ["charge.succeeded"]
--                 NULL means subscribe to all events
-- is_active     — soft disable without deletion
CREATE TABLE webhook_endpoints (
    id             TEXT PRIMARY KEY,
    user_id        UUID NOT NULL,
    webhook_key_id TEXT NOT NULL,
    url            TEXT NOT NULL,
    description    TEXT,
    events         JSONB,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_endpoints_user_id        ON webhook_endpoints(user_id);
CREATE INDEX idx_webhook_endpoints_webhook_key_id ON webhook_endpoints(webhook_key_id);
CREATE INDEX idx_webhook_endpoints_is_active      ON webhook_endpoints(is_active);

-- Webhook deliveries table
-- Immutable log of every outbound delivery attempt.
--
-- event_type    — e.g. "charge.succeeded"
-- event_id      — idempotency ID for the event (UUID)
-- payload       — the JSON body sent to the endpoint
-- status        — pending | succeeded | failed
-- http_status   — response status code from the merchant's server (NULL if unreachable)
-- attempts      — number of delivery attempts made
-- next_retry_at — when the next retry should be attempted (NULL if done)
-- delivered_at  — timestamp of first successful delivery
CREATE TABLE webhook_deliveries (
    id             TEXT PRIMARY KEY,
    endpoint_id    TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL,
    event_type     VARCHAR(100) NOT NULL,
    event_id       UUID NOT NULL,
    payload        JSONB NOT NULL,
    status         VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed')),
    http_status    INTEGER,
    attempts       INTEGER NOT NULL DEFAULT 0,
    next_retry_at  TIMESTAMPTZ,
    delivered_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_endpoint_id   ON webhook_deliveries(endpoint_id);
CREATE INDEX idx_webhook_deliveries_user_id        ON webhook_deliveries(user_id);
CREATE INDEX idx_webhook_deliveries_status         ON webhook_deliveries(status);
CREATE INDEX idx_webhook_deliveries_next_retry_at  ON webhook_deliveries(next_retry_at) WHERE status = 'pending';
CREATE INDEX idx_webhook_deliveries_event_id       ON webhook_deliveries(event_id);
