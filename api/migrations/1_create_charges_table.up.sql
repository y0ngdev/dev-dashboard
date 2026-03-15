-- Charges represent a payment attempt against a card or payment method.
CREATE TABLE charges (
    id              TEXT PRIMARY KEY,        -- publicid (8-char NanoID)
    user_id         TEXT NOT NULL,           -- merchant's user ID (from api key)
    api_key_id      TEXT NOT NULL,           -- which API key was used
    key_type        TEXT NOT NULL CHECK (key_type IN ('live', 'test')),
    amount          BIGINT NOT NULL CHECK (amount > 0),  -- in smallest currency unit (cents)
    currency        TEXT NOT NULL DEFAULT 'usd',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'succeeded', 'failed', 'refunded', 'partially_refunded')),
    description     TEXT NOT NULL DEFAULT '',
    -- Payment method snapshot (card details are not stored — only a safe display subset)
    payment_method  TEXT NOT NULL DEFAULT '',  -- e.g. "card"
    card_last4      TEXT,
    card_brand      TEXT,
    card_exp_month  SMALLINT,
    card_exp_year   SMALLINT,
    -- Outcome
    failure_code    TEXT,
    failure_message TEXT,
    -- Amounts refunded
    amount_refunded BIGINT NOT NULL DEFAULT 0,
    -- Idempotency
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX charges_user_id_created_at ON charges (user_id, created_at DESC);
CREATE INDEX charges_api_key_id         ON charges (api_key_id);

-- Refunds represent a partial or full reversal of a charge.
CREATE TABLE refunds (
    id          TEXT PRIMARY KEY,
    charge_id   TEXT NOT NULL REFERENCES charges(id),
    user_id     TEXT NOT NULL,
    amount      BIGINT NOT NULL CHECK (amount > 0),
    currency    TEXT NOT NULL DEFAULT 'usd',
    status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'succeeded', 'failed')),
    reason      TEXT NOT NULL DEFAULT '',
    failure_code    TEXT,
    failure_message TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX refunds_charge_id ON refunds (charge_id);
CREATE INDEX refunds_user_id   ON refunds (user_id, created_at DESC);
