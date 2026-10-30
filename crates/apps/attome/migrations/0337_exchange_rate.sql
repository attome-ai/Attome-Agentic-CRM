-- A19-T2: dated exchange rates. One row converts one unit of
-- from_currency into to_currency on rate_date, from a named source
-- ('manual' for a rate an administrator entered, or the feed that imported
-- it). The rate for a day is the newest on or before it
-- (attome_core::fx::rate_on). Reference data, not customer records:
-- written through /api/v1/exchange-rates by the runtime role, readable by
-- attome_readonly.
CREATE TABLE IF NOT EXISTS exchange_rate (
    id uuid PRIMARY KEY,
    from_currency char(3) NOT NULL REFERENCES currency (code),
    to_currency char(3) NOT NULL REFERENCES currency (code),
    rate numeric(20,10) NOT NULL CHECK (rate > 0),
    rate_date date NOT NULL,
    source text NOT NULL CHECK (source ~ '^[a-z0-9_.-]{1,64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    CONSTRAINT exchange_rate_pair_differs CHECK (from_currency <> to_currency),
    CONSTRAINT exchange_rate_one_per_day_and_source
        UNIQUE (from_currency, to_currency, rate_date, source)
);

-- The day lookup: newest rate on or before a day for a pair.
CREATE INDEX IF NOT EXISTS exchange_rate_pair_day
    ON exchange_rate (from_currency, to_currency, rate_date DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON exchange_rate TO attome_runtime;
GRANT SELECT ON exchange_rate TO attome_readonly;
