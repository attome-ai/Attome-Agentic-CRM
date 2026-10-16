-- F3-T7: metered usage for subscriptions. Raw usage records are insert-only
-- and partitioned by month on when the usage happened; a repeated
-- idempotency key for the same subscription line is ignored. Daily totals
-- per line and metric feed rating (F3-T8).
CREATE TABLE IF NOT EXISTS billing_usage_record (
    id uuid NOT NULL,
    subscription_line_id uuid NOT NULL,
    metric text NOT NULL,
    quantity numeric NOT NULL,
    occurred_at timestamptz NOT NULL,
    idempotency_key text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE UNIQUE INDEX IF NOT EXISTS billing_usage_record_key_idx
    ON billing_usage_record (subscription_line_id, idempotency_key, occurred_at);

-- Last, this and next month, so late and current usage lands before the
-- partition job first runs.
DO $$
DECLARE
    month_start timestamptz := date_trunc('month', now());
    i integer;
BEGIN
    FOR i IN -1..1 LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF billing_usage_record FOR VALUES FROM (%L) TO (%L)',
            'billing_usage_record_p' || to_char(month_start + make_interval(months => i), 'YYYY_MM'),
            month_start + make_interval(months => i),
            month_start + make_interval(months => i + 1)
        );
    END LOOP;
END
$$;

CREATE TABLE IF NOT EXISTS billing_usage_daily (
    subscription_line_id uuid NOT NULL,
    metric text NOT NULL,
    day date NOT NULL,
    quantity numeric NOT NULL DEFAULT 0,
    PRIMARY KEY (subscription_line_id, metric, day)
);

-- Insert-only: the application may add usage but never rewrite it.
GRANT SELECT, INSERT ON billing_usage_record TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON billing_usage_daily TO attome_runtime;
GRANT SELECT ON billing_usage_record, billing_usage_daily TO attome_readonly;
