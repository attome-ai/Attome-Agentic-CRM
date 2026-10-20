-- E23-T1: profile events — what a known contact or an anonymous visitor
-- did, append-only, RANGE-partitioned by month on `at` like the other
-- event tables (the partition create-ahead job keeps the coming months
-- ready; the profile_event_retention job drops months older than
-- marketing.profile_event_retention_months).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS profile_event (
    id           uuid        NOT NULL DEFAULT uuidv7(),
    contact_id   uuid,
    anonymous_id text,
    kind         text        NOT NULL,
    at           timestamptz NOT NULL,
    properties   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, at),
    CHECK (contact_id IS NOT NULL OR anonymous_id IS NOT NULL)
) PARTITION BY RANGE (at);

CREATE INDEX IF NOT EXISTS profile_event_contact_idx ON profile_event (contact_id, at);
CREATE INDEX IF NOT EXISTS profile_event_anonymous_idx ON profile_event (anonymous_id, at);

-- The current and next month, so events land before the job first runs.
DO $$
DECLARE
    month_start timestamptz := date_trunc('month', now());
    i integer;
BEGIN
    FOR i IN 0..1 LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF profile_event FOR VALUES FROM (%L) TO (%L)',
            'profile_event_p' || to_char(month_start + make_interval(months => i), 'YYYY_MM'),
            month_start + make_interval(months => i),
            month_start + make_interval(months => i + 1)
        );
    END LOOP;
END
$$;

GRANT SELECT, INSERT ON profile_event TO attome_runtime;
GRANT SELECT ON profile_event TO attome_readonly;
