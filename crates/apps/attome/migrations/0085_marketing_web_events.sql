-- E14-T2: website tracking. Raw events, partitioned by month (the partition
-- create-ahead job keeps the coming months ready), the sessions they form
-- and a daily rollup per page and campaign.
CREATE TABLE IF NOT EXISTS marketing_web_event (
    id uuid NOT NULL,
    site_key text NOT NULL,
    visitor_id uuid NOT NULL,
    session_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    kind text NOT NULL CHECK (kind IN ('page_view', 'custom')),
    event_type text,
    url text,
    title text,
    referrer text,
    time_on_page_ms integer,
    device text,
    browser_lang text,
    country char(2),
    ip_prefix text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- The current and next month, so events land before the job first runs.
DO $$
DECLARE
    month_start timestamptz := date_trunc('month', now());
    i integer;
BEGIN
    FOR i IN 0..1 LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF marketing_web_event FOR VALUES FROM (%L) TO (%L)',
            'marketing_web_event_p' || to_char(month_start + make_interval(months => i), 'YYYY_MM'),
            month_start + make_interval(months => i),
            month_start + make_interval(months => i + 1)
        );
    END LOOP;
END
$$;

CREATE TABLE IF NOT EXISTS marketing_web_session (
    id uuid PRIMARY KEY,
    site_key text NOT NULL,
    visitor_id uuid NOT NULL,
    started_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    landing_url text,
    referrer text,
    utm_source text,
    utm_medium text,
    utm_campaign text,
    utm_term text,
    utm_content text,
    click_ids jsonb NOT NULL DEFAULT '{}'::jsonb,
    page_count integer NOT NULL DEFAULT 0,
    contact_ref uuid,
    lead_ref uuid,
    is_bot boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS marketing_web_session_visitor_idx ON marketing_web_session (visitor_id);
CREATE INDEX IF NOT EXISTS marketing_web_session_contact_idx ON marketing_web_session (contact_ref);
CREATE INDEX IF NOT EXISTS marketing_web_session_site_idx ON marketing_web_session (site_key, started_at);

CREATE TABLE IF NOT EXISTS marketing_web_daily (
    site_key text NOT NULL,
    day date NOT NULL,
    url text NOT NULL,
    utm_campaign text NOT NULL DEFAULT '',
    views integer NOT NULL,
    sessions integer NOT NULL,
    PRIMARY KEY (site_key, day, url, utm_campaign)
);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON marketing_web_event, marketing_web_session, marketing_web_daily TO attome_runtime;
GRANT SELECT ON marketing_web_event, marketing_web_session, marketing_web_daily TO attome_readonly;
