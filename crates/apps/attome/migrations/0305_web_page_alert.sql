-- E14-T9: one row per web session and watched page whose view started the
-- `web.page_viewed` flow trigger, so a known visitor starts it once per
-- session however many times they view the page. Holds no business data.
CREATE TABLE IF NOT EXISTS marketing_watched_alert (
    session_id uuid NOT NULL,
    watched_page_id uuid NOT NULL,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    alerted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, watched_page_id)
);

CREATE INDEX IF NOT EXISTS marketing_web_session_live_idx
    ON marketing_web_session (site_key, last_seen_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON marketing_watched_alert TO attome_runtime;
GRANT SELECT ON marketing_watched_alert TO attome_readonly;
