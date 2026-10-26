-- G17-T10: schedule adherence. One row per person per minute seen (kept 35
-- days), and the nightly per-day roll-up of adherence and conformance.
CREATE TABLE IF NOT EXISTS wfm_adherence_minute (
    user_id uuid NOT NULL,
    minute timestamptz NOT NULL,
    scheduled text NOT NULL,
    actual text NOT NULL,
    in_adherence boolean NOT NULL,
    PRIMARY KEY (user_id, minute)
);

CREATE INDEX IF NOT EXISTS wfm_adherence_minute_by_minute ON wfm_adherence_minute (minute);

CREATE TABLE IF NOT EXISTS wfm_adherence_day (
    user_id uuid NOT NULL,
    day date NOT NULL,
    adherence_pct numeric(5, 2),
    conformance_pct numeric(6, 2),
    minutes bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);

GRANT SELECT, INSERT, DELETE ON wfm_adherence_minute TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON wfm_adherence_day TO attome_runtime;
GRANT SELECT ON wfm_adherence_minute, wfm_adherence_day TO attome_readonly;
