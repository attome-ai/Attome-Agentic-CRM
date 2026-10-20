-- E6-T10: the deliverability alerts raised, one per sending domain (or
-- target), kind and day, so a re-run of the daily evaluation notifies no one
-- twice.
CREATE TABLE IF NOT EXISTS marketing_deliverability_alert (
    day       date        NOT NULL,
    subject   text        NOT NULL,
    kind      text        NOT NULL,
    detail    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    raised_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (day, subject, kind)
);

GRANT SELECT, INSERT ON marketing_deliverability_alert TO attome_runtime;
GRANT SELECT ON marketing_deliverability_alert TO attome_readonly;
