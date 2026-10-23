-- L2-T7: one data quality alert per entity per day, to its stewards.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS quality_alert_sent (
    entity text NOT NULL,
    day date NOT NULL,
    sent_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity, day)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON quality_alert_sent TO attome_runtime;
GRANT SELECT ON quality_alert_sent TO attome_readonly;
