-- Z12-T7: the years whose Hijri holiday review reminder has gone out. The
-- yearly review job claims next year's row in the transaction that sends
-- the reminders, so every node and every restart sends it once a year.
CREATE TABLE IF NOT EXISTS calendar_review_notice (
    year integer PRIMARY KEY CHECK (year BETWEEN 2000 AND 2200),
    sent_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON calendar_review_notice TO attome_runtime;
GRANT SELECT ON calendar_review_notice TO attome_readonly;
