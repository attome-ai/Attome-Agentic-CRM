-- A18-T4: when a person was last reported for deleting many records, so the
-- sweep reports each burst once an hour at most.
CREATE TABLE IF NOT EXISTS bin_delete_alert (
    user_ref uuid PRIMARY KEY,
    alerted_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE ON bin_delete_alert TO attome_runtime;
GRANT SELECT ON bin_delete_alert TO attome_readonly;
