-- Z1-T7: every node start, with a fingerprint of its configuration and the
-- masked view it was computed from (no secret values; see
-- attome_config::fingerprint).
CREATE TABLE IF NOT EXISTS config_start (
    id           uuid        PRIMARY KEY,
    node_name    text        NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    app_version  text        NOT NULL,
    fingerprint  text        NOT NULL,
    view         jsonb       NOT NULL
);

CREATE INDEX IF NOT EXISTS config_start_started_at_idx ON config_start (started_at DESC);

GRANT SELECT, INSERT ON config_start TO attome_runtime;
GRANT SELECT ON config_start TO attome_readonly;
