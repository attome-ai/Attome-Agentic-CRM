-- AA9-T5: how often each limit was hit per day, by whom. Every node adds
-- its counts every five minutes; principal_id is the nil uuid for a hit
-- with no principal (before sign-in, or past the tally's size).
CREATE TABLE IF NOT EXISTS limit_usage_daily (
    day            date   NOT NULL,
    limit_key      text   NOT NULL,
    principal_kind text   NOT NULL,
    principal_id   uuid   NOT NULL,
    hits           bigint NOT NULL,
    peak           bigint NOT NULL,
    PRIMARY KEY (day, limit_key, principal_kind, principal_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON limit_usage_daily TO attome_runtime;
GRANT SELECT ON limit_usage_daily TO attome_readonly;
