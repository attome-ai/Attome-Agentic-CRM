-- AB2-T6: every database failover and switchover the cluster poll sees, once
-- per leader and timeline. Only written when config.ops.patroni_api_urls
-- names a Patroni cluster.
CREATE TABLE IF NOT EXISTS ops_failover_event (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('failover', 'switchover', 'redis_failover')),
    old_leader text,
    new_leader text NOT NULL,
    timeline bigint,
    started_at timestamptz NOT NULL,
    ended_at timestamptz,
    duration_ms bigint,
    writes_lost bigint,
    cause text,
    initiated_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ops_failover_event_uq
    ON ops_failover_event (kind, new_leader, timeline) NULLS NOT DISTINCT;
CREATE INDEX IF NOT EXISTS ops_failover_event_started_idx
    ON ops_failover_event (started_at DESC);

GRANT SELECT, INSERT, UPDATE ON ops_failover_event TO attome_runtime;
GRANT SELECT ON ops_failover_event TO attome_readonly;
