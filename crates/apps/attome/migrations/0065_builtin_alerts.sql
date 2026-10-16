-- AB10-T1: built-in alerting on the metrics store (no Prometheus needed).
-- One row per rule holds its state; every change to firing or back is kept
-- as an event (the notifier, AB10-T2, sends from these). One lease row lets
-- one node evaluate each minute.

CREATE TABLE IF NOT EXISTS ops_alert (
    name text NOT NULL PRIMARY KEY,
    state text NOT NULL DEFAULT 'inactive',
    severity text NOT NULL,
    summary text NOT NULL,
    value double precision,
    pending_since timestamptz,
    firing_since timestamptz,
    resolved_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ops_alert_state_chk CHECK (state IN ('inactive', 'pending', 'firing'))
);

CREATE TABLE IF NOT EXISTS ops_alert_event (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    name text NOT NULL,
    event text NOT NULL,
    severity text NOT NULL,
    summary text NOT NULL,
    value double precision,
    at timestamptz NOT NULL DEFAULT now(),
    notified_at timestamptz,
    CONSTRAINT ops_alert_event_chk CHECK (event IN ('firing', 'resolved'))
);
CREATE INDEX IF NOT EXISTS ix_ops_alert_event_at ON ops_alert_event (at DESC);

CREATE TABLE IF NOT EXISTS ops_alert_lease (
    id smallint NOT NULL PRIMARY KEY DEFAULT 1,
    evaluated_at timestamptz NOT NULL DEFAULT 'epoch',
    CONSTRAINT ops_alert_lease_one_row CHECK (id = 1)
);
INSERT INTO ops_alert_lease (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON ops_alert, ops_alert_event, ops_alert_lease TO attome_runtime;
GRANT SELECT ON ops_alert, ops_alert_event TO attome_readonly;
