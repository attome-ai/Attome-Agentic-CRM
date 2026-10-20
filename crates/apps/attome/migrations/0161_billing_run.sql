-- F3-T8: a subscription billing run. Its charges due by `as_of` are grouped
-- by account, billing period and currency, and each group becomes one F4
-- invoice request; the run keeps its progress here so a restarted job
-- carries on where it stopped.
CREATE TABLE IF NOT EXISTS billing_run (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    as_of       date        NOT NULL,
    status      text        NOT NULL DEFAULT 'pending'
                            CHECK (status = ANY (ARRAY['pending', 'running', 'done', 'failed'])),
    groups_done integer     NOT NULL DEFAULT 0,
    requests    integer     NOT NULL DEFAULT 0,
    error       text,
    created_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);

CREATE INDEX IF NOT EXISTS billing_run_status_idx ON billing_run (status, created_at);

GRANT SELECT, INSERT, UPDATE ON billing_run TO attome_runtime;
GRANT SELECT ON billing_run TO attome_readonly;
