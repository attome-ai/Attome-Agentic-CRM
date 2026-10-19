-- Z7-T5: chains and fan-out over registered jobs (attome_jobs::chain).
-- `job_chain_step` records each job whose follow-up was enqueued, so a
-- retried job never enqueues it twice; `job_group` counts a fan-out's
-- members still to finish and holds the job to run when none is left.
CREATE TABLE IF NOT EXISTS job_chain_step (
    step        uuid        PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS job_group (
    id           uuid        PRIMARY KEY,
    remaining    integer     NOT NULL CHECK (remaining >= 0),
    finally      jsonb       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);

CREATE INDEX IF NOT EXISTS job_chain_step_created_at_idx ON job_chain_step (created_at);

GRANT SELECT, INSERT, DELETE ON job_chain_step TO attome_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON job_group TO attome_runtime;
