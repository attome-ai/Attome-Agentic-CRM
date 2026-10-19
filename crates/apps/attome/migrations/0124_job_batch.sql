-- Z7-T4: chunked batch jobs (attome_jobs::batch). One row per batch: the
-- checkpoint of its last committed chunk, its progress and whether someone
-- asked it to stop. A chunk's writes commit with the row's new checkpoint,
-- so a retried job resumes after the last committed chunk.
CREATE TABLE IF NOT EXISTS job_batch (
    id                uuid        PRIMARY KEY,
    name              text        NOT NULL,
    status            text        NOT NULL DEFAULT 'running'
                                  CHECK (status IN ('running', 'finished', 'cancelled')),
    checkpoint        jsonb,
    done              bigint      NOT NULL DEFAULT 0,
    total             bigint,
    cancel_requested  boolean     NOT NULL DEFAULT false,
    started_by        uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz
);

CREATE INDEX IF NOT EXISTS job_batch_finished_at_idx ON job_batch (finished_at)
    WHERE finished_at IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON job_batch TO attome_runtime;
