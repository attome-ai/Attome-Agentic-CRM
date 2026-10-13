-- The durable job queue (attome-jobs): apalis-sql 0.7.4's Postgres schema,
-- squashed to its final upstream state (github.com/geofmureithi/apalis,
-- packages/apalis-sql/migrations/postgres, tag v0.7.4), plus Attome's own
-- additions:
--
-- - `dedup_key` and `apalis.push_job_dedup`: enqueue-time deduplication. A
--   key blocks a second enqueue while a job with it is Pending, Running or
--   Failed (still retrying), so one logical operation never runs twice at once.
-- - `apalis_jobs_poll_idx`: the polling query's exact shape, so a worker tick
--   reads LIMIT rows and stops instead of sorting every runnable job.
-- - `job_schedule`: one row per periodic job; a slot is claimed with one row
--   compare-and-swap, so N workers run each slot once.
--
-- An apalis upgrade that changes this schema is a new migration; this file is
-- never edited once released.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS apalis;

CREATE TABLE IF NOT EXISTS apalis.workers (
    id           TEXT NOT NULL,
    worker_type  TEXT NOT NULL,
    storage_name TEXT NOT NULL,
    layers       TEXT NOT NULL DEFAULT '',
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS apalis_workers_id_idx ON apalis.workers (id);
CREATE UNIQUE INDEX IF NOT EXISTS apalis_unique_worker_id ON apalis.workers (id);
CREATE INDEX IF NOT EXISTS apalis_workers_type_idx ON apalis.workers (worker_type);
CREATE INDEX IF NOT EXISTS apalis_workers_last_seen_idx ON apalis.workers (last_seen);

CREATE TABLE IF NOT EXISTS apalis.jobs (
    job          JSONB NOT NULL,
    id           TEXT NOT NULL,
    job_type     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'Pending',
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 25,
    run_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error   TEXT,
    lock_at      TIMESTAMPTZ,
    lock_by      TEXT,
    done_at      TIMESTAMPTZ,
    priority     INTEGER DEFAULT 0,
    dedup_key    TEXT,
    CONSTRAINT fk_worker_lock_by FOREIGN KEY (lock_by) REFERENCES apalis.workers (id)
);

CREATE INDEX IF NOT EXISTS apalis_jobs_id_idx ON apalis.jobs (id);
CREATE INDEX IF NOT EXISTS apalis_jobs_status_idx ON apalis.jobs (status);
CREATE UNIQUE INDEX IF NOT EXISTS apalis_unique_job_id ON apalis.jobs (id);
CREATE INDEX IF NOT EXISTS apalis_jobs_lock_by_idx ON apalis.jobs (lock_by);
CREATE INDEX IF NOT EXISTS apalis_jobs_job_type_idx ON apalis.jobs (job_type);

-- Crockford base32 ULID generator — used by apalis.push_job() for job ids.
CREATE OR REPLACE FUNCTION generate_ulid()
RETURNS TEXT
AS $$
DECLARE
  encoding   BYTEA = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  timestamp  BYTEA = E'\\000\\000\\000\\000\\000\\000';
  output     TEXT = '';
  unix_time  BIGINT;
  ulid       BYTEA;
BEGIN
  unix_time = (EXTRACT(EPOCH FROM CLOCK_TIMESTAMP()) * 1000)::BIGINT;
  timestamp = SET_BYTE(timestamp, 0, (unix_time >> 40)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 1, (unix_time >> 32)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 2, (unix_time >> 24)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 3, (unix_time >> 16)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 4, (unix_time >> 8)::BIT(8)::INTEGER);
  timestamp = SET_BYTE(timestamp, 5, unix_time::BIT(8)::INTEGER);

  ulid = timestamp || gen_random_bytes(10);

  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 0) & 224) >> 5));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 0) & 31)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 1) & 248) >> 3));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 1) & 7) << 2) | ((GET_BYTE(ulid, 2) & 192) >> 6)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 2) & 62) >> 1));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 2) & 1) << 4) | ((GET_BYTE(ulid, 3) & 240) >> 4)));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 3) & 15) << 1) | ((GET_BYTE(ulid, 4) & 128) >> 7)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 4) & 124) >> 2));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 4) & 3) << 3) | ((GET_BYTE(ulid, 5) & 224) >> 5)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 5) & 31)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 6) & 248) >> 3));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 6) & 7) << 2) | ((GET_BYTE(ulid, 7) & 192) >> 6)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 7) & 62) >> 1));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 7) & 1) << 4) | ((GET_BYTE(ulid, 8) & 240) >> 4)));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 8) & 15) << 1) | ((GET_BYTE(ulid, 9) & 128) >> 7)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 9) & 124) >> 2));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 9) & 3) << 3) | ((GET_BYTE(ulid, 10) & 224) >> 5)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 10) & 31)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 11) & 248) >> 3));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 11) & 7) << 2) | ((GET_BYTE(ulid, 12) & 192) >> 6)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 12) & 62) >> 1));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 12) & 1) << 4) | ((GET_BYTE(ulid, 13) & 240) >> 4)));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 13) & 15) << 1) | ((GET_BYTE(ulid, 14) & 128) >> 7)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 14) & 124) >> 2));
  output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 14) & 3) << 3) | ((GET_BYTE(ulid, 15) & 224) >> 5)));
  output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 15) & 31)));

  RETURN output;
END
$$ LANGUAGE plpgsql VOLATILE;

CREATE OR REPLACE FUNCTION apalis.get_jobs(
    worker_id   TEXT,
    v_job_type  TEXT,
    v_job_count INTEGER DEFAULT 5 :: INTEGER
) RETURNS SETOF apalis.jobs AS $$
BEGIN
  RETURN QUERY
  UPDATE apalis.jobs
  SET status  = 'Running',
      lock_by = worker_id,
      lock_at = now()
  WHERE id IN (
      SELECT id
      FROM apalis.jobs
      WHERE (status = 'Pending' OR (status = 'Failed' AND attempts < max_attempts))
        AND run_at < now()
        AND job_type = v_job_type
      ORDER BY priority DESC, run_at ASC
      LIMIT v_job_count FOR UPDATE SKIP LOCKED
  )
  RETURNING *;
END;
$$ LANGUAGE plpgsql VOLATILE;

CREATE OR REPLACE FUNCTION apalis.push_job(
    job_type     TEXT,
    job          JSON DEFAULT NULL :: JSON,
    status       TEXT DEFAULT 'Pending' :: TEXT,
    run_at       TIMESTAMPTZ DEFAULT NOW() :: TIMESTAMPTZ,
    max_attempts INTEGER DEFAULT 25 :: INTEGER,
    priority     INTEGER DEFAULT 0 :: INTEGER
) RETURNS apalis.jobs AS $$
DECLARE
  v_job_row apalis.jobs;
  v_job_id  TEXT;
BEGIN
  IF job_type IS NOT NULL AND length(job_type) > 512 THEN
    RAISE EXCEPTION 'Job_type is too long (max length: 512).' USING errcode = 'APAJT';
  END IF;

  IF max_attempts < 1 THEN
    RAISE EXCEPTION 'Job maximum attempts must be at least 1.' USING errcode = 'APAMA';
  END IF;

  SELECT generate_ulid() INTO v_job_id;

  INSERT INTO apalis.jobs
  VALUES (job, v_job_id, job_type, status, 0, max_attempts, run_at, NULL, NULL, NULL, NULL, priority)
  RETURNING * INTO v_job_row;

  RETURN v_job_row;
END;
$$ LANGUAGE plpgsql VOLATILE;

CREATE OR REPLACE FUNCTION apalis.notify_new_jobs() RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('apalis::job', 'insert');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER notify_workers
  AFTER INSERT ON apalis.jobs
  FOR EACH STATEMENT EXECUTE PROCEDURE apalis.notify_new_jobs();

-- Enqueue-time deduplication. The ON CONFLICT predicate must match the partial
-- index's predicate exactly, or PostgreSQL cannot infer the arbiter (42P10).
CREATE UNIQUE INDEX IF NOT EXISTS apalis_jobs_dedup_key_idx
    ON apalis.jobs (job_type, dedup_key)
    WHERE status IN ('Pending', 'Running', 'Failed') AND dedup_key IS NOT NULL;

CREATE OR REPLACE FUNCTION apalis.push_job_dedup(
    p_job_type     TEXT,
    p_job          JSON,
    p_dedup_key    TEXT,
    p_status       TEXT DEFAULT 'Pending' :: TEXT,
    p_run_at       TIMESTAMPTZ DEFAULT NOW() :: TIMESTAMPTZ,
    p_max_attempts INTEGER DEFAULT 25 :: INTEGER,
    p_priority     INTEGER DEFAULT 0 :: INTEGER
) RETURNS SETOF apalis.jobs AS $$
BEGIN
  IF p_job_type IS NOT NULL AND length(p_job_type) > 512 THEN
    RAISE EXCEPTION 'Job_type is too long (max length: 512).' USING errcode = 'APAJT';
  END IF;

  IF p_max_attempts < 1 THEN
    RAISE EXCEPTION 'Job maximum attempts must be at least 1.' USING errcode = 'APAMA';
  END IF;

  RETURN QUERY
  INSERT INTO apalis.jobs (job, id, job_type, status, attempts, max_attempts,
                            run_at, dedup_key, priority)
  VALUES (p_job, generate_ulid(), p_job_type, p_status, 0, p_max_attempts,
          p_run_at, p_dedup_key, p_priority)
  ON CONFLICT (job_type, dedup_key)
    WHERE status IN ('Pending', 'Running', 'Failed') AND dedup_key IS NOT NULL
    DO NOTHING
  RETURNING *;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- `apalis.get_jobs` filters on job_type and the two live statuses and orders by
-- (priority DESC, run_at); this index serves that exactly, flat in queue depth.
CREATE INDEX IF NOT EXISTS apalis_jobs_poll_idx
    ON apalis.jobs (job_type, priority DESC, run_at)
    WHERE status = 'Pending' OR status = 'Failed';

-- The schedule ledger. `attome_jobs::schedule::tick` claims a slot with
-- `UPDATE ... WHERE next_due_at <= now()`; a loser enqueues nothing. The
-- schedule name is the natural key and a row is never deleted, only advanced.
-- `last_succeeded_at` is stamped by the worker after a successful run.
CREATE TABLE IF NOT EXISTS job_schedule (
    name              TEXT        PRIMARY KEY,
    interval_secs     INTEGER     NOT NULL,
    next_due_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_enqueued_at  TIMESTAMPTZ,
    last_succeeded_at TIMESTAMPTZ,
    row_version       BIGINT      NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT job_schedule_interval_positive CHECK (interval_secs > 0)
);
