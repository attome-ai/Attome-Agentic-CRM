-- Z7-T3: a job kind may declare how many of its jobs run at once.
--
-- `apalis.job_concurrency_cap` holds one row per capped kind (the envelope's
-- `variant`); the binary writes it at worker start from what each kind
-- declares (`attome_jobs::install_concurrency_caps`). `apalis.get_jobs`
-- claims a capped kind's job only while fewer than `max_running` of that
-- kind are `Running`, and takes the cap rows' locks first so two workers
-- polling at the same instant cannot both see the last free slot. With no
-- rows the claim is exactly the one before (priority, then run time).

CREATE TABLE IF NOT EXISTS apalis.job_concurrency_cap (
    kind        text PRIMARY KEY,
    max_running integer NOT NULL CHECK (max_running > 0)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON apalis.job_concurrency_cap TO attome_runtime, attome_migrator;

CREATE OR REPLACE FUNCTION apalis.get_jobs(
    worker_id   TEXT,
    v_job_type  TEXT,
    v_job_count INTEGER DEFAULT 5 :: INTEGER
) RETURNS SETOF apalis.jobs AS $$
BEGIN
  -- Serialises claims while any cap exists; a no-op on an empty table.
  PERFORM 1 FROM apalis.job_concurrency_cap ORDER BY kind FOR UPDATE;
  RETURN QUERY
  WITH cap AS (
      SELECT c.kind,
             c.max_running - (
                 SELECT count(*) FROM apalis.jobs r
                 WHERE r.status = 'Running' AND r.job ->> 'variant' = c.kind
             ) AS free
      FROM apalis.job_concurrency_cap c
  ),
  candidates AS (
      SELECT j.id, j.job ->> 'variant' AS kind, j.priority, j.run_at
      FROM apalis.jobs j
      WHERE (j.status = 'Pending' OR (j.status = 'Failed' AND j.attempts < j.max_attempts))
        AND j.run_at < now()
        AND j.job_type = v_job_type
        AND NOT EXISTS (
            SELECT 1 FROM cap WHERE cap.kind = j.job ->> 'variant' AND cap.free <= 0
        )
      ORDER BY j.priority DESC, j.run_at ASC
      LIMIT v_job_count FOR UPDATE SKIP LOCKED
  ),
  ranked AS (
      SELECT c.id, c.priority, c.run_at, cap.free,
             row_number() OVER (PARTITION BY c.kind ORDER BY c.priority DESC, c.run_at ASC) AS n
      FROM candidates c
      LEFT JOIN cap ON cap.kind = c.kind
  )
  UPDATE apalis.jobs
  SET status  = 'Running',
      lock_by = worker_id,
      lock_at = now()
  WHERE id IN (SELECT ranked.id FROM ranked WHERE ranked.free IS NULL OR ranked.n <= ranked.free)
  RETURNING *;
END;
$$ LANGUAGE plpgsql VOLATILE;
