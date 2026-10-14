-- U4-T1: the built-in metrics store. One row per series per minute, taken
-- from the process's Prometheus registry; partitioned by day (the server
-- creates each day's partition and drops those older than 30 days).
CREATE TABLE IF NOT EXISTS ops_metric_sample (
    ts timestamptz NOT NULL,
    name text NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    value double precision NOT NULL
) PARTITION BY RANGE (ts);
CREATE INDEX IF NOT EXISTS ops_metric_sample_name_ts ON ops_metric_sample (name, ts);

GRANT SELECT, INSERT ON ops_metric_sample TO attome_runtime;
GRANT SELECT ON ops_metric_sample TO attome_readonly;
