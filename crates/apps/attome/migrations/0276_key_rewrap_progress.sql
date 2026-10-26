-- Q18-T4: how far the rewrap job got through each registered encrypted
-- column. Written after every batch, so a run stopped part-way resumes after
-- `last_key`; `finished_at` is set when the column was read to the end, and a
-- new run starts it again from the top.
CREATE TABLE IF NOT EXISTS key_rewrap_progress (
    table_name text NOT NULL,
    column_name text NOT NULL,
    domain text NOT NULL,
    last_key text,
    scanned bigint NOT NULL DEFAULT 0,
    rewrapped bigint NOT NULL DEFAULT 0,
    failed bigint NOT NULL DEFAULT 0,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    PRIMARY KEY (table_name, column_name)
);

GRANT SELECT, INSERT, UPDATE ON key_rewrap_progress TO attome_runtime;
