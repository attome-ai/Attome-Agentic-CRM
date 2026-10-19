-- Z7-T2: a schedule ledger row can be a cron expression, a one-off, a Hijri
-- day of the month or every working day, besides a fixed interval
-- (attome_jobs::schedule::Schedule). `schedule` describes it; a changed
-- description restarts the row at its new first slot. NULL for the rows
-- `schedule::tick` keeps on a fixed interval.
ALTER TABLE job_schedule ADD COLUMN IF NOT EXISTS schedule text;
