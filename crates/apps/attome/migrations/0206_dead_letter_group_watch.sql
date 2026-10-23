-- M5-T4: the dead-letter groups the hourly sweep has seen, so a group that
-- appears or grows raises an alert once, on whichever node runs the sweep.
-- One row per live group (`cause_group` = source:step:error kind, M5-T1);
-- a group that empties is deleted, so its return counts as new again.
CREATE TABLE IF NOT EXISTS dead_letter_group_watch (
    cause_group text PRIMARY KEY,
    source text NOT NULL,
    first_noticed_at timestamptz NOT NULL DEFAULT now(),
    last_count bigint NOT NULL,
    last_checked_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON dead_letter_group_watch TO attome_runtime;
GRANT SELECT ON dead_letter_group_watch TO attome_readonly;
