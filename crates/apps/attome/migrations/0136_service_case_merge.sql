-- G7-T1: which merges of service tickets had their case steps applied
-- (messages, notes, documents and links moved to the survivor, the merged
-- number kept as an alias, the merged case closed as merged), and what moved.
CREATE TABLE IF NOT EXISTS service_case_merge (
    merge_log_id uuid PRIMARY KEY,
    survivor_id uuid NOT NULL,
    merged_id uuid NOT NULL,
    moved jsonb NOT NULL DEFAULT '{}'::jsonb,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON service_case_merge TO attome_runtime;
GRANT SELECT ON service_case_merge TO attome_readonly;
