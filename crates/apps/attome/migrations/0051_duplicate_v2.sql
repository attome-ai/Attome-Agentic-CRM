-- A15-T1: duplicates, second version. A match rule may act on save (warn,
-- block, or allow with a reason) and scan on a schedule; the sweep keeps each
-- pair's per-field scores; every record's normalised match keys are stored so
-- a check on save is an index lookup; a merge is logged with everything it
-- needs to be undone, and the merged ids redirect to the survivor.
SET LOCAL lock_timeout = '5s';

ALTER TABLE match_rule ADD COLUMN IF NOT EXISTS on_save text NOT NULL DEFAULT 'off'
    CHECK (on_save IN ('off', 'warn', 'block', 'allow_with_reason'));
-- A cron string; NULL means no scheduled scan.
ALTER TABLE match_rule ADD COLUMN IF NOT EXISTS scan_schedule text;

-- Per field: the indicator and the comparator the sweep used.
ALTER TABLE duplicate_candidate ADD COLUMN IF NOT EXISTS field_scores jsonb;

CREATE TABLE IF NOT EXISTS merge_setting (
    entity_logicalname text PRIMARY KEY,
    merge_mode text NOT NULL DEFAULT 'soft_delete' CHECK (merge_mode IN ('soft_delete', 'keep_merged'))
);

CREATE TABLE IF NOT EXISTS match_key (
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    match_rule_id uuid NOT NULL REFERENCES match_rule (id),
    field text NOT NULL,
    key text NOT NULL,
    PRIMARY KEY (match_rule_id, field, record_id)
);
CREATE INDEX IF NOT EXISTS match_key_lookup_idx ON match_key (match_rule_id, field, key);

CREATE TABLE IF NOT EXISTS merge_log (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    survivor_id uuid NOT NULL,
    merged_ids uuid[] NOT NULL,
    survivor_before jsonb NOT NULL,
    merged_before jsonb NOT NULL,
    moved_rows jsonb NOT NULL,
    merge_mode text NOT NULL CHECK (merge_mode IN ('soft_delete', 'keep_merged')),
    merged_by uuid,
    merged_at timestamptz NOT NULL DEFAULT now(),
    undone_at timestamptz,
    undone_by uuid
);
CREATE INDEX IF NOT EXISTS merge_log_survivor_idx ON merge_log (entity_logicalname, survivor_id);

CREATE TABLE IF NOT EXISTS record_redirect (
    entity_logicalname text NOT NULL,
    from_id uuid NOT NULL,
    to_id uuid NOT NULL,
    merge_log_id uuid NOT NULL REFERENCES merge_log (id),
    PRIMARY KEY (entity_logicalname, from_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON merge_setting, match_key, merge_log, record_redirect
    TO attome_runtime;
GRANT SELECT ON merge_setting, match_key, merge_log, record_redirect TO attome_readonly;
