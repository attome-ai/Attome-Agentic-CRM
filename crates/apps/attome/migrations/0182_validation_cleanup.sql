-- A3-T5: the clean-up queue a newly published or tightened check leaves:
-- every stored record that fails it, with the rule and its message, and the
-- record's owner, so each owner sees their own records to fix. The publish
-- job rewrites a rule's rows from a full scan; fixing a record and saving it
-- does not remove its row until the next scan of that rule.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS validation_cleanup (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    rule_ref uuid NOT NULL,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    message text NOT NULL DEFAULT '',
    owner_ref uuid,
    found_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (rule_ref, record_id)
);

CREATE INDEX IF NOT EXISTS validation_cleanup_owner_idx
    ON validation_cleanup (owner_ref, found_at DESC);

GRANT SELECT, INSERT, DELETE ON validation_cleanup TO attome_runtime;
GRANT SELECT ON validation_cleanup TO attome_readonly;
