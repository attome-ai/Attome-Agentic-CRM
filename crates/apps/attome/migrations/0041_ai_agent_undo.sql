-- AH1-T1: the undo ledger. One row per request to undo what an agent did
-- (one session, or one agent since a time), and one row per record that
-- request touches, with what happened to it: restored, skipped because a
-- person changed it since, not undoable, or failed.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS ai_undo_run (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    scope text NOT NULL CHECK (scope IN ('session', 'agent_since')),
    agent_session_ids uuid[] NOT NULL,
    agent_ref uuid,
    since timestamptz,
    requested_by uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('planned', 'running', 'done', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    summary jsonb,
    CHECK ((scope = 'agent_since') = (agent_ref IS NOT NULL AND since IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS ai_undo_item (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    undo_run_id uuid NOT NULL REFERENCES ai_undo_run(id) ON DELETE CASCADE,
    entity text NOT NULL,
    record_id uuid NOT NULL,
    audit_header_id uuid,
    operation text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('pending', 'restored', 'skipped_changed', 'not_undoable', 'failed')),
    changed_attributes text[] NOT NULL DEFAULT '{}',
    detail text,
    seq integer NOT NULL,
    UNIQUE (undo_run_id, seq)
);

CREATE INDEX IF NOT EXISTS ai_undo_run_requested_idx ON ai_undo_run (requested_by, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON ai_undo_run TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON ai_undo_item TO attome_runtime;
GRANT SELECT ON ai_undo_run, ai_undo_item TO attome_readonly;
