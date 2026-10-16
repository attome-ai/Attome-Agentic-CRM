-- M1-T5: loop prevention across flows and a per-flow cap on parallel runs.
--
-- `entity_change_event.chain_depth`: how many flow runs led to this write.
-- A flow's record write sets the transaction-local `attome.workflow_chain_depth`
-- to its own depth plus one; every other write leaves it unset, so 0.
-- `current_setting` is stable, so adding the column rewrites nothing.
ALTER TABLE entity_change_event
    ADD COLUMN IF NOT EXISTS chain_depth smallint NOT NULL
        DEFAULT COALESCE(NULLIF(current_setting('attome.workflow_chain_depth', true), '')::smallint, 0);

-- The depth of the event that started the instance.
ALTER TABLE workflow_instance
    ADD COLUMN IF NOT EXISTS chain_depth smallint NOT NULL DEFAULT 0;

-- `queued`: started past the flow's `settings.max_concurrent_runs`; the
-- minute sweep moves it to `running` when a slot frees.
ALTER TABLE workflow_instance DROP CONSTRAINT IF EXISTS core_workflow_instance_status_chk;
ALTER TABLE workflow_instance ADD CONSTRAINT core_workflow_instance_status_chk
    CHECK (status = ANY (ARRAY['queued'::text, 'running'::text, 'waiting'::text,
                               'completed'::text, 'failed'::text, 'cancelled'::text]));

CREATE INDEX IF NOT EXISTS workflow_instance_queued_idx
    ON workflow_instance (definition_version_id, started_at)
    WHERE status = 'queued';
