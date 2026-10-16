-- M3-T3: a run can be paused (no step runs until it is resumed).
ALTER TABLE workflow_instance DROP CONSTRAINT IF EXISTS core_workflow_instance_status_chk;
ALTER TABLE workflow_instance ADD CONSTRAINT core_workflow_instance_status_chk
    CHECK (status = ANY (ARRAY['queued'::text, 'running'::text, 'waiting'::text, 'paused'::text,
                               'completed'::text, 'failed'::text, 'cancelled'::text]));
