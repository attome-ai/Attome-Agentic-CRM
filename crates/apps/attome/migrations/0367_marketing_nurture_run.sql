-- E9-T3: the nurture drip. A nurture state remembers the run whose step
-- waits for it, the person's record entity and the consent purpose the
-- drip sends under, and when the run was told the state finished. A send
-- remembers the saved design it came from, so an open or click marks that
-- email seen. A module step's named-event wait is found by its run.
SET LOCAL lock_timeout = '5s';

ALTER TABLE marketing_nurture_state
    ADD COLUMN IF NOT EXISTS instance_id uuid,
    ADD COLUMN IF NOT EXISTS person_entity text,
    ADD COLUMN IF NOT EXISTS purpose text,
    ADD COLUMN IF NOT EXISTS done_signalled_at timestamptz;

CREATE INDEX IF NOT EXISTS marketing_nurture_state_finished_idx
    ON marketing_nurture_state (program_id)
    WHERE status <> 'active' AND instance_id IS NOT NULL AND done_signalled_at IS NULL;

ALTER TABLE email_campaign_send ADD COLUMN IF NOT EXISTS design_id uuid;

CREATE INDEX IF NOT EXISTS workflow_trigger_index_wait_instance_idx
    ON workflow_trigger_index (instance_id) WHERE role = 'wait';
