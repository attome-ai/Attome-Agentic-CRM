-- M3-T1: one node-run row per node and loop round, with the input the node
-- ran with and the output it produced. A pair over 64 KiB lives in object
-- storage and the row keeps its key (`payload_ref`). Rows written before
-- this are round 0 and carry no payload.
ALTER TABLE workflow_node_run ADD COLUMN IF NOT EXISTS round integer NOT NULL DEFAULT 0;
ALTER TABLE workflow_node_run ADD COLUMN IF NOT EXISTS input jsonb;
ALTER TABLE workflow_node_run ADD COLUMN IF NOT EXISTS output jsonb;
ALTER TABLE workflow_node_run ADD COLUMN IF NOT EXISTS payload_ref text;

ALTER TABLE workflow_node_run DROP CONSTRAINT IF EXISTS core_workflow_node_run_instance_node_unique;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'workflow_node_run_instance_node_round_unique') THEN
        ALTER TABLE workflow_node_run
            ADD CONSTRAINT workflow_node_run_instance_node_round_unique
            UNIQUE (instance_id, node_id, round);
    END IF;
END $$;
