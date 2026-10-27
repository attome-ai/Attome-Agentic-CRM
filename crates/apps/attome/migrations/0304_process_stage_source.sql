-- O8-T1: stage moves (M7, `stage_move`) are a process-mining source too.
ALTER TABLE process_event DROP CONSTRAINT IF EXISTS process_event_source_kind_chk;
ALTER TABLE process_event ADD CONSTRAINT process_event_source_kind_chk
    CHECK (source_kind IN ('workflow_node_run', 'audit_detail', 'stage_move'));
