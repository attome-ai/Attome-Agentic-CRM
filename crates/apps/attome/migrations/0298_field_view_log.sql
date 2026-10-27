-- Q15-T5: full reads of Financial and Health values: who saw which field of
-- which record, and when. Written in batches by each node's view-log buffer
-- (attome_security::view_log), never on the request path except when the
-- buffer is full. Insert-only for the runtime role: the log is evidence.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS field_view_log (
    id uuid DEFAULT uuidv7() PRIMARY KEY,
    user_ref uuid NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    attribute_logicalname text NOT NULL,
    viewed_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS field_view_log_record
    ON field_view_log (entity_logicalname, record_id, viewed_at);
CREATE INDEX IF NOT EXISTS field_view_log_user
    ON field_view_log (user_ref, viewed_at);

GRANT SELECT, INSERT ON field_view_log TO attome_runtime;
