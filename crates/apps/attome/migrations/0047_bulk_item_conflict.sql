-- A16-T6: the version conflict a bulk or staged-import row met, so the
-- caller sees which rows were stale and what changed since, while the other
-- rows apply: {"current_version": n, "current_state": {...}} (the body a
-- single PATCH answers with), or NULL when the row did not conflict.
ALTER TABLE automation_bulk_operation_item ADD COLUMN IF NOT EXISTS conflict jsonb;
ALTER TABLE automation_staged_import_item ADD COLUMN IF NOT EXISTS conflict jsonb;
