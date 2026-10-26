-- AA10-T5: a mass operation larger than the inline threshold is undone in the
-- background, chunk by chunk from the last one; while it is, its status is
-- `undoing`.
SET LOCAL lock_timeout = '5s';

ALTER TABLE heavy_operation DROP CONSTRAINT IF EXISTS heavy_operation_status_check;
ALTER TABLE heavy_operation ADD CONSTRAINT heavy_operation_status_check CHECK (status IN (
    'estimating', 'queued', 'running', 'paused', 'cancelled', 'failed', 'done', 'undoing',
    'undone'));
