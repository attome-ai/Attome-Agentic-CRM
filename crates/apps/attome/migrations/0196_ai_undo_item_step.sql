-- AH1-T4: each undo item keeps the step it was planned as, so a run that
-- stopped half way resumes from the stored plan (the record's row_version
-- and the values to set back), never from a fresh comparison.
SET LOCAL lock_timeout = '5s';

ALTER TABLE ai_undo_item ADD COLUMN IF NOT EXISTS step jsonb;
