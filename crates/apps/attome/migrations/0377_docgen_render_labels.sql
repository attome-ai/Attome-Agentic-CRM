-- B16-T12: a label render: the records drawn one after another in one PDF.
-- NULL for an ordinary one-record render.
SET LOCAL lock_timeout = '5s';

ALTER TABLE docgen_render ADD COLUMN IF NOT EXISTS label_record_ids uuid[];
