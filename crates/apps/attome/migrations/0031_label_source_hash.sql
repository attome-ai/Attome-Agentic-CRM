-- A20-T1: a translation remembers the source text it translated (as a hash),
-- so a later change to the source shows the translation as stale, and
-- whether a person has reviewed it (an agent's draft is not yet reviewed).
ALTER TABLE metadata_label ADD COLUMN IF NOT EXISTS source_hash text;
ALTER TABLE metadata_label ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'reviewed';
ALTER TABLE metadata_label DROP CONSTRAINT IF EXISTS metadata_label_status_check;
ALTER TABLE metadata_label ADD CONSTRAINT metadata_label_status_check
    CHECK (status IN ('draft', 'reviewed'));
