-- R1-T1: restriction of processing and rectification requests, and
-- per-law response deadlines on every data-subject request.
ALTER TABLE dsr_request DROP CONSTRAINT IF EXISTS dsr_request_request_type_check;
ALTER TABLE dsr_request ADD CONSTRAINT dsr_request_request_type_check
    CHECK (request_type = ANY (ARRAY['access', 'erasure', 'portability', 'objection',
                                     'restriction', 'rectification']));
ALTER TABLE dsr_request ADD COLUMN IF NOT EXISTS due_at timestamp with time zone;
ALTER TABLE dsr_request ADD COLUMN IF NOT EXISTS law text;
ALTER TABLE dsr_request ADD COLUMN IF NOT EXISTS resolution text;

-- One row per record a restriction request covers. While `lifted_at` is
-- null the record is left out of AI, bulk export and marketing email
-- (`attome_core::processing_restriction`).
CREATE TABLE IF NOT EXISTS processing_restriction (
    id uuid DEFAULT uuidv7() NOT NULL PRIMARY KEY,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    dsr_request_id uuid NOT NULL REFERENCES dsr_request (id),
    placed_by uuid NOT NULL,
    placed_at timestamp with time zone DEFAULT now() NOT NULL,
    lifted_by uuid,
    lifted_at timestamp with time zone
);
CREATE INDEX IF NOT EXISTS idx_processing_restriction_live
    ON processing_restriction (record_id, entity_logicalname) WHERE lifted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_processing_restriction_request
    ON processing_restriction (dsr_request_id);
