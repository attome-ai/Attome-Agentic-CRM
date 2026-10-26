-- D17-T1: sequences are workflows of kind 'sequence'. The kind check gains
-- the new kind, and one infrastructure table holds who is enrolled: one row
-- per contact and enrolment, with the exits that apply (copied from the
-- published version's `settings.sequence.exit_on` when enrolled).
SET LOCAL lock_timeout = '5s';

-- The new check is added NOT VALID and validated separately so validation
-- takes only a SHARE UPDATE EXCLUSIVE lock.
ALTER TABLE workflow_definition DROP CONSTRAINT IF EXISTS ck_workflow_definition_kind;
ALTER TABLE workflow_definition
    ADD CONSTRAINT ck_workflow_definition_kind
    CHECK (kind = ANY (ARRAY['flow', 'journey', 'nurture', 'sequence'])) NOT VALID;
ALTER TABLE workflow_definition VALIDATE CONSTRAINT ck_workflow_definition_kind;

CREATE TABLE IF NOT EXISTS workflow_sequence_enrolment (
    id                    uuid        PRIMARY KEY DEFAULT uuidv7(),
    definition_id         uuid        NOT NULL REFERENCES workflow_definition (id),
    definition_version_id uuid        NOT NULL,
    contact_id            uuid        NOT NULL,
    instance_id           uuid        REFERENCES workflow_instance (id),
    status                text        NOT NULL
                          CHECK (status = ANY (ARRAY['active', 'completed', 'exited', 'stopped'])),
    exit_on               text[]      NOT NULL DEFAULT ARRAY['reply', 'meeting', 'stage_change'],
    exit_reason           text,
    enrolled_by           uuid,
    enrolled_at           timestamptz NOT NULL DEFAULT now(),
    ended_at              timestamptz
);

-- One active enrolment per contact per sequence.
CREATE UNIQUE INDEX IF NOT EXISTS workflow_sequence_enrolment_active_uq
    ON workflow_sequence_enrolment (definition_id, contact_id) WHERE status = 'active';
-- The exit sweep finds a contact's active enrolments.
CREATE INDEX IF NOT EXISTS workflow_sequence_enrolment_contact_idx
    ON workflow_sequence_enrolment (contact_id) WHERE status = 'active';
-- The guard reads an instance's enrolment before every step.
CREATE INDEX IF NOT EXISTS workflow_sequence_enrolment_instance_idx
    ON workflow_sequence_enrolment (instance_id);
CREATE INDEX IF NOT EXISTS workflow_sequence_enrolment_definition_idx
    ON workflow_sequence_enrolment (definition_id, enrolled_at DESC);

GRANT SELECT, INSERT, UPDATE ON workflow_sequence_enrolment TO attome_runtime;
GRANT SELECT ON workflow_sequence_enrolment TO attome_readonly;
