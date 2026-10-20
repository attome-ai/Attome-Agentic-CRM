-- E8-T3: journeys are workflows of kind 'journey'. The definition gains its
-- kind (every existing definition is a 'flow'), and four infrastructure
-- tables hold a journey's runs: one enrolment per person and run, the
-- per-node counts the canvas shows, the message log frequency caps read,
-- and the blocks a guard or step recorded.
SET LOCAL lock_timeout = '5s';

-- A constant default is metadata-only (no table rewrite); the CHECK is
-- added NOT VALID and validated separately so validation takes only a
-- SHARE UPDATE EXCLUSIVE lock.
ALTER TABLE workflow_definition ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'flow';
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'ck_workflow_definition_kind'
           AND conrelid = 'workflow_definition'::regclass
    ) THEN
        ALTER TABLE workflow_definition
            ADD CONSTRAINT ck_workflow_definition_kind
            CHECK (kind = ANY (ARRAY['flow', 'journey', 'nurture'])) NOT VALID;
    END IF;
END
$$;
ALTER TABLE workflow_definition VALIDATE CONSTRAINT ck_workflow_definition_kind;

CREATE TABLE IF NOT EXISTS marketing_journey_enrolment (
    id                    uuid        PRIMARY KEY DEFAULT uuidv7(),
    definition_id         uuid        NOT NULL REFERENCES workflow_definition (id),
    definition_version_id uuid        NOT NULL,
    person_id             uuid        NOT NULL,
    person_entity         text        NOT NULL,
    instance_id           uuid        REFERENCES workflow_instance (id),
    status                text        NOT NULL
                          CHECK (status = ANY (ARRAY['active', 'completed', 'exited', 'removed'])),
    entry_source          text        NOT NULL,
    entered_at            timestamptz NOT NULL DEFAULT now(),
    ended_at              timestamptz,
    end_reason            text,
    goal_reached_at       timestamptz,
    is_test               boolean     NOT NULL DEFAULT false
);

-- One active run per person per journey.
CREATE UNIQUE INDEX IF NOT EXISTS marketing_journey_enrolment_active_uq
    ON marketing_journey_enrolment (definition_id, person_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS marketing_journey_enrolment_ended_idx
    ON marketing_journey_enrolment (definition_id, ended_at);
CREATE INDEX IF NOT EXISTS marketing_journey_enrolment_person_idx
    ON marketing_journey_enrolment (person_id);

CREATE TABLE IF NOT EXISTS marketing_journey_node_count (
    definition_version_id uuid   NOT NULL,
    node_id               text   NOT NULL,
    entered               bigint NOT NULL DEFAULT 0,
    waiting               bigint NOT NULL DEFAULT 0,
    passed                bigint NOT NULL DEFAULT 0,
    blocked               bigint NOT NULL DEFAULT 0,
    exited                bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (definition_version_id, node_id)
);

-- Every marketing message a person was sent, by any source (a journey's
-- step, a one-off send), for frequency caps.
CREATE TABLE IF NOT EXISTS marketing_message_log (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    person_id   uuid        NOT NULL,
    channel     text        NOT NULL,
    purpose     text        NOT NULL,
    source_kind text        NOT NULL,
    source_id   uuid        NOT NULL,
    sent_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS marketing_message_log_person_idx
    ON marketing_message_log (person_id, sent_at DESC);

CREATE TABLE IF NOT EXISTS marketing_journey_block (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    instance_id uuid        NOT NULL,
    node_id     text        NOT NULL,
    reason      text        NOT NULL,
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS marketing_journey_block_instance_idx
    ON marketing_journey_block (instance_id);

GRANT SELECT, INSERT, UPDATE ON marketing_journey_enrolment, marketing_journey_node_count
    TO attome_runtime;
-- The message log and the blocks are append-only.
GRANT SELECT, INSERT ON marketing_message_log, marketing_journey_block TO attome_runtime;
GRANT SELECT ON marketing_journey_enrolment, marketing_journey_node_count, marketing_message_log,
    marketing_journey_block TO attome_readonly;
