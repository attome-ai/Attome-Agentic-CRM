-- Y7-T1: the change-event outbox carries what changed. `changed_attributes`
-- names every attribute the write changed (always filled, even when values
-- are withheld); `before` / `after` hold their values, a sensitive one as
-- `{"ref": true}`; `seq` is a global order consumers can rewind to.
CREATE SEQUENCE IF NOT EXISTS entity_change_event_seq;

ALTER TABLE entity_change_event
    ADD COLUMN IF NOT EXISTS changed_attributes text[] NOT NULL DEFAULT '{}';
ALTER TABLE entity_change_event ADD COLUMN IF NOT EXISTS before jsonb;
ALTER TABLE entity_change_event ADD COLUMN IF NOT EXISTS after jsonb;
ALTER TABLE entity_change_event
    ADD COLUMN IF NOT EXISTS seq bigint NOT NULL DEFAULT nextval('entity_change_event_seq');
ALTER SEQUENCE entity_change_event_seq OWNED BY entity_change_event.seq;

CREATE INDEX IF NOT EXISTS entity_change_event_seq_idx ON entity_change_event (seq);
