-- M13-T1: each subscription picks the shape of its webhook body.
-- `id`      — entity, record id, operation and event name only;
-- `changes` — plus the changed attributes with their old and new values,
--             taken from the outbox row (Y7-T1) when the event is matched,
--             because the outbox row may be pruned before delivery;
-- `full`    — plus the record as the owner may read it now (the shape every
--             subscription had before this migration, so it stays the
--             default).
ALTER TABLE event_subscription
    ADD COLUMN IF NOT EXISTS payload_shape text NOT NULL DEFAULT 'full';
DO $$
BEGIN
    ALTER TABLE event_subscription
        ADD CONSTRAINT event_subscription_payload_shape_chk
        CHECK (payload_shape IN ('id', 'changes', 'full'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE event_delivery ADD COLUMN IF NOT EXISTS event_name text;
ALTER TABLE event_delivery ADD COLUMN IF NOT EXISTS changed_attributes text[];
ALTER TABLE event_delivery ADD COLUMN IF NOT EXISTS changes_before jsonb;
ALTER TABLE event_delivery ADD COLUMN IF NOT EXISTS changes_after jsonb;
