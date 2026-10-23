-- L7-T6: schema changes as change-stream events (written by the changeset
-- recorder in the change's transaction, ordered with the record feed by
-- commit_xid), and each subscriber's confirmation that it erased an erased
-- record's copy (R1 evidence).
CREATE TABLE IF NOT EXISTS schema_change_event (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    change text NOT NULL,
    object_kind text NOT NULL,
    object_ref uuid,
    field text,
    commit_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS schema_change_event_feed_idx
    ON schema_change_event (commit_xid, id);

CREATE TABLE IF NOT EXISTS change_stream_erasure_confirmation (
    subscription_ref uuid NOT NULL REFERENCES change_stream_subscription (id),
    event_id uuid NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    confirmed_by uuid NOT NULL,
    confirmed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subscription_ref, event_id)
);

GRANT SELECT, INSERT ON schema_change_event TO attome_runtime;
GRANT SELECT ON schema_change_event TO attome_readonly;
GRANT SELECT, INSERT ON change_stream_erasure_confirmation TO attome_runtime;
GRANT SELECT ON change_stream_erasure_confirmation TO attome_readonly;
