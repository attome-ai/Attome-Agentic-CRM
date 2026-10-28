-- Y11-T6: the conflicts a platform upgrade finds. A property the platform
-- changed (its layer row's old value against the seed's new one) that an app
-- or the customer also set to something else is not merged automatically:
-- the seed keeps the current value and records the three values here, open,
-- for a builder to resolve (Y11-T7). One open conflict per property; a later
-- platform change updates it.
CREATE TABLE IF NOT EXISTS metadata_layer_conflict (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    object_kind text NOT NULL,
    object_key text NOT NULL,
    property text NOT NULL,
    old_platform jsonb,
    new_platform jsonb,
    customer jsonb,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolution text CHECK (resolution IN ('keep_customer', 'take_platform', 'combine')),
    resolved_by uuid,
    resolved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'open') = (resolution IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS metadata_layer_conflict_open_uq
    ON metadata_layer_conflict (object_kind, object_key, property) WHERE status = 'open';

GRANT SELECT, INSERT, UPDATE ON metadata_layer_conflict TO attome_runtime;
GRANT SELECT ON metadata_layer_conflict TO attome_readonly;
