-- Y11-T9: a reset of an entity's or field's customisation, kept so it can be
-- undone. `layer_rows` holds the customer's layer rows the reset removed
-- (property and value); an undo puts them back once.
CREATE TABLE IF NOT EXISTS metadata_layer_reset (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    object_kind text NOT NULL,
    object_key text NOT NULL,
    layer_rows jsonb NOT NULL,
    reset_by uuid NOT NULL,
    reset_at timestamptz NOT NULL DEFAULT now(),
    undone_by uuid,
    undone_at timestamptz,
    CHECK ((undone_by IS NULL) = (undone_at IS NULL))
);

CREATE INDEX IF NOT EXISTS metadata_layer_reset_object_idx
    ON metadata_layer_reset (object_kind, object_key, reset_at DESC);

GRANT SELECT, INSERT, UPDATE ON metadata_layer_reset TO attome_runtime;
GRANT SELECT ON metadata_layer_reset TO attome_readonly;
