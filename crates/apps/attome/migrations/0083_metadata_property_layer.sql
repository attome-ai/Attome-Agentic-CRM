-- Y11-T2: per-property layering. A layer stores only the properties it
-- changes; the effective value is the platform's, then each app's in install
-- order, then the customer's (attome_model::layer_stack::effective).
CREATE TABLE IF NOT EXISTS metadata_property_layer (
    object_kind text NOT NULL,
    object_key text NOT NULL,
    property text NOT NULL,
    layer text NOT NULL CHECK (layer IN ('platform', 'app', 'customer')),
    app text NOT NULL DEFAULT '',
    value jsonb,
    set_by uuid,
    set_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (object_kind, object_key, property, layer, app)
);

CREATE TABLE IF NOT EXISTS app_layer (
    app text PRIMARY KEY,
    position integer NOT NULL UNIQUE,
    installed_at timestamptz NOT NULL DEFAULT now()
);

-- A layer may lock an object it owns, or allow only additions to it.
CREATE TABLE IF NOT EXISTS metadata_lock (
    object_kind text NOT NULL,
    object_key text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('locked', 'add_only')),
    set_by_layer text NOT NULL,
    PRIMARY KEY (object_kind, object_key)
);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON metadata_property_layer, app_layer, metadata_lock TO attome_runtime;
GRANT SELECT ON metadata_property_layer, app_layer, metadata_lock TO attome_readonly;
