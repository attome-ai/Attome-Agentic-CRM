-- G12-T1 (V2-D1195): the model objects each installed pack shipped. Boot
-- installs `packs/<name>/model/**` on the pack's layer and records here the
-- content it last published, so an upgrade can tell an object the pack still
-- owns (replaced) from one the customer changed since (kept and reported).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS pack_model_object (
    pack text NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    object_id uuid NOT NULL,
    content_hash text NOT NULL,
    status text NOT NULL CHECK (status IN ('installed', 'kept_customer', 'removed_from_pack')),
    detail text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pack, kind, name)
);

GRANT SELECT, INSERT, UPDATE ON pack_model_object TO attome_runtime;
